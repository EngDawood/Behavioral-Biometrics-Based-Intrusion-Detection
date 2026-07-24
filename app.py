"""
app.py
======

Flask backend for the Behavioral Biometrics-Based Intrusion Detection system.

Beyond a simple enroll/verify demo, this backend behaves as a small intrusion
detection service:

    * three-tier decision  -- accept / suspicious / reject, from the score margin
    * intrusion detection  -- a run of consecutive failed verifications for a user
                              is flagged as an intrusion and temporarily locks that
                              account
    * admin monitoring     -- live statistics, an intrusion-alert feed, and a
                              per-user drill-down with unlock / reset / delete
    * self-service         -- a signed-in user changes their own phrase (which
                              re-enrolls the rhythm with it), and an admin
                              changes their own password or resets their rhythm
    * basic hardening       -- per-IP rate limiting on verification

Design note: all lock and intrusion state is DERIVED from the `attempts` table.
Relative to the ERD in Chapter 4, the schema gains two nullable columns --
users.password_hash (a per-user secret phrase, so the demo carries a knowledge
factor next to the biometric one) and admins.profile_json (the admin's own
keystroke-rhythm profile, used as a second login factor) -- and one table,
`user_sessions`: an ACCEPTED verification signs the user in so they can view
their own profile at /me. The backend still owns every decision; the browser
only captures raw keystroke timings.

Run:
    pip install -r requirements.txt
    python app.py                 # http://127.0.0.1:5000
Default admin login: admin / admin123  (change ADMIN_PASSWORD below).
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

import keystroke_model

# --- configuration ---------------------------------------------------------
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "demo.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"

PHRASE = ".tie5Roanl"          # default phrase (matches the CMU password)
REQUIRED_SAMPLES = 10          # enrollment repetitions
SESSION_HOURS = 8              # admin session lifetime

# Custom-phrase policy. A phrase is also the timing template (3(n+1)-2 features
# for n characters), so the bounds protect the biometric, not just the secret:
# too short leaves too few features to tell people apart, too long is typed
# inconsistently and inflates the user's own threshold.
PHRASE_MIN = 10
PHRASE_MAX = 20

# Admin keystroke second factor: enrollment repetitions for the admin's rhythm
# profile (fewer than user enrollment -- login friction matters more here).
ADMIN_ENROLL_SAMPLES = 8

# The admin rhythm factor is deliberately more forgiving than the user demo:
# a false rejection here locks the only operator out of the console, which is
# worse than the small extra tolerance it costs. The genuine admin is accepted
# while their score stays within this multiple of their enrolled threshold.
ADMIN_RHYTHM_MARGIN = 2.5

# Decision policy.
SUSPICIOUS_MARGIN = 1.15       # score in (threshold, threshold*margin] -> "suspicious"

# Intrusion detection policy.
FAIL_LOCK_STREAK = 3           # this many consecutive rejects -> intrusion + lock
LOCK_COOLDOWN_MIN = 5          # lock duration, measured from the triggering failure

# Rate limiting (per client IP, verification endpoint).
RATE_LIMIT_MAX = 30            # max verify calls ...
RATE_LIMIT_WINDOW = 60        # ... per this many seconds

# Seed admin (demo only -- change before any real deployment).
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

app = Flask(__name__)
_rate_log: dict[str, list[float]] = defaultdict(list)  # ip -> recent request times


# --- database helpers ------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _ensure_column(con, table: str, column: str, decl: str) -> None:
    """Add a column to an existing table if a pre-migration demo.db lacks it."""
    cols = [r[1] for r in con.execute(f"PRAGMA table_info({table})")]
    if column not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA_PATH.read_text())
    # Databases created before the phrase / admin-rhythm features miss the two
    # nullable columns; add them in place so existing demo data keeps working.
    _ensure_column(con, "users", "password_hash", "TEXT")
    _ensure_column(con, "admins", "profile_json", "TEXT")
    # Every pre-migration user enrolled with the default phrase, so their
    # knowledge factor is known and can be backfilled.
    con.execute(
        "UPDATE users SET password_hash = ? WHERE password_hash IS NULL",
        (generate_password_hash(PHRASE),),
    )
    if con.execute("SELECT 1 FROM admins WHERE username = ?", (ADMIN_USERNAME,)).fetchone() is None:
        con.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), now_iso()),
        )
    con.commit()
    con.close()


# --- phrase policy ----------------------------------------------------------
def expected_features(phrase: str) -> int:
    """Timing-vector length for a phrase: H, DD, UD per key, plus final Enter."""
    return 3 * (len(phrase) + 1) - 2


def validate_phrase(phrase: str) -> str | None:
    """Check a user-chosen phrase against the policy. Returns an error or None.

    Mirrors the client-side check in index.html; this copy is authoritative.
    Printable ASCII only: IME / non-Latin input produces key events that do not
    map 1:1 to characters, which breaks keystroke capture in the browser.
    """
    if len(phrase) < PHRASE_MIN:
        return f"phrase must be at least {PHRASE_MIN} characters"
    if len(phrase) > PHRASE_MAX:
        return f"phrase must be at most {PHRASE_MAX} characters"
    if not all("!" <= c <= "~" for c in phrase):
        return "phrase must use printable ASCII characters only, without spaces"
    if not any(c.isdigit() for c in phrase):
        return "phrase must include at least one number"
    if not any(not c.isalnum() for c in phrase):
        return "phrase must include at least one symbol"
    return None


# --- decision + intrusion logic (all derived from `attempts`) --------------
def decision_band(score: float, threshold: float) -> str:
    """Three-tier decision from the score's margin over the threshold."""
    if score <= threshold:
        return "accept"
    if score <= threshold * SUSPICIOUS_MARGIN:
        return "suspicious"
    return "reject"


def band_of(row) -> str:
    """The band for a logged attempt row.

    An attempt against an unknown username is logged with no score, and counts
    as a reject.
    """
    if row["score"] is None or row["threshold"] is None:
        return "reject"
    return decision_band(row["score"], row["threshold"])


# The SQL form of decision_band, so a band filter can be pushed into the query
# and paginate over the true match count instead of a page-local slice.
BAND_SQL = {
    "accept": "accepted = 1",
    "suspicious": "accepted = 0 AND score IS NOT NULL AND threshold IS NOT NULL "
                  f"AND score <= threshold * {SUSPICIOUS_MARGIN}",
    "reject": "accepted = 0 AND (score IS NULL OR threshold IS NULL "
              f"OR score > threshold * {SUSPICIOUS_MARGIN})",
}


def trailing_failure_streak(db, username):
    """Count consecutive non-accepted attempts back from the latest one.

    Returns (streak, most_recent_failure_time_iso_or_None).
    """
    rows = db.execute(
        "SELECT accepted, created_at FROM attempts WHERE username = ? ORDER BY id DESC",
        (username,),
    ).fetchall()
    streak = 0
    last_fail = None
    for row in rows:
        if row["accepted"] == 0:
            streak += 1
            if last_fail is None:
                last_fail = row["created_at"]
        else:
            break
    return streak, last_fail


def lock_status(db, username):
    """Is this account currently locked by the intrusion policy?

    Locked when the trailing failure streak has reached FAIL_LOCK_STREAK and the
    cooldown window (measured from the triggering failure) has not yet elapsed.
    Returns (is_locked, seconds_remaining).
    """
    streak, last_fail = trailing_failure_streak(db, username)
    if streak >= FAIL_LOCK_STREAK and last_fail:
        elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(last_fail)).total_seconds()
        remaining = LOCK_COOLDOWN_MIN * 60 - elapsed
        if remaining > 0:
            return True, int(remaining)
    return False, 0


def detect_intrusions(db):
    """Every point in the log where a user hit FAIL_LOCK_STREAK consecutive fails."""
    rows = db.execute(
        "SELECT username, accepted, created_at FROM attempts ORDER BY id ASC"
    ).fetchall()
    running = defaultdict(int)
    events = []
    for row in rows:
        user = row["username"]
        if row["accepted"] == 0:
            running[user] += 1
            if running[user] == FAIL_LOCK_STREAK:
                events.append({"username": user, "time": row["created_at"]})
        else:
            running[user] = 0
    return events


def acknowledged_intrusions(db) -> set:
    """(username, time) pairs an admin has already signed off on."""
    rows = db.execute(
        "SELECT target, detail FROM admin_actions WHERE action = 'ack_intrusion'"
    ).fetchall()
    return {(r["target"], r["detail"]) for r in rows}


def open_intrusions(db):
    """Intrusion events that have not been acknowledged yet."""
    acked = acknowledged_intrusions(db)
    return [e for e in detect_intrusions(db) if (e["username"], e["time"]) not in acked]


def log_admin_action(db, action: str, target: str, detail: str | None = None) -> None:
    """Record an admin action in the audit trail. Caller commits."""
    admin = current_admin()
    db.execute(
        "INSERT INTO admin_actions (admin_id, action, target, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (admin["admin_id"] if admin else None, action, target, detail, now_iso()),
    )


# --- listing helpers -------------------------------------------------------
PAGE_SIZE = 25


def paginate(page: int, total: int, per_page: int = PAGE_SIZE):
    """Clamp `page` into range. Returns (page, n_pages, offset)."""
    pages = max(1, -(-total // per_page))
    page = min(max(page or 1, 1), pages)
    return page, pages, (page - 1) * per_page


def like_term(text: str) -> str:
    """Wrap a user-supplied search string for LIKE ... ESCAPE '\\'.

    The wildcards are escaped so that searching for a literal '%' or '_' does
    not match every row.
    """
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def rate_limited(ip: str) -> bool:
    now = time.monotonic()
    window = _rate_log[ip]
    window[:] = [t for t in window if now - t < RATE_LIMIT_WINDOW]
    if len(window) >= RATE_LIMIT_MAX:
        return True
    window.append(now)
    return False


# --- admin auth ------------------------------------------------------------
def current_admin():
    token = request.cookies.get("admin_token")
    if not token:
        return None
    row = get_db().execute(
        "SELECT s.admin_id, s.expires_at, a.username "
        "FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token = ?",
        (token,),
    ).fetchone()
    if row is None or datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return row


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_admin() is None:
            if request.path.startswith("/api/"):
                return jsonify(error="admin authentication required"), 401
            return redirect(url_for("admin_login_page"))
        return view(*args, **kwargs)

    return wrapped


# --- user auth (demo users, signed in by an accepted verification) ----------
def current_user():
    token = request.cookies.get("user_token")
    if not token:
        return None
    row = get_db().execute(
        "SELECT s.user_id, s.expires_at, u.username "
        "FROM user_sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
        (token,),
    ).fetchone()
    if row is None or datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return row


def user_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            if request.path.startswith("/api/"):
                return jsonify(error="sign in by verifying your typing rhythm first"), 401
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


def issue_user_session(db, user_id: int, resp):
    """Attach a fresh user-session cookie to an already-built response."""
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    db.execute(
        "INSERT INTO user_sessions (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, token, now_iso(), expires.isoformat()),
    )
    db.commit()
    resp.set_cookie("user_token", token, httponly=True, samesite="Lax",
                    max_age=SESSION_HOURS * 3600)
    return resp


@app.context_processor
def inject_nav():
    """Feed shared navigation state into every template.

    `_sidebar.html` needs the signed-in admin and the unacknowledged-alert count
    on all six admin pages; the public nav needs the signed-in demo user so home
    and the other public pages can reflect the login. Each block is skipped when
    its cookie is absent, so a plain anonymous request runs no extra queries.
    """
    ctx = {}
    if request.cookies.get("admin_token"):
        admin = current_admin()
        if admin is not None:
            ctx["admin"] = admin["username"]
            ctx["open_alerts"] = len(open_intrusions(get_db()))
    if request.cookies.get("user_token"):
        user = current_user()
        if user is not None:
            ctx["signed_in_user"] = user["username"]
    return ctx


# --- public pages ----------------------------------------------------------
@app.route("/")
def index():
    return render_template(
        "index.html",
        phrase=PHRASE,
        required_samples=REQUIRED_SAMPLES,
        phrase_min=PHRASE_MIN,
        phrase_max=PHRASE_MAX,
    )


@app.route("/about")
def about():
    """Public explainer: what the system measures and how it decides."""
    n_features = 3 * (len(PHRASE) + 1) - 2
    return render_template(
        "about.html",
        phrase=PHRASE,
        required_samples=REQUIRED_SAMPLES,
        n_features=n_features,
        threshold_k=keystroke_model.DEFAULT_THRESHOLD_K,
        suspicious_margin=SUSPICIOUS_MARGIN,
        fail_lock_streak=FAIL_LOCK_STREAK,
        lock_cooldown_min=LOCK_COOLDOWN_MIN,
        rate_limit_max=RATE_LIMIT_MAX,
        rate_limit_window=RATE_LIMIT_WINDOW,
    )


@app.route("/project")
def project():
    """Academic credits: who built this, for whom, and under whose supervision."""
    return render_template("project.html")


@app.route("/me")
@user_required
def me():
    """A signed-in user's own view: their profile stats and attempt history.

    The user-owned twin of the admin drill-down -- same derived data, no
    controls. Reached only through an ACCEPTED verification (see api_verify).
    """
    db = get_db()
    user = current_user()
    username = user["username"]

    profile = db.execute(
        "SELECT p.n_samples, p.threshold, p.updated_at FROM profiles p "
        "WHERE p.user_id = ?",
        (user["user_id"],),
    ).fetchone()

    rows = db.execute(
        "SELECT id, score, threshold, accepted, created_at "
        "FROM attempts WHERE username = ? ORDER BY id DESC LIMIT 50",
        (username,),
    ).fetchall()
    attempts = [{**dict(r), "band": band_of(r)} for r in rows]

    n_attempts = db.execute(
        "SELECT COUNT(*) c FROM attempts WHERE username = ?", (username,)
    ).fetchone()["c"]
    n_accepted = db.execute(
        "SELECT COUNT(*) c FROM attempts WHERE username = ? AND accepted = 1", (username,)
    ).fetchone()["c"]
    is_locked, remaining = lock_status(db, username)

    return render_template(
        "me.html",
        username=username,
        profile=profile,
        attempts=attempts,
        n_attempts=n_attempts,
        accept_rate=round(100 * n_accepted / n_attempts, 1) if n_attempts else None,
        is_locked=is_locked,
        remaining=remaining,
        required_samples=REQUIRED_SAMPLES,
        phrase_min=PHRASE_MIN,
        phrase_max=PHRASE_MAX,
    )


@app.post("/api/user/password")
@user_required
def api_user_password():
    """Change the signed-in user's phrase, re-enrolling their rhythm with it.

    The phrase is the secret AND the timing template, so a new phrase makes the
    old profile meaningless -- a 12-character phrase does not even produce a
    vector the old profile could score. The change therefore only completes if
    the user also types the new phrase REQUIRED_SAMPLES times, and the hash and
    the rebuilt profile are written in the same transaction: the account is
    never left holding a phrase its profile was not trained on.
    """
    data = request.get_json(silent=True) or {}
    old_phrase = data.get("old_phrase") or ""
    new_phrase = data.get("new_phrase") or ""
    samples = data.get("samples")
    feature_order = data.get("feature_order")

    db = get_db()
    user = current_user()
    row = db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (user["user_id"],)
    ).fetchone()
    if not row["password_hash"] or not check_password_hash(row["password_hash"], old_phrase):
        return jsonify(error="current phrase is not correct"), 401

    err = validate_phrase(new_phrase)
    if err:
        return jsonify(error=err), 400
    if new_phrase == old_phrase:
        return jsonify(error="the new phrase must differ from the current one"), 400
    if not samples or len(samples) < REQUIRED_SAMPLES:
        return jsonify(error=f"need {REQUIRED_SAMPLES} samples of the new phrase"), 400
    n_features = expected_features(new_phrase)
    if any(len(s) != n_features for s in samples):
        return jsonify(
            error=f"each sample must carry {n_features} timing features "
                  f"for a {len(new_phrase)}-character phrase"
        ), 400

    try:
        profile = store_enrollment(db, user["user_id"], samples, feature_order)
    except ValueError as exc:
        db.rollback()
        return jsonify(error=str(exc)), 400

    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_phrase), user["user_id"]),
    )
    # A credential change ends every other session for this account; the one
    # making the change stays signed in.
    db.execute(
        "DELETE FROM user_sessions WHERE user_id = ? AND token != ?",
        (user["user_id"], request.cookies.get("user_token")),
    )
    db.commit()
    return jsonify(ok=True, n_samples=profile["n_samples"],
                   threshold=round(profile["threshold"], 3))


@app.post("/api/user/logout")
def api_user_logout():
    token = request.cookies.get("user_token")
    if token:
        get_db().execute("DELETE FROM user_sessions WHERE token = ?", (token,))
        get_db().commit()
    resp = jsonify(ok=True)
    resp.delete_cookie("user_token")
    return resp


@app.route("/logout")
def user_logout():
    """Clear a demo-user session and return home. A plain link, so the nav on
    any public page can log out without its own script."""
    resp = redirect(url_for("index"))
    token = request.cookies.get("user_token")
    if token:
        get_db().execute("DELETE FROM user_sessions WHERE token = ?", (token,))
        get_db().commit()
    resp.delete_cookie("user_token")
    return resp


@app.route("/admin")
def admin_login_page():
    if current_admin() is not None:
        return redirect(url_for("admin_dashboard"))
    return render_template("admin.html", logged_in=False,
                           admin_enroll_samples=ADMIN_ENROLL_SAMPLES)


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()

    total = db.execute("SELECT COUNT(*) c FROM attempts").fetchone()["c"]
    accepted = db.execute("SELECT COUNT(*) c FROM attempts WHERE accepted = 1").fetchone()["c"]
    n_users = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    intrusions = detect_intrusions(db)

    usernames = [r["username"] for r in db.execute("SELECT username FROM users").fetchall()]
    locked = []
    for u in usernames:
        is_locked, remaining = lock_status(db, u)
        if is_locked:
            locked.append({"username": u, "remaining": remaining})

    stats = {
        "users": n_users,
        "attempts": total,
        "accept_rate": round(100 * accepted / total, 1) if total else 0.0,
        "intrusions": len(intrusions),
        "locked": len(locked),
    }

    rows = db.execute(
        "SELECT id, username, score, threshold, accepted, created_at "
        "FROM attempts ORDER BY id DESC LIMIT 200"
    ).fetchall()
    attempts = [{**dict(r), "band": band_of(r)} for r in rows]

    # Enrolled-user roster: profile state plus the last time each user was seen.
    user_rows = db.execute(
        "SELECT u.username, p.n_samples, p.threshold, "
        "       (SELECT MAX(a.created_at) FROM attempts a WHERE a.username = u.username) AS last_seen "
        "FROM users u LEFT JOIN profiles p ON p.user_id = u.id "
        "ORDER BY u.id DESC LIMIT 12"
    ).fetchall()
    locked_names = {l["username"] for l in locked}
    users = [{**dict(r), "locked": r["username"] in locked_names} for r in user_rows]

    return render_template(
        "admin.html",
        logged_in=True,
        admin=current_admin()["username"],
        stats=stats,
        attempts=attempts,
        users=users,
        alerts=list(reversed(intrusions))[:20],
        locked=locked,
        fail_lock_streak=FAIL_LOCK_STREAK,
        lock_cooldown_min=LOCK_COOLDOWN_MIN,
    )


@app.route("/admin/users")
@admin_required
def admin_users():
    """The full enrolled-user roster, with search, status filter and paging.

    The dashboard only has room for the twelve most recent users; this is the
    complete list.
    """
    db = get_db()
    q = (request.args.get("q") or "").strip()
    status = request.args.get("status") or "all"

    rows = db.execute(
        "SELECT u.username, u.created_at, p.n_samples, p.threshold, "
        "       (SELECT COUNT(*) FROM attempts a WHERE a.username = u.username) AS n_attempts, "
        "       (SELECT COUNT(*) FROM attempts a WHERE a.username = u.username "
        "        AND a.accepted = 1) AS n_accepted, "
        "       (SELECT MAX(a.created_at) FROM attempts a "
        "        WHERE a.username = u.username) AS last_seen "
        "FROM users u LEFT JOIN profiles p ON p.user_id = u.id "
        "WHERE u.username LIKE ? ESCAPE '\\' "
        "ORDER BY u.id DESC",
        (like_term(q),),
    ).fetchall()

    # Lock state is derived per user, so the status filter runs in Python.
    users = []
    for r in rows:
        is_locked, remaining = lock_status(db, r["username"])
        total = r["n_attempts"]
        users.append({
            **dict(r),
            "locked": is_locked,
            "remaining": remaining,
            "accept_rate": round(100 * r["n_accepted"] / total, 1) if total else None,
        })

    keep = {
        "locked": lambda u: u["locked"],
        "enrolled": lambda u: u["n_samples"] and not u["locked"],
        "noprofile": lambda u: not u["n_samples"],
    }.get(status)
    if keep:
        users = [u for u in users if keep(u)]

    page, pages, offset = paginate(request.args.get("page", type=int), len(users))
    return render_template(
        "users.html",
        users=users[offset:offset + PAGE_SIZE],
        total=len(users),
        q=q,
        status=status,
        page=page,
        pages=pages,
    )


@app.route("/admin/events")
@admin_required
def admin_events():
    """The complete verification log, filterable by user and by decision band."""
    db = get_db()
    q = (request.args.get("q") or "").strip()
    band = request.args.get("band") or "all"

    where = ["username LIKE ? ESCAPE '\\'"]
    params = [like_term(q)]
    if band in BAND_SQL:
        where.append(f"({BAND_SQL[band]})")
    clause = " AND ".join(where)

    total = db.execute(f"SELECT COUNT(*) c FROM attempts WHERE {clause}", params).fetchone()["c"]
    page, pages, offset = paginate(request.args.get("page", type=int), total)

    rows = db.execute(
        "SELECT id, username, score, threshold, accepted, created_at FROM attempts "
        f"WHERE {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        [*params, PAGE_SIZE, offset],
    ).fetchall()
    attempts = [{**dict(r), "band": band_of(r)} for r in rows]

    # Band counts for the filter tabs, over the current user search but ignoring
    # the band filter itself -- otherwise the unselected tabs would all read 0.
    counts = {"all": db.execute(
        "SELECT COUNT(*) c FROM attempts WHERE username LIKE ? ESCAPE '\\'",
        (like_term(q),),
    ).fetchone()["c"]}
    for name, sql in BAND_SQL.items():
        counts[name] = db.execute(
            f"SELECT COUNT(*) c FROM attempts WHERE username LIKE ? ESCAPE '\\' AND ({sql})",
            (like_term(q),),
        ).fetchone()["c"]

    return render_template(
        "events.html",
        attempts=attempts, total=total, counts=counts,
        q=q, band=band, page=page, pages=pages,
        suspicious_margin=SUSPICIOUS_MARGIN,
    )


@app.route("/admin/alerts")
@admin_required
def admin_alerts():
    """Every intrusion event, newest first, with acknowledge and unlock controls.

    The dashboard feed is capped at twenty; this is the whole history. An event
    is "open" until an admin acknowledges it -- that ack is the only part stored,
    in `admin_actions`. The events themselves stay derived from `attempts`.
    """
    db = get_db()
    show = request.args.get("show") or "open"

    acked = acknowledged_intrusions(db)
    events = []
    for e in reversed(detect_intrusions(db)):
        is_locked, remaining = lock_status(db, e["username"])
        events.append({
            **e,
            "acked": (e["username"], e["time"]) in acked,
            "locked": is_locked,
            "remaining": remaining,
        })

    n_open = sum(1 for e in events if not e["acked"])
    if show == "open":
        shown = [e for e in events if not e["acked"]]
    elif show == "acked":
        shown = [e for e in events if e["acked"]]
    else:
        shown = events

    page, pages, offset = paginate(request.args.get("page", type=int), len(shown))

    recent = db.execute(
        "SELECT a.action, a.target, a.created_at, ad.username AS admin "
        "FROM admin_actions a LEFT JOIN admins ad ON ad.id = a.admin_id "
        "ORDER BY a.id DESC LIMIT 12"
    ).fetchall()

    return render_template(
        "alerts.html",
        events=shown[offset:offset + PAGE_SIZE],
        total=len(shown),
        n_open=n_open,
        n_all=len(events),
        n_acked=len(events) - n_open,
        show=show,
        page=page,
        pages=pages,
        audit=recent,
        fail_lock_streak=FAIL_LOCK_STREAK,
        lock_cooldown_min=LOCK_COOLDOWN_MIN,
    )


@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    """How the detector is behaving in aggregate.

    Everything is computed from `attempts`. The key chart is the distribution of
    score / threshold: a ratio of 1.0 is exactly the accept boundary, so the
    shape either side of it shows how much headroom the policy actually has.
    """
    db = get_db()
    rows = db.execute(
        "SELECT username, score, threshold, accepted, created_at FROM attempts"
    ).fetchall()

    bands = {"accept": 0, "suspicious": 0, "reject": 0}
    for r in rows:
        bands[band_of(r)] += 1
    total = len(rows)

    # Ratio histogram. Scored attempts only -- an unknown-user attempt has no
    # score and would otherwise pile up in a phantom bin.
    ratios = [
        r["score"] / r["threshold"]
        for r in rows
        if r["score"] is not None and r["threshold"]
    ]
    edges = [0, 0.25, 0.5, 0.75, 1.0, 1.15, 1.5, 2.0]
    hist = [0] * len(edges)
    for ratio in ratios:
        slot = len(edges) - 1
        for i, hi in enumerate(edges[1:]):
            if ratio < hi:
                slot = i
                break
        hist[slot] += 1
    peak = max(hist) or 1
    labels = [f"{lo:g}–{hi:g}" for lo, hi in zip(edges, edges[1:])] + [f"{edges[-1]:g}+"]
    histogram = [
        {
            "label": label,
            "count": count,
            "pct": round(100 * count / peak, 1),
            # The accept boundary sits at ratio 1.0; bins below it were accepted.
            "band": "accept" if edges[i] < 1.0 else
                    ("suspicious" if edges[i] < SUSPICIOUS_MARGIN else "reject"),
        }
        for i, (label, count) in enumerate(zip(labels, hist))
    ]

    # Daily volume, last 14 days that have any traffic.
    by_day: dict[str, dict[str, int]] = {}
    for r in rows:
        day = r["created_at"][:10]
        bucket = by_day.setdefault(day, {"accept": 0, "fail": 0})
        bucket["accept" if r["accepted"] else "fail"] += 1
    days = sorted(by_day)[-14:]
    day_peak = max((sum(by_day[d].values()) for d in days), default=0) or 1
    timeline = [
        {
            "day": d[5:],
            "accept": by_day[d]["accept"],
            "fail": by_day[d]["fail"],
            "accept_pct": round(100 * by_day[d]["accept"] / day_peak, 1),
            "fail_pct": round(100 * by_day[d]["fail"] / day_peak, 1),
        }
        for d in days
    ]

    # Riskiest users: most non-accepted attempts.
    per_user: dict[str, dict] = {}
    for r in rows:
        u = per_user.setdefault(r["username"], {"username": r["username"], "n": 0, "fails": 0})
        u["n"] += 1
        if not r["accepted"]:
            u["fails"] += 1
    risky = sorted(
        (u for u in per_user.values() if u["fails"]),
        key=lambda u: (-u["fails"], u["username"]),
    )[:8]
    for u in risky:
        u["fail_rate"] = round(100 * u["fails"] / u["n"], 1)

    return render_template(
        "analytics.html",
        total=total,
        bands=bands,
        band_pct={
            k: round(100 * v / total, 1) if total else 0.0 for k, v in bands.items()
        },
        scored=len(ratios),
        mean_ratio=round(sum(ratios) / len(ratios), 2) if ratios else None,
        histogram=histogram,
        timeline=timeline,
        risky=risky,
        intrusions=len(detect_intrusions(db)),
        suspicious_margin=SUSPICIOUS_MARGIN,
    )


@app.route("/admin/policy")
@admin_required
def admin_policy():
    """Read-only view of the policy the server actually enforces.

    Every value here is a module constant, so what the dashboard shows and what
    the decision path applies cannot drift apart.
    """
    def pct(value, low, high):
        return round(100 * (value - low) / (high - low), 1)

    toggles = [
        {"title": "Three-tier decisions",
         "desc": "Score the margin over the threshold, so a borderline attempt is flagged "
                 "suspicious instead of being silently accepted or rejected.",
         "on": SUSPICIOUS_MARGIN > 1},
        {"title": "Lock on repeated failure",
         "desc": f"Freeze an account after {FAIL_LOCK_STREAK} consecutive non-accepted attempts "
                 f"and refuse it for {LOCK_COOLDOWN_MIN} minutes, before any scoring runs.",
         "on": FAIL_LOCK_STREAK > 0},
        {"title": "Rate limit verification",
         "desc": f"Cap each client IP at {RATE_LIMIT_MAX} verification calls per "
                 f"{RATE_LIMIT_WINDOW} seconds.",
         "on": RATE_LIMIT_MAX > 0},
        {"title": "Re-enrollment clears history",
         "desc": "Rebuilding a profile drops that user's old samples and attempt history, so a "
                 "stale failure streak cannot keep a freshly enrolled account locked.",
         "on": True},
    ]

    return render_template(
        "policy.html",
        phrase=PHRASE,
        required_samples=REQUIRED_SAMPLES,
        samples_pct=pct(REQUIRED_SAMPLES, 3, 15),
        threshold_k=keystroke_model.DEFAULT_THRESHOLD_K,
        k_pct=pct(keystroke_model.DEFAULT_THRESHOLD_K, 0.5, 3.0),
        suspicious_margin=SUSPICIOUS_MARGIN,
        margin_pct=pct(SUSPICIOUS_MARGIN, 1.0, 2.0),
        fail_lock_streak=FAIL_LOCK_STREAK,
        lock_cooldown_min=LOCK_COOLDOWN_MIN,
        toggles=toggles,
    )


@app.route("/admin/account")
@admin_required
def admin_account():
    """The signed-in admin's own account: their two factors and their audit trail.

    The admin twin of /me. It is the only screen that reads `admin_actions` as
    history rather than as acknowledgement state, and it is scoped to the
    signed-in admin -- an operator reviews what they themselves did.
    """
    db = get_db()
    admin = current_admin()

    account = db.execute(
        "SELECT username, profile_json, created_at FROM admins WHERE id = ?",
        (admin["admin_id"],),
    ).fetchone()
    actions = db.execute(
        "SELECT action, target, detail, created_at FROM admin_actions "
        "WHERE admin_id = ? ORDER BY id DESC LIMIT 20",
        (admin["admin_id"],),
    ).fetchall()
    n_sessions = db.execute(
        "SELECT COUNT(*) c FROM sessions WHERE admin_id = ? AND expires_at > ?",
        (admin["admin_id"], now_iso()),
    ).fetchone()["c"]

    return render_template(
        "account.html",
        account=account,
        has_rhythm=account["profile_json"] is not None,
        actions=actions,
        n_sessions=n_sessions,
        phrase_min=PHRASE_MIN,
        phrase_max=PHRASE_MAX,
        admin_enroll_samples=ADMIN_ENROLL_SAMPLES,
    )


@app.route("/admin/user/<username>")
@admin_required
def admin_user(username):
    db = get_db()
    rows = db.execute(
        "SELECT id, score, threshold, accepted, created_at "
        "FROM attempts WHERE username = ? ORDER BY id DESC LIMIT 200",
        (username,),
    ).fetchall()
    attempts = [{**dict(r), "band": band_of(r)} for r in rows]

    profile = db.execute(
        "SELECT p.n_samples, p.threshold, p.updated_at FROM profiles p "
        "JOIN users u ON u.id = p.user_id WHERE u.username = ?",
        (username,),
    ).fetchone()
    is_locked, remaining = lock_status(db, username)

    return render_template(
        "admin_user.html",
        username=username,
        attempts=attempts,
        profile=profile,
        is_locked=is_locked,
        remaining=remaining,
    )


# --- API: enroll -----------------------------------------------------------
def store_enrollment(db, user_id: int, samples, feature_order):
    """Rebuild a user's enrollment from scratch: samples, profile, lock state.

    Shared by first enrollment and by a phrase change, because both have to
    rebuild the same way -- a profile only means anything for the phrase it was
    trained on. The model is fitted before anything is written, so a bad sample
    set raises ValueError while the database is still untouched. The caller owns
    the transaction.
    """
    profile = keystroke_model.enroll(samples, feature_order=feature_order)

    db.execute("DELETE FROM enrollment_samples WHERE user_id = ?", (user_id,))
    for sample in samples:
        db.execute(
            "INSERT INTO enrollment_samples (user_id, features, created_at) VALUES (?, ?, ?)",
            (user_id, json.dumps(sample), now_iso()),
        )

    db.execute("DELETE FROM profiles WHERE user_id = ?", (user_id,))
    db.execute(
        "INSERT INTO profiles (user_id, detector, profile_json, threshold, n_samples, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, profile["detector"], json.dumps(profile),
         profile["threshold"], profile["n_samples"], now_iso()),
    )
    # A fresh enrollment clears any prior failed-attempt streak / lock.
    db.execute("DELETE FROM attempts WHERE user_id = ?", (user_id,))
    return profile


@app.post("/api/enroll")
def api_enroll():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    samples = data.get("samples")
    feature_order = data.get("feature_order")

    if not username or not samples:
        return jsonify(error="username and samples are required"), 400
    if len(samples) < 2:
        return jsonify(error="need at least 2 samples to enroll"), 400

    # The phrase is both the secret and the timing template. No custom phrase
    # means the default one; a custom phrase must pass the policy, and either
    # way every sample must have the feature count that phrase implies.
    if password:
        err = validate_phrase(password)
        if err:
            return jsonify(error=err), 400
    else:
        password = PHRASE
    n_features = expected_features(password)
    if any(len(s) != n_features for s in samples):
        return jsonify(
            error=f"each sample must carry {n_features} timing features "
                  f"for a {len(password)}-character phrase"
        ), 400

    db = get_db()
    # Usernames are matched case-insensitively, so enrolling "dawood" when
    # "Dawood" already exists re-enrolls that same account rather than making a
    # second one. The stored casing is kept as first entered.
    row = db.execute(
        "SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,)
    ).fetchone()
    if row is None:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), now_iso()),
        )
        user_id = cur.lastrowid
    else:
        user_id = row["id"]
        # Re-enrollment: rebind the knowledge factor to the phrase actually typed
        # this time (store_enrollment replaces the samples and the profile).
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(password), user_id),
        )

    try:
        profile = store_enrollment(db, user_id, samples, feature_order)
    except ValueError as exc:
        db.rollback()
        return jsonify(error=str(exc)), 400
    db.commit()
    return jsonify(ok=True, username=username, n_samples=profile["n_samples"],
                   threshold=round(profile["threshold"], 3))


# --- API: verify -----------------------------------------------------------
@app.post("/api/verify")
def api_verify():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    if rate_limited(ip):
        return jsonify(error="too many attempts, slow down", retry_after=RATE_LIMIT_WINDOW), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    typed = data.get("password")
    sample = data.get("sample")
    feature_order = data.get("feature_order")

    if not username or not sample:
        return jsonify(error="username and sample are required"), 400
    if typed is None:
        return jsonify(error="password (the typed phrase) is required"), 400

    db = get_db()

    # Resolve the username case-insensitively to its stored casing, so "dawood"
    # verifies against the profile enrolled as "Dawood". Everything downstream
    # (lock state, attempt logging, streaks) then keys off one canonical name.
    canon = db.execute(
        "SELECT username FROM users WHERE username = ? COLLATE NOCASE", (username,)
    ).fetchone()
    if canon is not None:
        username = canon["username"]

    # Locked accounts are refused before any scoring, and the refusal is not
    # logged, so the lock window stays anchored to the triggering failure.
    is_locked, remaining = lock_status(db, username)
    if is_locked:
        return jsonify(error="account temporarily locked", locked=True,
                       retry_after=remaining), 423

    row = db.execute(
        "SELECT p.profile_json, u.id AS user_id, u.password_hash FROM profiles p "
        "JOIN users u ON u.id = p.user_id WHERE u.username = ?",
        (username,),
    ).fetchone()

    if row is None:
        db.execute(
            "INSERT INTO attempts (user_id, username, score, threshold, accepted, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (None, username, None, None, 0, now_iso()),
        )
        db.commit()
        return jsonify(error="no profile for that username", accepted=False), 404

    # Knowledge factor first: the typed text must match the enrolled phrase
    # before the rhythm is even scored. A wrong phrase is logged as a scoreless
    # reject, so it feeds the same failure-streak / lock policy as a bad rhythm.
    if not check_password_hash(row["password_hash"], typed):
        db.execute(
            "INSERT INTO attempts (user_id, username, score, threshold, accepted, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (row["user_id"], username, None, None, 0, now_iso()),
        )
        db.commit()
        streak, _ = trailing_failure_streak(db, username)
        intrusion = streak >= FAIL_LOCK_STREAK
        return jsonify(
            error="phrase does not match the enrolled one",
            accepted=False,
            intrusion=intrusion,
            locked=intrusion,
            retry_after=LOCK_COOLDOWN_MIN * 60 if intrusion else 0,
            fail_streak=streak,
        ), 401

    profile = json.loads(row["profile_json"])
    try:
        result = keystroke_model.verify(profile, sample, feature_order=feature_order)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    band = decision_band(result["score"], result["threshold"])
    accepted = band == "accept"

    db.execute(
        "INSERT INTO attempts (user_id, username, score, threshold, accepted, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (row["user_id"], username, result["score"], result["threshold"],
         int(accepted), now_iso()),
    )
    db.commit()

    # Did this attempt just trigger an intrusion lock?
    streak, _ = trailing_failure_streak(db, username)
    intrusion = (not accepted) and streak >= FAIL_LOCK_STREAK

    resp = jsonify(
        accepted=accepted,
        band=band,
        score=round(result["score"], 3),
        threshold=round(result["threshold"], 3),
        deviations=hold_deviations(profile, result["deviations"]),
        intrusion=intrusion,
        locked=intrusion,
        retry_after=LOCK_COOLDOWN_MIN * 60 if intrusion else 0,
        fail_streak=streak,
    )
    # An accepted verification IS the login: both factors just passed, so the
    # user gets a session and can view their own profile at /me. A suspicious
    # band is flagged, not trusted -- no session.
    if accepted:
        issue_user_session(db, row["user_id"], resp)
    return resp


def hold_deviations(profile, deviations):
    """The per-key hold (dwell) slice of the deviation vector, for the UI.

    One number per key pressed, so the client can show which keystrokes drifted.
    The flight features (DD/UD) are dropped: they sit between keys and have no
    single key to attribute them to. Falls back to the whole vector if the
    profile has no feature names to slice by.
    """
    order = profile.get("feature_order")
    if not order:
        return [round(d, 3) for d in deviations]
    return [
        round(d, 3)
        for name, d in zip(order, deviations)
        if str(name).startswith("H_")
    ]


# --- API: admin login / logout / management --------------------------------
def issue_admin_session(db, admin_id: int):
    """Create a session row and return the ok-response carrying its cookie."""
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    db.execute(
        "INSERT INTO sessions (admin_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (admin_id, token, now_iso(), expires.isoformat()),
    )
    db.commit()
    resp = jsonify(ok=True)
    resp.set_cookie("admin_token", token, httponly=True, samesite="Lax",
                    max_age=SESSION_HOURS * 3600)
    return resp


@app.post("/api/admin/login")
def api_admin_login():
    """Two-factor admin login: password hash first, then keystroke rhythm.

    An admin with no rhythm profile yet is told to enroll one (the client then
    walks them through it); once a profile exists, a login must carry a timing
    sample whose score lands within ADMIN_RHYTHM_MARGIN of the enrolled
    threshold. That generous margin -- rather than the bare threshold -- keeps
    a slightly-off day from locking the only admin out of the console.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    sample = data.get("sample")
    feature_order = data.get("feature_order")

    db = get_db()
    admin = db.execute(
        "SELECT id, password_hash, profile_json FROM admins WHERE username = ?", (username,)
    ).fetchone()
    if admin is None or not check_password_hash(admin["password_hash"], password):
        return jsonify(error="invalid credentials"), 401

    if admin["profile_json"] is None:
        return jsonify(ok=False, enroll_rhythm=True, samples_needed=ADMIN_ENROLL_SAMPLES)

    if not sample:
        return jsonify(error="keystroke sample required — type your password "
                             "and press Enter, without corrections"), 401
    try:
        result = keystroke_model.verify(
            json.loads(admin["profile_json"]), sample, feature_order=feature_order
        )
    except ValueError:
        return jsonify(error="could not read your typing rhythm — retype your "
                             "password cleanly and press Enter"), 401
    if result["score"] > result["threshold"] * ADMIN_RHYTHM_MARGIN:
        return jsonify(error="password correct, but the typing rhythm does not "
                             "match this admin"), 401

    return issue_admin_session(db, admin["id"])


@app.post("/api/admin/enroll_rhythm")
def api_admin_enroll_rhythm():
    """First-login rhythm enrollment for an admin, then sign them in.

    Guarded by the admin password itself (there is no session yet), and only
    allowed while the admin has no profile -- re-enrollment would let a stolen
    password overwrite the biometric factor.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    samples = data.get("samples")
    feature_order = data.get("feature_order")

    db = get_db()
    admin = db.execute(
        "SELECT id, password_hash, profile_json FROM admins WHERE username = ?", (username,)
    ).fetchone()
    if admin is None or not check_password_hash(admin["password_hash"], password):
        return jsonify(error="invalid credentials"), 401
    if admin["profile_json"] is not None:
        return jsonify(error="rhythm profile already enrolled"), 409

    if not samples or len(samples) < ADMIN_ENROLL_SAMPLES:
        return jsonify(error=f"need {ADMIN_ENROLL_SAMPLES} samples"), 400
    n_features = expected_features(password)
    if any(len(s) != n_features for s in samples):
        return jsonify(error="sample does not match the password length"), 400

    try:
        profile = keystroke_model.enroll(samples, feature_order=feature_order)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    db.execute(
        "UPDATE admins SET profile_json = ? WHERE id = ?",
        (json.dumps(profile), admin["id"]),
    )
    db.execute(
        "INSERT INTO admin_actions (admin_id, action, target, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (admin["id"], "enroll_rhythm", username, None, now_iso()),
    )
    return issue_admin_session(db, admin["id"])


@app.post("/api/admin/logout")
def api_admin_logout():
    token = request.cookies.get("admin_token")
    if token:
        get_db().execute("DELETE FROM sessions WHERE token = ?", (token,))
        get_db().commit()
    resp = jsonify(ok=True)
    resp.delete_cookie("admin_token")
    return resp


@app.post("/api/admin/password")
@admin_required
def api_admin_password():
    """Change the signed-in admin's own password.

    The admin's rhythm profile is enrolled on the password text itself, so a new
    password invalidates the biometric factor along with the old secret:
    profile_json is cleared and the next login walks the admin through rhythm
    enrollment again. The new password must pass the same phrase policy as a
    user's -- the length bounds exist because the text is a timing template.
    """
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""

    db = get_db()
    admin = current_admin()
    row = db.execute(
        "SELECT password_hash FROM admins WHERE id = ?", (admin["admin_id"],)
    ).fetchone()
    if not check_password_hash(row["password_hash"], old_password):
        return jsonify(error="current password is not correct"), 401

    err = validate_phrase(new_password)
    if err:
        return jsonify(error=err), 400
    if new_password == old_password:
        return jsonify(error="the new password must differ from the current one"), 400

    db.execute(
        "UPDATE admins SET password_hash = ?, profile_json = NULL WHERE id = ?",
        (generate_password_hash(new_password), admin["admin_id"]),
    )
    log_admin_action(db, "change_password", admin["username"])
    # Other consoles signed in on the old password are dropped; this one stays.
    db.execute(
        "DELETE FROM sessions WHERE admin_id = ? AND token != ?",
        (admin["admin_id"], request.cookies.get("admin_token")),
    )
    db.commit()
    return jsonify(ok=True)


@app.post("/api/admin/rhythm/reset")
@admin_required
def api_admin_reset_rhythm():
    """Drop the admin's own rhythm profile so it can be enrolled again.

    The escape hatch for a rhythm that has drifted far enough to keep failing
    login. Guarded by the password, like the enrollment it re-opens, and it ends
    every session including this one -- the admin comes back through /admin,
    where the login flow collects the new samples.
    """
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""

    db = get_db()
    admin = current_admin()
    row = db.execute(
        "SELECT password_hash FROM admins WHERE id = ?", (admin["admin_id"],)
    ).fetchone()
    if not check_password_hash(row["password_hash"], password):
        return jsonify(error="password is not correct"), 401

    db.execute("UPDATE admins SET profile_json = NULL WHERE id = ?", (admin["admin_id"],))
    log_admin_action(db, "reset_rhythm", admin["username"])
    db.execute("DELETE FROM sessions WHERE admin_id = ?", (admin["admin_id"],))
    db.commit()

    resp = jsonify(ok=True)
    resp.delete_cookie("admin_token")
    return resp


@app.post("/api/admin/user/<username>/unlock")
@admin_required
def api_unlock_user(username):
    """Clear a user's attempt history, which releases any derived lock."""
    db = get_db()
    db.execute("DELETE FROM attempts WHERE username = ?", (username,))
    log_admin_action(db, "unlock", username)
    db.commit()
    return jsonify(ok=True)


@app.post("/api/admin/user/<username>/delete")
@admin_required
def api_delete_user(username):
    """Remove a user entirely: profile, samples and attempts."""
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row is not None:
        db.execute("DELETE FROM users WHERE id = ?", (row["id"],))  # cascades
    db.execute("DELETE FROM attempts WHERE username = ?", (username,))
    log_admin_action(db, "delete", username)
    db.commit()
    return jsonify(ok=True)


@app.post("/api/admin/user/<username>/reset")
@admin_required
def api_reset_user(username):
    """Force a user back to enrollment: profile, samples, attempts and sessions go.

    The milder sibling of delete -- the account survives, but it can no longer
    authenticate until the user enrolls a fresh phrase and rhythm.

    The phrase hash is deliberately left in place rather than nulled: a NULL
    hash is exactly what init_db backfills with the default phrase, so clearing
    it would quietly hand this account that phrase on the next restart. It is
    inert as it stands -- verification needs a profile, and re-enrollment
    rebinds the hash to whatever phrase the user then chooses.
    """
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        return jsonify(error="no such user"), 404

    db.execute("DELETE FROM profiles WHERE user_id = ?", (row["id"],))
    db.execute("DELETE FROM enrollment_samples WHERE user_id = ?", (row["id"],))
    db.execute("DELETE FROM user_sessions WHERE user_id = ?", (row["id"],))
    db.execute("DELETE FROM attempts WHERE username = ?", (username,))
    log_admin_action(db, "reset", username)
    db.commit()
    return jsonify(ok=True)


@app.post("/api/admin/alert/ack")
@admin_required
def api_ack_alert():
    """Sign off on one intrusion alert, so it drops out of the open feed.

    Identified by the username and the timestamp of the attempt that tripped the
    lock, which is what makes an event unique in `detect_intrusions`.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    time_iso = (data.get("time") or "").strip()
    if not username or not time_iso:
        return jsonify(error="username and time are required"), 400

    db = get_db()
    if (username, time_iso) not in acknowledged_intrusions(db):
        log_admin_action(db, "ack_intrusion", username, time_iso)
        db.commit()
    return jsonify(ok=True)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
