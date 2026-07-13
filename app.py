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
                              per-user drill-down with unlock / delete controls
    * basic hardening       -- per-IP rate limiting on verification

Design note: all lock and intrusion state is DERIVED from the `attempts` table.
No extra tables or columns are added, so the six-table ERD in Chapter 4 stays
exactly as designed. The backend still owns every decision; the browser only
captures raw keystroke timings.

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

PHRASE = ".tie5Roanl"          # phrase every user types (matches the CMU password)
REQUIRED_SAMPLES = 10          # enrollment repetitions
SESSION_HOURS = 8              # admin session lifetime

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


def init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA_PATH.read_text())
    if con.execute("SELECT 1 FROM admins WHERE username = ?", (ADMIN_USERNAME,)).fetchone() is None:
        con.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), now_iso()),
        )
    con.commit()
    con.close()


# --- decision + intrusion logic (all derived from `attempts`) --------------
def decision_band(score: float, threshold: float) -> str:
    """Three-tier decision from the score's margin over the threshold."""
    if score <= threshold:
        return "accept"
    if score <= threshold * SUSPICIOUS_MARGIN:
        return "suspicious"
    return "reject"


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


# --- public pages ----------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", phrase=PHRASE, required_samples=REQUIRED_SAMPLES)


@app.route("/admin")
def admin_login_page():
    if current_admin() is not None:
        return redirect(url_for("admin_dashboard"))
    return render_template("admin.html", logged_in=False)


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
    attempts = []
    for r in rows:
        band = (
            decision_band(r["score"], r["threshold"])
            if r["score"] is not None and r["threshold"] is not None
            else "reject"
        )
        attempts.append({**dict(r), "band": band})

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


@app.route("/admin/user/<username>")
@admin_required
def admin_user(username):
    db = get_db()
    rows = db.execute(
        "SELECT id, score, threshold, accepted, created_at "
        "FROM attempts WHERE username = ? ORDER BY id DESC LIMIT 200",
        (username,),
    ).fetchall()
    attempts = []
    for r in rows:
        band = (
            decision_band(r["score"], r["threshold"])
            if r["score"] is not None and r["threshold"] is not None
            else "reject"
        )
        attempts.append({**dict(r), "band": band})

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
@app.post("/api/enroll")
def api_enroll():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    samples = data.get("samples")
    feature_order = data.get("feature_order")

    if not username or not samples:
        return jsonify(error="username and samples are required"), 400
    if len(samples) < 2:
        return jsonify(error="need at least 2 samples to enroll"), 400

    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        cur = db.execute(
            "INSERT INTO users (username, created_at) VALUES (?, ?)", (username, now_iso())
        )
        user_id = cur.lastrowid
    else:
        user_id = row["id"]
        # Re-enrollment: replace old samples so the profile is rebuilt cleanly.
        db.execute("DELETE FROM enrollment_samples WHERE user_id = ?", (user_id,))

    for sample in samples:
        db.execute(
            "INSERT INTO enrollment_samples (user_id, features, created_at) VALUES (?, ?, ?)",
            (user_id, json.dumps(sample), now_iso()),
        )

    try:
        profile = keystroke_model.enroll(samples, feature_order=feature_order)
    except ValueError as exc:
        db.rollback()
        return jsonify(error=str(exc)), 400

    db.execute("DELETE FROM profiles WHERE user_id = ?", (user_id,))
    db.execute(
        "INSERT INTO profiles (user_id, detector, profile_json, threshold, n_samples, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, profile["detector"], json.dumps(profile),
         profile["threshold"], profile["n_samples"], now_iso()),
    )
    # A fresh enrollment clears any prior failed-attempt streak / lock.
    db.execute("DELETE FROM attempts WHERE user_id = ?", (user_id,))
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
    sample = data.get("sample")
    feature_order = data.get("feature_order")

    if not username or not sample:
        return jsonify(error="username and sample are required"), 400

    db = get_db()

    # Locked accounts are refused before any scoring, and the refusal is not
    # logged, so the lock window stays anchored to the triggering failure.
    is_locked, remaining = lock_status(db, username)
    if is_locked:
        return jsonify(error="account temporarily locked", locked=True,
                       retry_after=remaining), 423

    row = db.execute(
        "SELECT p.profile_json, u.id AS user_id FROM profiles p "
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

    return jsonify(
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
@app.post("/api/admin/login")
def api_admin_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    admin = db.execute(
        "SELECT id, password_hash FROM admins WHERE username = ?", (username,)
    ).fetchone()
    if admin is None or not check_password_hash(admin["password_hash"], password):
        return jsonify(error="invalid credentials"), 401

    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    db.execute(
        "INSERT INTO sessions (admin_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (admin["id"], token, now_iso(), expires.isoformat()),
    )
    db.commit()
    resp = jsonify(ok=True)
    resp.set_cookie("admin_token", token, httponly=True, samesite="Lax",
                    max_age=SESSION_HOURS * 3600)
    return resp


@app.post("/api/admin/logout")
def api_admin_logout():
    token = request.cookies.get("admin_token")
    if token:
        get_db().execute("DELETE FROM sessions WHERE token = ?", (token,))
        get_db().commit()
    resp = jsonify(ok=True)
    resp.delete_cookie("admin_token")
    return resp


@app.post("/api/admin/user/<username>/unlock")
@admin_required
def api_unlock_user(username):
    """Clear a user's attempt history, which releases any derived lock."""
    db = get_db()
    db.execute("DELETE FROM attempts WHERE username = ?", (username,))
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
    db.commit()
    return jsonify(ok=True)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
