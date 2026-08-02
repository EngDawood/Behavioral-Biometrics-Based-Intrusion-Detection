"""
app/admin_views.py
==================

The admin console pages: dashboard, user roster, event log, alert feed, analytics,
policy switchboard, the admin's own account, and the per-user drill-down.

Read-only views. Everything they show about locks and intrusions is derived from
`attempts` on read, via `app/ids.py`.

Every view keeps the endpoint name it had as a plain `@app.route` in the original
single-module `app.py`, so `_sidebar.html` and the rest of the templates need no
change.
"""

from __future__ import annotations

from flask import redirect, render_template, request, url_for

import keystroke_model

from app import app
from app.auth import admin_required, current_admin
from app.config import (
    ADMIN_ENROLL_SAMPLES,
    ADMIN_RHYTHM_MARGIN,
    ADMIN_RHYTHM_REQUIRED,
    FAIL_LOCK_STREAK,
    LOCK_COOLDOWN_MIN,
    PHRASE,
    PHRASE_MAX,
    PHRASE_MIN,
    ADMIN_RATE_LIMIT_MAX,
    ADMIN_RATE_LIMIT_WINDOW,
    ENROLL_RATE_LIMIT_MAX,
    ENROLL_RATE_LIMIT_WINDOW,
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW,
    REQUIRED_SAMPLES,
    RETRY_ALLOWANCE,
    SHOW_SCORE_DETAIL,
    SUSPICIOUS_MARGIN,
    TEMPO_NORMALISE,
    TRUST_PROXY,
)
from app.db import get_db, now_iso
from app.helpers import PAGE_SIZE, like_term, paginate
from app.ids import (
    BAND_SQL,
    acknowledged_intrusions,
    band_of,
    cached_intrusions,
    lock_states,
    lock_status,
)


@app.route("/admin")
def admin_login_page():
    if current_admin() is not None:
        return redirect(url_for("admin_dashboard"))
    # Whether the card promises the rhythm factor or announces first-time setup.
    # Deliberately an INSTALL-level fact -- "no admin has enrolled a rhythm yet"
    # -- and not a lookup on the typed username: this page is unauthenticated and
    # the username box is editable, so answering it per account would hand an
    # attacker an oracle for which admin is still single-factor. The flag fails
    # closed: the moment any admin enrolls it reverts to the two-factor copy, and
    # a profile-less admin is still routed into enrollment by api_admin_login()
    # once the password checks out, so the worst case is understated copy.
    enrolled = get_db().execute(
        "SELECT COUNT(*) c FROM admins WHERE profile_json IS NOT NULL"
    ).fetchone()["c"]
    return render_template("admin.html", logged_in=False,
                           admin_enroll_samples=ADMIN_ENROLL_SAMPLES,
                           rhythm_required=ADMIN_RHYTHM_REQUIRED,
                           rhythm_pending=ADMIN_RHYTHM_REQUIRED and not enrolled)


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()

    total = db.execute("SELECT COUNT(*) c FROM attempts").fetchone()["c"]
    accepted = db.execute("SELECT COUNT(*) c FROM attempts WHERE accepted = 1").fetchone()["c"]
    n_users = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    intrusions = cached_intrusions(db)

    usernames = [r["username"] for r in db.execute("SELECT username FROM users").fetchall()]
    states = lock_states(db, usernames)
    locked = [{"username": u, "remaining": states[u][1]} for u in usernames if states[u][0]]

    stats = {
        "users": n_users,
        "attempts": total,
        "accept_rate": round(100 * accepted / total, 1) if total else 0.0,
        "intrusions": len(intrusions),
        "locked": len(locked),
    }

    rows = db.execute(
        "SELECT id, username, score, threshold, accepted, outcome, created_at "
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

    # Lock state is derived per user, so the status filter runs in Python. The
    # whole roster is resolved in one pass -- calling lock_status() per row
    # rescanned `attempts` once for every user on the page.
    states = lock_states(db, [r["username"] for r in rows])
    users = []
    for r in rows:
        is_locked, remaining = states[r["username"]]
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
        "SELECT id, username, score, threshold, accepted, outcome, created_at FROM attempts "
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
    raised = cached_intrusions(db)
    states = lock_states(db, {e["username"] for e in raised})
    events = []
    for e in reversed(raised):
        is_locked, remaining = states[e["username"]]
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
        "SELECT username, score, threshold, accepted, outcome, created_at FROM attempts"
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
        # Bins close on the RIGHT (ratio <= edge), because the decision
        # boundaries do: `decision_band` accepts at exactly 1.0 and calls
        # exactly 1.15 suspicious. Closing them on the left put a ratio of
        # 1.0 -- an accept -- in the bin the chart paints as suspicious.
        for i, hi in enumerate(edges[1:]):
            if ratio <= hi:
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
        intrusions=len(cached_intrusions(db)),
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
        {"title": "Keystroke rhythm on the admin console",
         "desc": f"Require the admin's typing rhythm as a second factor at sign-in, enrolled "
                 f"over {ADMIN_ENROLL_SAMPLES} repetitions of the password and accepted within "
                 f"{ADMIN_RHYTHM_MARGIN}x the enrolled threshold. Off, /admin is password-only "
                 f"and a guessed or stolen admin password is the entire defence; enrolled "
                 f"profiles are kept, so turning it back on restores the factor unchanged.",
         "on": ADMIN_RHYTHM_REQUIRED},
        {"title": "Rate limit verification",
         "desc": f"Cap each client IP at {RATE_LIMIT_MAX} verification calls per "
                 f"{RATE_LIMIT_WINDOW} seconds, each admin sign-in at "
                 f"{ADMIN_RATE_LIMIT_MAX} per {ADMIN_RATE_LIMIT_WINDOW} seconds, and each "
                 f"enrollment at {ENROLL_RATE_LIMIT_MAX} per {ENROLL_RATE_LIMIT_WINDOW} seconds.",
         "on": RATE_LIMIT_MAX > 0},
        {"title": "Re-enrollment clears history",
         "desc": "Rebuilding a profile drops that user's old samples and attempt history, so a "
                 "stale failure streak cannot keep a freshly enrolled account locked.",
         "on": True},
        {"title": "Retraining needs a session, not just the phrase",
         "desc": "Overwriting an enrolled rhythm requires a signed-in session for that account "
                 "(or an admin) as well as the phrase, and is refused while the account is "
                 "locked. The phrase alone is one factor -- accepting it here would let anyone "
                 "who learned it replace the biometric and wipe the account's history.",
         "on": True},
        {"title": "Forgive a bad day, then insist",
         "desc": f"A borderline attempt is answered with a retry rather than a strike, up to "
                 f"{RETRY_ALLOWANCE} times in a row, so illness, an injured hand or plain "
                 f"tiredness does not freeze a real account. The run resets on any accept and "
                 f"every attempt past it is a strike, so the {FAIL_LOCK_STREAK}-strike lock is "
                 f"still reached -- it just costs an intruder {RETRY_ALLOWANCE} more tries.",
         "on": RETRY_ALLOWANCE > 0},
        {"title": "Score the rhythm's shape, not its speed",
         "desc": "Each attempt is divided by its own tempo before scoring, so typing the same "
                 "pattern uniformly slower is forgiven while typing a different pattern is not. "
                 f"The correction is clamped to {keystroke_model.TEMPO_MIN}x-{keystroke_model.TEMPO_MAX}x "
                 "so it cannot rescale an arbitrary sample onto the profile.",
         "on": TEMPO_NORMALISE},
        {"title": "Return score detail to the client",
         "desc": "The result screen shows the distance, the threshold and the per-key deviation. "
                 "That is also a hill-climbing oracle, so a real deployment turns it off "
                 "(SENTINEL_HIDE_SCORES=1) and returns the decision band alone.",
         "on": SHOW_SCORE_DETAIL},
        {"title": "Trust X-Forwarded-For",
         "desc": "Off unless this process really sits behind a proxy that sets the header "
                 "(SENTINEL_TRUST_PROXY=1). Reading it otherwise lets a caller pick their own "
                 "rate-limit bucket, which defeats the limit entirely.",
         "on": TRUST_PROXY},
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
        retry_allowance=RETRY_ALLOWANCE,
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
        rhythm_required=ADMIN_RHYTHM_REQUIRED,
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
        "SELECT id, score, threshold, accepted, outcome, created_at "
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
