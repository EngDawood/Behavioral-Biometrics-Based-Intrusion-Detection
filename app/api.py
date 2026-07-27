"""
app/api.py
==========

The JSON API: enrollment, verification, admin sign-in, and the admin management
endpoints that unlock, reset, delete and acknowledge.

This is where the decisions are made. The browser only posts raw keystroke
timings and renders the band that comes back.

Every endpoint keeps the URL, method, status codes and JSON keys it had in the
original single-module `app.py` -- the `fetch()` calls in the templates are
untouched.
"""

from __future__ import annotations

import json
import secrets

from flask import jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

import keystroke_model

from app import app
from app.auth import (
    admin_required,
    current_admin,
    current_user,
    issue_admin_session,
    issue_user_session,
    log_admin_action,
)
from app.config import (
    ADMIN_ENROLL_SAMPLES,
    ADMIN_RATE_LIMIT_MAX,
    ADMIN_RATE_LIMIT_WINDOW,
    ADMIN_RHYTHM_MARGIN,
    ENROLL_RATE_LIMIT_MAX,
    ENROLL_RATE_LIMIT_WINDOW,
    FAIL_LOCK_STREAK,
    LOCK_COOLDOWN_MIN,
    PHRASE,
    RATE_LIMIT_WINDOW,
    REQUIRED_SAMPLES,
    RETRY_ALLOWANCE,
    SHOW_SCORE_DETAIL,
    TEMPO_NORMALISE,
)
from app.db import get_db, now_iso
from app.enrollment import store_enrollment
from app.helpers import client_ip, rate_limited
from app.ids import (
    acknowledged_intrusions,
    decision_band,
    lock_status,
    trailing_failure_streak,
    trailing_retry_run,
)
from app.validation import (
    clean_feature_order,
    clean_sample,
    clean_samples,
    expected_features,
    validate_phrase,
)

# Compared against when no real hash is available, so an unknown username costs
# the same time as a known one (see api_verify).
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16))


# --- API: enroll -----------------------------------------------------------
@app.post("/api/enroll")
def api_enroll():
    # Enrollment writes the biometric factor, so it gets a budget of its own.
    # Without one this endpoint was an unthrottled oracle: it answers "taken" or
    # "created" for any name, and it will happily do so thousands of times a
    # minute. Throttling is the honest mitigation -- any endpoint that creates
    # accounts by name necessarily reveals which names are free, exactly as a
    # signup form does, so the goal is to make sweeping the namespace slow rather
    # than to pretend the distinction can be hidden.
    if rate_limited(client_ip(), ENROLL_RATE_LIMIT_MAX, ENROLL_RATE_LIMIT_WINDOW, "enroll"):
        return jsonify(error="too many enrollment attempts, slow down",
                       retry_after=ENROLL_RATE_LIMIT_WINDOW), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    samples = data.get("samples")
    feature_order = data.get("feature_order")

    if not username or not samples:
        return jsonify(error="username and samples are required"), 400

    # The phrase is both the secret and the timing template. No custom phrase
    # means the default one; a custom phrase must pass the policy, and either
    # way every sample must have the feature count that phrase implies.
    if password:
        err = validate_phrase(password)
        if err:
            return jsonify(error=err), 400
    else:
        password = PHRASE

    try:
        feature_order = clean_feature_order(feature_order)
        samples = clean_samples(samples, expected_features(password), REQUIRED_SAMPLES)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    db = get_db()
    # Usernames are matched case-insensitively, so enrolling "dawood" when
    # "Dawood" already exists re-enrolls that same account rather than making a
    # second one. The stored casing is kept as first entered.
    row = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE",
        (username,),
    ).fetchone()
    if row is None:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), now_iso()),
        )
        user_id = cur.lastrowid
    else:
        user_id = row["id"]
        # Attempts are logged under the stored casing, so the clear-down in
        # store_enrollment has to use it too, not whatever casing was typed.
        username = row["username"]
        # Re-enrolling an account that already has a profile overwrites the
        # biometric factor, so it has to be authorised by more than the phrase.
        #
        # Requiring the phrase ALONE (as this did) was still a full takeover for
        # anyone who had learned it: they could overwrite the rhythm profile with
        # their own, and -- via store_enrollment -- delete the account's entire
        # attempt history, releasing the lock and destroying the evidence in the
        # same request. That collapses two factors back into one, which is the
        # whole premise of the system. Worse, api_enroll never consulted
        # lock_status(), so it worked *while the account was locked*: three
        # rejected attempts, then re-enroll, and the intruder is the owner.
        #
        # So a retrain now needs a live session for that same account (proof the
        # rhythm passed recently) or an admin, AND the phrase, AND an unlocked
        # account. The genuine case this is meant to serve -- a user whose rhythm
        # is drifting -- still works: they sign in normally and retrain. A user
        # already locked out cannot self-serve, by design; that is an admin
        # reset, the same as any other biometric system's helpdesk path.
        enrolled = db.execute(
            "SELECT 1 FROM profiles WHERE user_id = ?", (user_id,)
        ).fetchone()
        if enrolled is not None:
            is_locked, remaining = lock_status(db, username)
            if is_locked:
                return jsonify(
                    error="account temporarily locked -- re-enrollment cannot clear a lock",
                    locked=True, retry_after=remaining,
                ), 423

            signed_in = current_user()
            owner = signed_in is not None and signed_in["user_id"] == user_id
            if not (owner or current_admin()):
                return jsonify(
                    error=f'"{username}" is already enrolled. Retraining its rhythm requires '
                          f"signing in first, or an admin reset.",
                    username_taken=True,
                ), 409
            if not row["password_hash"] or not check_password_hash(row["password_hash"], password):
                return jsonify(
                    error="that is not the phrase this account is enrolled with",
                ), 401
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(password), user_id),
        )

    try:
        profile = store_enrollment(db, user_id, username, samples, feature_order)
    except ValueError as exc:
        db.rollback()
        return jsonify(error=str(exc)), 400
    db.commit()
    return jsonify(ok=True, username=username, n_samples=profile["n_samples"],
                   threshold=round(profile["threshold"], 3))


# --- API: verify -----------------------------------------------------------
@app.post("/api/verify")
def api_verify():
    if rate_limited(client_ip()):
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

    # Shape-check before numpy sees it: a malformed vector used to escape as a
    # 500, and a vector of nulls scored NaN and was serialised as invalid JSON.
    try:
        feature_order = clean_feature_order(feature_order)
        sample = clean_sample(sample)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

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

    # Knowledge factor first: the typed text must match the enrolled phrase
    # before the rhythm is even scored. A wrong phrase is logged as a scoreless
    # reject, so it feeds the same failure-streak / lock policy as a bad rhythm.
    #
    # An unknown username takes this same path, with the same status and the
    # same message. Answering it with a distinct 404 ("no profile for that
    # username") turned the endpoint into a directory: anyone could ask it
    # which accounts existed. The dummy comparison keeps the timing of the two
    # cases comparable, so the hash work does not leak what the status no
    # longer does.
    stored_hash = row["password_hash"] if row is not None else None
    if not stored_hash or not check_password_hash(stored_hash, typed):
        if not stored_hash:
            check_password_hash(_DUMMY_HASH, typed)
        # A wrong phrase is a strike, never a retry: the retry allowance exists to
        # forgive a rhythm that drifted, and nothing about the typed text drifts.
        db.execute(
            "INSERT INTO attempts "
            "(user_id, username, score, threshold, accepted, outcome, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (row["user_id"] if row is not None else None, username,
             None, None, 0, "reject", now_iso()),
        )
        db.commit()
        streak, _ = trailing_failure_streak(db, username)
        intrusion = streak >= FAIL_LOCK_STREAK
        return jsonify(
            error="verification failed -- check the username and phrase, and that "
                  "this account has been enrolled",
            accepted=False,
            intrusion=intrusion,
            locked=intrusion,
            retry_after=LOCK_COOLDOWN_MIN * 60 if intrusion else 0,
            fail_streak=streak,
        ), 401

    profile = json.loads(row["profile_json"])
    try:
        result = keystroke_model.verify(
            profile, sample, feature_order=feature_order,
            tempo_normalise=TEMPO_NORMALISE,
        )
    except (ValueError, TypeError) as exc:
        return jsonify(error=str(exc)), 400

    band = decision_band(result["score"], result["threshold"])

    # The retry allowance. A borderline score is answered with "type it again"
    # rather than a strike, but only while the run of retries is under budget --
    # otherwise an attacker sitting in the borderline band would never reach the
    # lock. `retries_left` is read BEFORE this attempt is logged, so it describes
    # the budget this attempt is spending.
    retries_left = 0
    if band == "suspicious":
        spent = trailing_retry_run(db, username)
        if spent >= RETRY_ALLOWANCE:
            band = "reject"          # allowance exhausted: this one counts
        else:
            retries_left = RETRY_ALLOWANCE - spent - 1

    accepted = band == "accept"

    db.execute(
        "INSERT INTO attempts "
        "(user_id, username, score, threshold, accepted, outcome, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (row["user_id"], username, result["score"], result["threshold"],
         int(accepted), band, now_iso()),
    )
    db.commit()

    # Did this attempt just trigger an intrusion lock? A retry cannot: it is not
    # a strike, so it never moves the streak.
    streak, _ = trailing_failure_streak(db, username)
    intrusion = band == "reject" and streak >= FAIL_LOCK_STREAK

    payload = dict(
        accepted=accepted,
        band=band,
        intrusion=intrusion,
        locked=intrusion,
        retry_after=LOCK_COOLDOWN_MIN * 60 if intrusion else 0,
        fail_streak=streak,
        retries_left=retries_left,
    )
    # The score, the threshold and the per-key deviations are what the result
    # screen draws -- and also a hill-climbing oracle, telling an unauthenticated
    # caller exactly which keystroke to adjust next. The demo keeps them; a real
    # deployment sets SENTINEL_HIDE_SCORES=1 and returns the band alone.
    if SHOW_SCORE_DETAIL:
        payload.update(
            score=round(result["score"], 3),
            threshold=round(result["threshold"], 3),
            deviations=hold_deviations(profile, result["deviations"]),
            # 1.0 = the enrolled pace. Reported so the result screen can say
            # "you typed 1.4x slower than usual" instead of leaving a forgiven
            # attempt looking unexplained.
            tempo=round(result["tempo"], 3),
            raw_score=round(result["raw_score"], 3),
        )
    resp = jsonify(**payload)
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
@app.post("/api/admin/login")
def api_admin_login():
    """Two-factor admin login: password hash first, then keystroke rhythm.

    An admin with no rhythm profile yet is told to enroll one (the client then
    walks them through it); once a profile exists, a login must carry a timing
    sample whose score lands within ADMIN_RHYTHM_MARGIN of the enrolled
    threshold. That generous margin -- rather than the bare threshold -- keeps
    a slightly-off day from locking the only admin out of the console.
    """
    # Password guessing is cheap and this endpoint had no ceiling at all: forty
    # wrong passwords in a row drew forty plain 401s. The rhythm factor only
    # helps once a profile exists, so the budget is enforced first, and on a
    # tighter window than verification gets.
    if rate_limited(client_ip(), ADMIN_RATE_LIMIT_MAX, ADMIN_RATE_LIMIT_WINDOW, "admin"):
        return jsonify(error="too many sign-in attempts, slow down",
                       retry_after=ADMIN_RATE_LIMIT_WINDOW), 429

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
            json.loads(admin["profile_json"]),
            clean_sample(sample),
            feature_order=clean_feature_order(feature_order),
        )
    except (ValueError, TypeError):
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
    # Guarded by the password, so it is guessable in exactly the same way the
    # login is -- and it writes the biometric factor, so it gets the same budget.
    if rate_limited(client_ip(), ADMIN_RATE_LIMIT_MAX, ADMIN_RATE_LIMIT_WINDOW, "admin"):
        return jsonify(error="too many sign-in attempts, slow down",
                       retry_after=ADMIN_RATE_LIMIT_WINDOW), 429

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

    try:
        feature_order = clean_feature_order(feature_order)
        samples = clean_samples(samples, expected_features(password), ADMIN_ENROLL_SAMPLES)
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
