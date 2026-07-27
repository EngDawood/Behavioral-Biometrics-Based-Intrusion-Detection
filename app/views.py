"""
app/views.py
============

The public pages, the signed-in user's own view at /me, and the self-service
endpoints that go with it.

Every view keeps the endpoint name it had as a plain `@app.route` in the original
single-module `app.py`, so the `url_for()` calls in the templates are untouched.
"""

from __future__ import annotations

from flask import jsonify, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import keystroke_model

from app import app
from app.auth import current_user, user_required
from app.config import (
    FAIL_LOCK_STREAK,
    LOCK_COOLDOWN_MIN,
    PHRASE,
    PHRASE_MAX,
    PHRASE_MIN,
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW,
    REQUIRED_SAMPLES,
    SUSPICIOUS_MARGIN,
)
from app.db import get_db
from app.enrollment import store_enrollment
from app.ids import band_of, lock_status
from app.validation import (
    clean_feature_order,
    clean_samples,
    expected_features,
    validate_phrase,
)


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
    return render_template(
        "about.html",
        phrase=PHRASE,
        required_samples=REQUIRED_SAMPLES,
        n_features=expected_features(PHRASE),
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
        "SELECT id, score, threshold, accepted, outcome, created_at "
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
    try:
        feature_order = clean_feature_order(feature_order)
        samples = clean_samples(samples, expected_features(new_phrase), REQUIRED_SAMPLES)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    try:
        profile = store_enrollment(
            db, user["user_id"], user["username"], samples, feature_order
        )
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
