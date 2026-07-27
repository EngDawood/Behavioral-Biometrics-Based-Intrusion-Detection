"""
app/auth.py
===========

The two parallel auth stacks, deliberately mirrored:

    current_admin() / admin_required / issue_admin_session()   over `sessions`
    current_user()  / user_required  / issue_user_session()    over `user_sessions`

Both read an httponly, SameSite=Lax cookie holding a `secrets.token_urlsafe(32)`.
`@*_required` returns 401 JSON for `/api/` paths and redirects otherwise.

`inject_nav()` is a plain function here; the package factory registers it with
`app.context_processor(inject_nav)` so this module needs no import from the
package.

`log_admin_action()` lives here rather than in `app/ids.py` -- where the rest of
the audit-trail reading happens -- because it needs the signed-in admin, and
having ids import auth while auth imports ids would be a cycle.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import jsonify, redirect, request, url_for

from app.config import SESSION_HOURS
from app.db import get_db, now_iso, parse_iso, purge_expired_sessions
from app.ids import open_intrusions


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
    if row is None or parse_iso(row["expires_at"]) < datetime.now(timezone.utc):
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


def issue_admin_session(db, admin_id: int):
    """Create a session row and return the ok-response carrying its cookie."""
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    purge_expired_sessions(db)
    db.execute(
        "INSERT INTO sessions (admin_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (admin_id, token, now_iso(), expires.isoformat()),
    )
    db.commit()
    resp = jsonify(ok=True)
    resp.set_cookie("admin_token", token, httponly=True, samesite="Lax",
                    max_age=SESSION_HOURS * 3600)
    return resp


def log_admin_action(db, action: str, target: str, detail: str | None = None) -> None:
    """Record an admin action in the audit trail. Caller commits."""
    admin = current_admin()
    db.execute(
        "INSERT INTO admin_actions (admin_id, action, target, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (admin["admin_id"] if admin else None, action, target, detail, now_iso()),
    )


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
    if row is None or parse_iso(row["expires_at"]) < datetime.now(timezone.utc):
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
    purge_expired_sessions(db)
    db.execute(
        "INSERT INTO user_sessions (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, token, now_iso(), expires.isoformat()),
    )
    db.commit()
    resp.set_cookie("user_token", token, httponly=True, samesite="Lax",
                    max_age=SESSION_HOURS * 3600)
    return resp


# --- shared navigation state ------------------------------------------------
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
