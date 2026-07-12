"""
app.py
======

Flask backend for the live browser demo (Behavioral Biometrics-Based Intrusion
Detection).

The backend owns the decision: the browser only captures raw keystroke timings
and posts feature vectors. All matching happens here, using the SAME
`keystroke_model` module that drives the offline benchmark, so the demo and the
benchmark score samples with identical logic.

Flow:
    enroll  ->  browser sends N samples  ->  store raw samples + build/store profile
    verify  ->  browser sends 1 sample   ->  load profile, score, log attempt, decide
    admin   ->  log in, view every attempt on a dashboard

Run:
    pip install -r requirements.txt
    python app.py                 # http://127.0.0.1:5000
Default admin login: admin / admin123  (change ADMIN_PASSWORD below).
"""

from __future__ import annotations

import json
import secrets
import sqlite3
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

# The phrase every demo user types. Kept identical to the CMU benchmark password
# so the two modes stay conceptually aligned (the demo's profiles are still
# collected independently, in the browser, at millisecond precision).
PHRASE = ".tie5Roanl"
REQUIRED_SAMPLES = 10          # enrollment repetitions
SESSION_HOURS = 8             # admin session lifetime

# Seed admin (for the demo only -- change before any real deployment).
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

app = Flask(__name__)


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
    """Create tables (if missing) and seed the admin account once."""
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA_PATH.read_text())
    row = con.execute(
        "SELECT 1 FROM admins WHERE username = ?", (ADMIN_USERNAME,)
    ).fetchone()
    if row is None:
        con.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), now_iso()),
        )
    con.commit()
    con.close()


# --- admin auth (server-side session tokens) -------------------------------
def current_admin():
    token = request.cookies.get("admin_token")
    if not token:
        return None
    row = get_db().execute(
        "SELECT s.admin_id, s.expires_at, a.username "
        "FROM sessions s JOIN admins a ON a.id = s.admin_id "
        "WHERE s.token = ?",
        (token,),
    ).fetchone()
    if row is None:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return row


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_admin() is None:
            return redirect(url_for("admin_login_page"))
        return view(*args, **kwargs)

    return wrapped


# --- pages -----------------------------------------------------------------
@app.route("/")
def index():
    return render_template(
        "index.html", phrase=PHRASE, required_samples=REQUIRED_SAMPLES
    )


@app.route("/admin")
def admin_login_page():
    if current_admin() is not None:
        return redirect(url_for("admin_dashboard"))
    return render_template("admin.html", logged_in=False, attempts=[])


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    rows = get_db().execute(
        "SELECT id, username, score, threshold, accepted, created_at "
        "FROM attempts ORDER BY id DESC LIMIT 200"
    ).fetchall()
    admin = current_admin()
    return render_template(
        "admin.html", logged_in=True, attempts=rows, admin=admin["username"]
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
    # Upsert the user.
    row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        cur = db.execute(
            "INSERT INTO users (username, created_at) VALUES (?, ?)",
            (username, now_iso()),
        )
        user_id = cur.lastrowid
    else:
        user_id = row["id"]

    # Store the raw samples.
    for sample in samples:
        db.execute(
            "INSERT INTO enrollment_samples (user_id, features, created_at) "
            "VALUES (?, ?, ?)",
            (user_id, json.dumps(sample), now_iso()),
        )

    # Build the profile with the shared matcher and store it (one per user).
    try:
        profile = keystroke_model.enroll(samples, feature_order=feature_order)
    except ValueError as exc:
        db.rollback()
        return jsonify(error=str(exc)), 400

    db.execute("DELETE FROM profiles WHERE user_id = ?", (user_id,))
    db.execute(
        "INSERT INTO profiles "
        "(user_id, detector, profile_json, threshold, n_samples, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            user_id,
            profile["detector"],
            json.dumps(profile),
            profile["threshold"],
            profile["n_samples"],
            now_iso(),
        ),
    )
    db.commit()
    return jsonify(
        ok=True,
        username=username,
        n_samples=profile["n_samples"],
        threshold=round(profile["threshold"], 3),
    )


# --- API: verify -----------------------------------------------------------
@app.post("/api/verify")
def api_verify():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    sample = data.get("sample")
    feature_order = data.get("feature_order")

    if not username or not sample:
        return jsonify(error="username and sample are required"), 400

    db = get_db()
    row = db.execute(
        "SELECT p.profile_json, u.id AS user_id "
        "FROM profiles p JOIN users u ON u.id = p.user_id "
        "WHERE u.username = ?",
        (username,),
    ).fetchone()

    if row is None:
        # Unknown user: log the attempt as a rejection so the dashboard sees it.
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

    db.execute(
        "INSERT INTO attempts (user_id, username, score, threshold, accepted, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            row["user_id"],
            username,
            result["score"],
            result["threshold"],
            int(result["accepted"]),
            now_iso(),
        ),
    )
    db.commit()
    return jsonify(
        accepted=result["accepted"],
        score=round(result["score"], 3),
        threshold=round(result["threshold"], 3),
    )


# --- API: admin login / logout ---------------------------------------------
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
        "INSERT INTO sessions (admin_id, token, created_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (admin["id"], token, now_iso(), expires.isoformat()),
    )
    db.commit()

    resp = jsonify(ok=True)
    resp.set_cookie(
        "admin_token", token, httponly=True, samesite="Lax", max_age=SESSION_HOURS * 3600
    )
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


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
