"""
app/__init__.py
===============

The Flask application object, its request hooks, and the imports that attach the
routes.

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
    * basic hardening      -- per-IP rate limiting on verification

Design note: all lock and intrusion state is DERIVED from the `attempts` table.
Relative to the ERD in Chapter 4, the schema gains two nullable columns --
users.password_hash (a per-user secret phrase, so the demo carries a knowledge
factor next to the biometric one) and admins.profile_json (the admin's own
keystroke-rhythm profile, used as a second login factor) -- and one table,
`user_sessions`: an ACCEPTED verification signs the user in so they can view
their own profile at /me. The backend still owns every decision; the browser
only captures raw keystroke timings.

Layout note: `Flask(__name__)` resolves its template and static folders relative
to THIS package, so `templates/` and `static/` live inside `app/`. The database
and `schema.sql` do not -- see the BASE_DIR comment in `app/config.py`.

Run:
    pip install -r requirements.txt
    python app.py                 # http://127.0.0.1:5000
Default admin login: admin / admin123  (change ADMIN_PASSWORD in app/config.py).
"""

from __future__ import annotations

from flask import Flask

from app.auth import inject_nav
from app.db import close_db

app = Flask(__name__)

# Registered here rather than with decorators in their own modules, so that
# app/db.py and app/auth.py import nothing from this package and cannot take
# part in an import cycle.
app.teardown_appcontext(close_db)
app.context_processor(inject_nav)

# --- re-exports -------------------------------------------------------------
# `seed_demo.py` does `import app as A` and reads these seven names off it. Since
# a package shadows a same-named module, that import resolves HERE and not to the
# root `app.py` entry point -- so these have to be reachable from this module or
# seeding breaks at attribute access.
from app.config import (  # noqa: E402,F401
    DB_PATH,
    PHRASE,
    REQUIRED_SAMPLES,
    TEMPO_NORMALISE,
)
from app.db import init_db, now_iso  # noqa: E402,F401
from app.ids import decision_band  # noqa: E402,F401

# --- route registration -----------------------------------------------------
# Imported LAST, and for their side effects: each module decorates its views with
# `@app.route` / `@app.post` against the object created above. Plain routes on a
# single app object rather than blueprints, so every endpoint name stays exactly
# what the 13 templates already pass to `url_for()`.
from app import admin_views, api, views  # noqa: E402,F401
