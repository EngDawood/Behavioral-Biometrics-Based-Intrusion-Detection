"""
app.py
======

Entry point. The backend itself lives in the `app/` package -- this file only
starts it.

    .venv/Scripts/python.exe app.py          # http://127.0.0.1:5000

Where the code went:

    app/config.py       every tunable, and what raising or lowering it costs
    app/db.py           connections, schema creation, in-place migrations
    app/validation.py   phrase policy and timing-vector coercion (pure)
    app/ids.py          decision bands, failure streaks, locks, intrusion alerts
    app/helpers.py      paging, LIKE escaping, the per-IP rate limiter
    app/auth.py         both auth stacks, session issuing, the audit-trail write
    app/enrollment.py   the transactional profile rebuild both enroll paths share
    app/views.py        public pages, /me, user self-service
    app/admin_views.py  the admin console pages
    app/api.py          the JSON API -- enroll, verify, admin, management
    app/templates/      13 Jinja templates (Flask resolves these per-package)
    app/static/         sentinel.css

Note that `import app` resolves to the PACKAGE, not to this file -- a package
shadows a same-named module. That is deliberate and it is what `seed_demo.py`
relies on: it does `import app as A` and reads the names `app/__init__.py`
re-exports. Running `python app.py` still executes this file, because running a
script by path does not go through the import system at all.

Default admin login: admin / admin123  (change ADMIN_PASSWORD in app/config.py).
"""

from __future__ import annotations

import os

from app import app, init_db

if __name__ == "__main__":
    init_db()
    # Werkzeug's debugger executes arbitrary code from the browser, so it is off
    # unless it is asked for explicitly (SENTINEL_DEBUG=1) and the bind address
    # is stated rather than inherited -- leaving `debug=True` in a file people
    # copy is how a demo becomes a remote shell.
    app.run(
        host=os.environ.get("SENTINEL_HOST", "127.0.0.1"),
        port=int(os.environ.get("SENTINEL_PORT", "5000")),
        debug=os.environ.get("SENTINEL_DEBUG") == "1",
    )
