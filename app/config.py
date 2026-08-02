"""
app/config.py
=============

Every tunable the backend has, with a note on what raising or lowering it costs.

Policy numbers live here as module constants, not in the environment: what the
policy screen shows and what the decision path enforces must not be able to
drift apart. The only environment variables are deployment *posture* -- proxy
trust, score disclosure, debug -- and every one of them defaults to the safe
value, so a plain `python app.py` is the demo.
"""

from __future__ import annotations

import os
from pathlib import Path

# BASE_DIR is the REPOSITORY ROOT, not this package. `Path(__file__).parent`
# would point at app/, which would put demo.db and schema.sql inside the
# package -- the running app would quietly create an empty database next to the
# code and leave the real one behind at the root. The extra `.parent` is what
# keeps both files where they have always been.
BASE_DIR = Path(__file__).resolve().parent.parent
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

# The master switch for the admin's keystroke second factor. Turning it off
# costs the console its biometric factor outright: /admin becomes password-only,
# and a stolen or guessed admin password is then the whole of the defence -- the
# exact attack the rhythm check exists to answer. It is here for the demo, where
# a projector, an unfamiliar keyboard or a nervous presenter can make a rehearsed
# rhythm fail in front of an audience, and for recovering a console whose only
# admin can no longer reproduce their own typing. Enrolled profiles are left
# untouched while it is off, so flipping it back restores the factor as it was.
ADMIN_RHYTHM_REQUIRED = True

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

# Anomaly tolerance. A genuine user has bad days -- illness, an injured hand, a
# borrowed keyboard, plain tiredness -- and the cost of getting that wrong is not
# symmetric: a locked-out real user is a support ticket and a lost user, while a
# borderline attempt that is asked to try once more costs an attacker one extra
# attempt out of a budget the lock is about to end anyway.
#
# RETRY_ALLOWANCE is how many times IN A ROW a borderline ("suspicious") attempt
# is answered with "type it again" instead of counting toward the lock. The run
# is consecutive and resets on any accept, so it cannot be farmed: an attacker
# parked in the suspicious band gets RETRY_ALLOWANCE free attempts and every one
# after that is a strike, which still reaches the lock.
RETRY_ALLOWANCE = 2

# Score the SHAPE of the rhythm rather than its speed (keystroke_model.verify).
# This is what covers the sick / injured / tired user directly: they type the
# same pattern slower, which without this pushes every feature off its mean at
# once. See keystroke_model.TEMPO_MIN for the bound on how far it can reach.
TEMPO_NORMALISE = True

# Intrusion detection policy.
FAIL_LOCK_STREAK = 3           # this many consecutive strikes -> intrusion + lock
LOCK_COOLDOWN_MIN = 5          # lock duration, measured from the triggering failure

# Rate limiting (per client IP).
RATE_LIMIT_MAX = 30            # max verify calls ...
RATE_LIMIT_WINDOW = 60        # ... per this many seconds

# Admin login is guessed at, not typed at, so it gets a tighter budget than
# verification: a human operator needs a handful of tries, a script wants
# thousands.
ADMIN_RATE_LIMIT_MAX = 10
ADMIN_RATE_LIMIT_WINDOW = 300

# Enrollment is slow for a human -- REQUIRED_SAMPLES typed repetitions -- so a
# generous human allowance is still a tight machine one.
ENROLL_RATE_LIMIT_MAX = 10
ENROLL_RATE_LIMIT_WINDOW = 300

# Only trust X-Forwarded-For when this process really does sit behind a proxy
# that sets it. Reading the header unconditionally hands every client its own
# rate-limit bucket -- the limiter then counts nothing.
TRUST_PROXY = os.environ.get("SENTINEL_TRUST_PROXY") == "1"

# How many client IPs the in-memory limiter will track before it evicts the
# idle ones. Bounds the memory an attacker can make this process hold.
RATE_LIMIT_MAX_IPS = 4096

# Whether a verification response carries the score, threshold and per-key
# deviations. The demo needs them -- they are what the result screen draws --
# but they also tell an attacker exactly which keystroke to adjust next, so a
# real deployment sets this False and returns the band alone.
SHOW_SCORE_DETAIL = os.environ.get("SENTINEL_HIDE_SCORES") != "1"

# Seed admin (demo only -- change before any real deployment).
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
