"""
app/ids.py
==========

The intrusion-detection core: decision bands, failure streaks, locks and alerts.

All of it is DERIVED from the `attempts` table -- nothing here stores "locked" or
"intrusion". The one thing that *is* written down is `attempts.outcome`, because
the band stopped being a function of the score alone: a borderline attempt is a
retry while the allowance holds and a strike once it is spent, and those two
carry identical scores. Read it through `band_of()`, never by re-deriving from
score/threshold.

Every function takes a `db` handle rather than reaching for one, so this module
is testable against a bare sqlite3 connection and has no Flask dependency.

`log_admin_action()` deliberately lives in `app/auth.py`, not here: it needs the
signed-in admin, and importing auth from this module would make the two mutually
dependent.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from flask import g

from app.config import FAIL_LOCK_STREAK, LOCK_COOLDOWN_MIN, SUSPICIOUS_MARGIN
from app.db import parse_iso


def decision_band(score: float, threshold: float) -> str:
    """Three-tier decision from the score's margin over the threshold."""
    if score <= threshold:
        return "accept"
    if score <= threshold * SUSPICIOUS_MARGIN:
        return "suspicious"
    return "reject"


def band_of(row) -> str:
    """The band recorded for a logged attempt row.

    The stored `outcome` is authoritative, because the band is no longer a pure
    function of the score: a borderline attempt reads 'suspicious' while the
    retry allowance holds and 'reject' once it is spent, and both carry the same
    score. Falling back to the score keeps rows written by an older build (and
    by seed_demo.py) readable.
    """
    outcome = row["outcome"] if "outcome" in row.keys() else None
    if outcome:
        return outcome
    if row["score"] is None or row["threshold"] is None:
        return "reject"
    return decision_band(row["score"], row["threshold"])


# The SQL form of band_of, so a band filter can be pushed into the query and
# paginate over the true match count instead of a page-local slice. `outcome` is
# backfilled by init_db(), so COALESCE only ever catches rows inserted by a
# writer that predates the column.
def _band_sql(band: str) -> str:
    legacy = ("CASE WHEN accepted = 1 THEN 'accept' "
              "WHEN score IS NULL OR threshold IS NULL THEN 'reject' "
              f"WHEN score <= threshold * {SUSPICIOUS_MARGIN} THEN 'suspicious' "
              "ELSE 'reject' END")
    return f"COALESCE(outcome, {legacy}) = '{band}'"


BAND_SQL = {band: _band_sql(band) for band in ("accept", "suspicious", "reject")}

# What each recorded outcome does to the lock. A retry ('suspicious') is
# deliberately neither: it does not add a strike, and it does not clear the
# strikes already standing. Skipping it rather than resetting is what stops an
# attacker from parking in the borderline band to wipe their record.
STRIKE = "reject"
NEUTRAL = "suspicious"


def trailing_outcomes(db, username):
    """This user's attempt outcomes, newest first, as (band, created_at) pairs."""
    rows = db.execute(
        "SELECT accepted, score, threshold, outcome, created_at FROM attempts "
        "WHERE username = ? ORDER BY id DESC",
        (username,),
    ).fetchall()
    return [(band_of(row), row["created_at"]) for row in rows]


def trailing_failure_streak(db, username):
    """Count consecutive strikes back from the latest attempt.

    An accept ends the run. A retry is stepped over without ending it and
    without counting -- see NEUTRAL.

    Returns (streak, most_recent_strike_time_iso_or_None).
    """
    streak = 0
    last_fail = None
    for band, created_at in trailing_outcomes(db, username):
        if band == "accept":
            break
        if band == NEUTRAL:
            continue
        streak += 1
        if last_fail is None:
            last_fail = created_at
    return streak, last_fail


def trailing_retry_run(db, username) -> int:
    """How many retries this user has been served since their last accepted login.

    The allowance is per failing *episode*, and only a success ends an episode.
    Counting back to the nearest non-retry instead would refresh the budget every
    time a strike landed, which turns the policy into "one strike per
    RETRY_ALLOWANCE+1 attempts" forever: an attacker parked in the borderline
    band would still reach the lock, but at a third of the rate, and a genuine
    user would never feel the system insist. Stepping over strikes -- rather than
    stopping at them -- is what makes the budget actually run out.
    """
    run = 0
    for band, _ in trailing_outcomes(db, username):
        if band == "accept":
            break
        if band == NEUTRAL:
            run += 1
    return run


def lock_status(db, username):
    """Is this account currently locked by the intrusion policy?

    Locked when the trailing failure streak has reached FAIL_LOCK_STREAK and the
    cooldown window (measured from the triggering failure) has not yet elapsed.
    Returns (is_locked, seconds_remaining).
    """
    streak, last_fail = trailing_failure_streak(db, username)
    if streak >= FAIL_LOCK_STREAK and last_fail:
        elapsed = (datetime.now(timezone.utc) - parse_iso(last_fail)).total_seconds()
        remaining = LOCK_COOLDOWN_MIN * 60 - elapsed
        if remaining > 0:
            return True, int(remaining)
    return False, 0


def lock_states(db, usernames):
    """Lock state for many users from ONE pass over `attempts`.

    Same rule as `lock_status()`, applied to a whole roster at once. The
    per-user form issues a query each time it is called, so the users page ran
    one full scan of `attempts` per row; this walks the log once instead.
    Returns {username: (is_locked, seconds_remaining)}.
    """
    rows = db.execute(
        "SELECT username, accepted, score, threshold, outcome, created_at FROM attempts "
        "ORDER BY id DESC"
    ).fetchall()

    streak: dict[str, int] = defaultdict(int)
    last_fail: dict[str, str] = {}
    settled: set[str] = set()          # users whose trailing streak has ended
    for row in rows:
        user = row["username"]
        if user in settled:
            continue
        band = band_of(row)
        if band == NEUTRAL:
            continue                   # a retry neither strikes nor settles
        if band == "accept":
            settled.add(user)          # newest attempt walking back was an accept
        else:
            streak[user] += 1
            last_fail.setdefault(user, row["created_at"])

    now = datetime.now(timezone.utc)
    states = {}
    for user in usernames:
        locked, remaining = False, 0
        if streak.get(user, 0) >= FAIL_LOCK_STREAK and user in last_fail:
            left = LOCK_COOLDOWN_MIN * 60 - (now - parse_iso(last_fail[user])).total_seconds()
            if left > 0:
                locked, remaining = True, int(left)
        states[user] = (locked, remaining)
    return states


def detect_intrusions(db):
    """Every point in the log where a failure run locked an account.

    An event is raised the first time a streak reaches FAIL_LOCK_STREAK, and
    again whenever a later failure re-locks an account whose previous lock had
    already lapsed -- which is what `lock_status()` actually does.

    Firing only on `== FAIL_LOCK_STREAK` (as this did) meant a user could raise
    exactly ONE alert ever: once the streak was past the limit, every further
    failure re-locked the account in silence, so a sustained attack against an
    already-acknowledged account never showed up in the feed again.
    """
    rows = db.execute(
        "SELECT username, accepted, score, threshold, outcome, created_at FROM attempts "
        "ORDER BY id ASC"
    ).fetchall()
    running = defaultdict(int)
    raised_at: dict[str, datetime] = {}   # user -> time of their last raised event
    events = []
    for row in rows:
        user = row["username"]
        band = band_of(row)
        if band == NEUTRAL:
            continue                      # a retry is not an intrusion signal
        if band == "accept":
            running[user] = 0             # a success ends the run and the lock
            raised_at.pop(user, None)
            continue
        running[user] += 1
        if running[user] < FAIL_LOCK_STREAK:
            continue
        when = parse_iso(row["created_at"])
        previous = raised_at.get(user)
        if previous is None or (when - previous).total_seconds() >= LOCK_COOLDOWN_MIN * 60:
            events.append({"username": user, "time": row["created_at"]})
            raised_at[user] = when
    return events


def cached_intrusions(db):
    """`detect_intrusions` memoised for the life of one request.

    Several things want the event list on a single page render -- the sidebar
    alert badge, the dashboard counters, the alerts feed -- and each call walks
    the whole `attempts` table. Nothing writes attempts on those requests, so
    one pass is enough.
    """
    if "intrusions" not in g:
        g.intrusions = detect_intrusions(db)
    return g.intrusions


def acknowledged_intrusions(db) -> set:
    """(username, time) pairs an admin has already signed off on."""
    rows = db.execute(
        "SELECT target, detail FROM admin_actions WHERE action = 'ack_intrusion'"
    ).fetchall()
    return {(r["target"], r["detail"]) for r in rows}


def open_intrusions(db):
    """Intrusion events that have not been acknowledged yet."""
    acked = acknowledged_intrusions(db)
    return [e for e in cached_intrusions(db) if (e["username"], e["time"]) not in acked]
