-- schema.sql
-- Live browser demo database for the Behavioral Biometrics-Based Intrusion
-- Detection project. Six tables, matching the ERD in Chapter 4.
--
-- Scope: this database backs the LIVE demo only. It stores keystroke samples
-- collected in the browser (millisecond precision). It never holds CMU benchmark
-- data -- the two modes are kept separate on purpose.

PRAGMA foreign_keys = ON;

-- 1. Enrolled demo users (the people who register a typing profile).
--    password_hash guards the knowledge factor: the hash of the phrase this
--    user enrolled with (the default phrase unless they chose their own).
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT,
    created_at    TEXT    NOT NULL
);

-- 2. Admin accounts that can view the attempts dashboard. profile_json holds
--    the admin's optional keystroke-rhythm profile (second login factor),
--    serialised exactly like a user profile; NULL until the admin enrolls it.
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    profile_json  TEXT,
    created_at    TEXT    NOT NULL
);

-- 3. Raw enrollment samples: one typing vector per row, kept for auditing and
--    for rebuilding a profile if enrollment parameters change.
CREATE TABLE IF NOT EXISTS enrollment_samples (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    features   TEXT    NOT NULL,            -- JSON array of timing features
    created_at TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- 4. The computed matching profile for each user (the model the backend scores
--    against). One profile per user.
CREATE TABLE IF NOT EXISTS profiles (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL UNIQUE,
    detector     TEXT    NOT NULL,
    profile_json TEXT    NOT NULL,          -- full serialised profile dict
    threshold    REAL    NOT NULL,
    n_samples    INTEGER NOT NULL,
    updated_at   TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- 5. Every verification attempt, logged for the admin dashboard. username is
--    stored directly so attempts against unknown users are still recorded.
--
--    `outcome` records what the server DID, which is no longer a function of the
--    score alone: a borderline attempt is served as a retry the first few times
--    and only becomes a strike once the retry allowance is spent. Deriving the
--    band from score/threshold at read time could not tell those two apart, and
--    the lock counts strikes -- so the decision is written down at the moment it
--    is made. NULL means a row written before this column existed; init_db()
--    backfills those from `accepted`.
CREATE TABLE IF NOT EXISTS attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,                     -- NULL if the username was unknown
    username   TEXT    NOT NULL,
    score      REAL,
    threshold  REAL,
    accepted   INTEGER NOT NULL,            -- 0 = not signed in, 1 = accepted
    outcome    TEXT,                        -- 'accept' | 'suspicious' | 'reject'
    created_at TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

-- 6. Admin login sessions (server-side tokens with expiry).
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id   INTEGER NOT NULL,
    token      TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    FOREIGN KEY (admin_id) REFERENCES admins (id) ON DELETE CASCADE
);

-- 7. Audit trail of admin actions. Two jobs: it records who unlocked or deleted
--    an account, and it persists intrusion-alert acknowledgements. Intrusions
--    themselves stay derived from `attempts` -- they are not stored -- so an ack
--    refers to one by (target, detail) = (username, triggering attempt time).
CREATE TABLE IF NOT EXISTS admin_actions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id   INTEGER,                     -- NULL if that admin was later removed
    action     TEXT    NOT NULL,            -- 'unlock' | 'delete' | 'reset' |
                                            -- 'ack_intrusion' | 'enroll_rhythm' |
                                            -- 'change_password' | 'reset_rhythm'
    target     TEXT    NOT NULL,            -- username the action applies to
    detail     TEXT,                        -- ack: ISO time of the triggering attempt
    created_at TEXT    NOT NULL,
    FOREIGN KEY (admin_id) REFERENCES admins (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_actions_ack
    ON admin_actions (action, target, detail);

-- 8. Demo-user login sessions. Issued when a verification is ACCEPTED (phrase
--    and rhythm both matched), so the user can view their own profile at /me.
--    Mirrors `sessions`, but for enrolled users instead of admins.
CREATE TABLE IF NOT EXISTS user_sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token      TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
