-- schema.sql
-- Live browser demo database for the Behavioral Biometrics-Based Intrusion
-- Detection project. Six tables, matching the ERD in Chapter 4.
--
-- Scope: this database backs the LIVE demo only. It stores keystroke samples
-- collected in the browser (millisecond precision). It never holds CMU benchmark
-- data -- the two modes are kept separate on purpose.

PRAGMA foreign_keys = ON;

-- 1. Enrolled demo users (the people who register a typing profile).
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL
);

-- 2. Admin accounts that can view the attempts dashboard.
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
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
CREATE TABLE IF NOT EXISTS attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,                     -- NULL if the username was unknown
    username   TEXT    NOT NULL,
    score      REAL,
    threshold  REAL,
    accepted   INTEGER NOT NULL,            -- 0 = rejected, 1 = accepted
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
    action     TEXT    NOT NULL,            -- 'unlock' | 'delete' | 'ack_intrusion'
    target     TEXT    NOT NULL,            -- username the action applies to
    detail     TEXT,                        -- ack: ISO time of the triggering attempt
    created_at TEXT    NOT NULL,
    FOREIGN KEY (admin_id) REFERENCES admins (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_actions_ack
    ON admin_actions (action, target, detail);
