"""
seed_demo.py
============

Populate the demo database with a few synthetic users and some verification
attempts, so the admin dashboard has data to show before anyone has typed
anything live.

    python seed_demo.py

WARNING: this resets demo.db (deletes any existing enrollments and attempts) to
give a clean, known state for a presentation. Run it BEFORE the live demo, not
after you've collected real data.

The synthetic samples use the same feature layout the browser produces (Hold /
Down-Down / Up-Down, interleaved per key, plus a trailing Enter key) so the
seeded profiles are compatible with real browser verifications.
"""

from __future__ import annotations

import json
import sqlite3

import numpy as np
from werkzeug.security import generate_password_hash

import app as A
import keystroke_model as km

RNG = np.random.default_rng(7)
N_KEYS = len(A.PHRASE) + 1          # phrase characters + Enter
USERS = ["alice", "bob", "carol"]


def feature_order(n_keys):
    """Same labels the front-end emits: H_i, DD_i_j, UD_i_j."""
    names = []
    for i in range(n_keys):
        names.append(f"H_{i}")
        if i < n_keys - 1:
            names += [f"DD_{i}_{i+1}", f"UD_{i}_{i+1}"]
    return names


ORDER = feature_order(N_KEYS)


def make_signature():
    """A user's characteristic timing vector (milliseconds), in ORDER."""
    vec = []
    for name in ORDER:
        if name.startswith("H"):
            vec.append(RNG.normal(100, 15))     # hold ~100 ms
        elif name.startswith("DD"):
            vec.append(RNG.normal(200, 30))     # down-down ~200 ms
        else:
            vec.append(RNG.normal(90, 25))      # up-down ~90 ms
    return np.array(vec)


def draw_sample(base, jitter=0.10):
    """One noisy typing sample around a signature."""
    return (base * (1 + RNG.normal(0, jitter, size=base.shape))).tolist()


def main():
    # Fresh database for a clean demo state.
    if A.DB_PATH.exists():
        A.DB_PATH.unlink()
    A.init_db()

    con = sqlite3.connect(A.DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    signatures = {u: make_signature() for u in USERS}

    # Enroll each synthetic user. The knowledge factor is set here, not left to
    # init_db()'s backfill: that backfill already ran above, so a NULL hash would
    # only be filled in on the *next* app start -- and verification crashes on a
    # NULL hash in the meantime.
    for user in USERS:
        cur.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (user, generate_password_hash(A.PHRASE), A.now_iso()),
        )
        user_id = cur.lastrowid

        samples = [draw_sample(signatures[user]) for _ in range(A.REQUIRED_SAMPLES)]
        for s in samples:
            cur.execute(
                "INSERT INTO enrollment_samples (user_id, features, created_at) "
                "VALUES (?, ?, ?)",
                (user_id, json.dumps(s), A.now_iso()),
            )

        profile = km.enroll(samples, feature_order=ORDER)
        cur.execute(
            "INSERT INTO profiles "
            "(user_id, detector, profile_json, threshold, n_samples, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                user_id,
                profile["detector"],
                json.dumps(profile),
                profile["threshold"],
                profile["n_samples"],
                A.now_iso(),
            ),
        )
    con.commit()

    # Log some attempts: genuine (should mostly accept) and impostor (should
    # mostly reject), so the dashboard shows a realistic mix.
    def log_attempt(username, sample):
        row = cur.execute(
            "SELECT p.profile_json, u.id AS uid "
            "FROM profiles p JOIN users u ON u.id = p.user_id "
            "WHERE u.username = ?",
            (username,),
        ).fetchone()
        profile = json.loads(row["profile_json"])
        result = km.verify(profile, sample, feature_order=ORDER)
        cur.execute(
            "INSERT INTO attempts "
            "(user_id, username, score, threshold, accepted, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                row["uid"],
                username,
                result["score"],
                result["threshold"],
                int(result["accepted"]),
                A.now_iso(),
            ),
        )
        return result["accepted"]

    genuine_ok = impostor_rejected = total_gen = total_imp = 0
    for user in USERS:
        other = next(u for u in USERS if u != user)
        for _ in range(3):                                  # genuine attempts
            total_gen += 1
            genuine_ok += log_attempt(user, draw_sample(signatures[user]))
        for _ in range(2):                                  # impostor attempts
            total_imp += 1
            impostor_rejected += not log_attempt(user, draw_sample(signatures[other]))
    con.commit()
    con.close()

    print(f"Seeded {len(USERS)} users: {', '.join(USERS)}")
    print(f"  genuine attempts accepted:  {genuine_ok}/{total_gen}")
    print(f"  impostor attempts rejected: {impostor_rejected}/{total_imp}")
    print("Start the app (python app.py) and open /admin to see the dashboard.")


if __name__ == "__main__":
    main()
