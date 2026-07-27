"""
app/enrollment.py
=================

Rebuilding a user's enrollment: samples, profile, and the lock state that a fresh
enrollment clears.

Its own module because two different routes share it -- first enrollment
(`/api/enroll`) and a phrase change (`/api/user/password`) -- and both have to
rebuild the same way. Keeping it out of either route module means neither has to
import the other.
"""

from __future__ import annotations

import json

import keystroke_model

from app.db import now_iso


def store_enrollment(db, user_id: int, username: str, samples, feature_order):
    """Rebuild a user's enrollment from scratch: samples, profile, lock state.

    Shared by first enrollment and by a phrase change, because both have to
    rebuild the same way -- a profile only means anything for the phrase it was
    trained on. The model is fitted before anything is written, so a bad sample
    set raises ValueError while the database is still untouched. The caller owns
    the transaction.

    `username` is required as well as `user_id` because the two identify
    different rows in `attempts`: an attempt against a name that was not
    enrolled *yet* is logged with a NULL user_id (there is no user to point at),
    while every streak is counted by username. Clearing by user_id alone left
    those rows behind, so three failed attempts before enrolling produced an
    account that was locked the moment it was created.
    """
    profile = keystroke_model.enroll(samples, feature_order=feature_order)

    db.execute("DELETE FROM enrollment_samples WHERE user_id = ?", (user_id,))
    for sample in samples:
        db.execute(
            "INSERT INTO enrollment_samples (user_id, features, created_at) VALUES (?, ?, ?)",
            (user_id, json.dumps(sample), now_iso()),
        )

    db.execute("DELETE FROM profiles WHERE user_id = ?", (user_id,))
    db.execute(
        "INSERT INTO profiles (user_id, detector, profile_json, threshold, n_samples, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, profile["detector"], json.dumps(profile),
         profile["threshold"], profile["n_samples"], now_iso()),
    )
    # A fresh enrollment clears any prior failed-attempt streak / lock, whether
    # those attempts were logged against the account or against the bare name.
    db.execute(
        "DELETE FROM attempts WHERE user_id = ? OR username = ?", (user_id, username)
    )
    return profile
