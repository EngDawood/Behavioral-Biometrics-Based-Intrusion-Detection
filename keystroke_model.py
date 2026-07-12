"""
keystroke_model.py
==================

Shared keystroke-dynamics matching logic for the Behavioral Biometrics-Based
Intrusion Detection project.

This module is the single source of truth for *how a typing sample is scored*.
It is imported unchanged by two callers:

    * train.py               -- the offline CMU benchmark evaluation
    * the Flask backend       -- the live enroll -> verify demo

Design rules honoured here:
    * The primary detector is **Scaled Manhattan** (Manhattan distance normalised
      by each feature's Mean Absolute Deviation). The same detector is used by the
      benchmark and the live demo, so both modes tell one coherent story.
    * This module contains **matching logic only**. No Flask, no SQLite, no HTTP,
      no browser/DOM code. Profile persistence and request handling belong to the
      backend; this file just turns samples into scores and decisions.
    * Profiles are plain, JSON-serialisable dicts so the backend can store them in
      SQLite without any pickling.

A "sample" is one password-timing vector: a 1-D sequence of timing features
(Hold, Down-Down, Up-Down) in a fixed, agreed order. The caller is responsible
for extracting features in a consistent order; `enroll` records that order in the
profile and `verify` checks it.
"""

from __future__ import annotations

import numpy as np

__all__ = [
    "ScaledManhattanDetector",
    "ManhattanDetector",
    "EuclideanDetector",
    "NearestNeighbourDetector",
    "DETECTORS",
    "enroll",
    "verify",
    "DEFAULT_THRESHOLD_K",
]

# How many standard deviations above the mean genuine (training) score the
# accept/reject boundary sits, when a profile does not specify its own threshold.
# Larger  -> more permissive (fewer legitimate users locked out, more intruders let in).
# This is a starting heuristic for the live demo; it can be tuned per deployment.
DEFAULT_THRESHOLD_K = 1.5


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------
# Every detector exposes the same tiny interface:
#     .fit(X)   -> self         (X: 2-D array, one training vector per row)
#     .score(X) -> 1-D array    (one distance per row; LOWER = more genuine)
# This uniform shape is what lets train.py loop over all four detectors and lets
# the backend swap detectors without touching its own code.


class ScaledManhattanDetector:
    """Primary detector: Manhattan distance scaled by per-feature MAD.

    Noisy features (large mean absolute deviation across a user's training
    samples) are down-weighted, which is what gives this detector its edge over
    plain Manhattan on the CMU benchmark (~9.6% vs ~15.3% EER).
    """

    name = "Scaled Manhattan"

    def fit(self, X):
        X = np.asarray(X, dtype=float)
        self.mean_ = X.mean(axis=0)
        mad = np.abs(X - self.mean_).mean(axis=0)
        mad[mad == 0] = 1.0  # guard: a zero-variance feature must not divide by 0
        self.mad_ = mad
        return self

    def score(self, X):
        X = np.atleast_2d(np.asarray(X, dtype=float))
        return (np.abs(X - self.mean_) / self.mad_).sum(axis=1)


class ManhattanDetector:
    """Plain Manhattan distance from the per-feature mean (benchmark baseline)."""

    name = "Manhattan"

    def fit(self, X):
        self.mean_ = np.asarray(X, dtype=float).mean(axis=0)
        return self

    def score(self, X):
        X = np.atleast_2d(np.asarray(X, dtype=float))
        return np.abs(X - self.mean_).sum(axis=1)


class EuclideanDetector:
    """Squared Euclidean distance from the per-feature mean (benchmark baseline)."""

    name = "Euclidean"

    def fit(self, X):
        self.mean_ = np.asarray(X, dtype=float).mean(axis=0)
        return self

    def score(self, X):
        X = np.atleast_2d(np.asarray(X, dtype=float))
        return ((X - self.mean_) ** 2).sum(axis=1)


class NearestNeighbourDetector:
    """Minimum L1 distance to any single training vector (benchmark comparison)."""

    name = "Nearest Neighbour"

    def fit(self, X):
        self.train_ = np.asarray(X, dtype=float)
        return self

    def score(self, X):
        X = np.atleast_2d(np.asarray(X, dtype=float))
        return np.array([np.abs(self.train_ - x).sum(axis=1).min() for x in X])


# Registry used by train.py. The primary detector is listed first on purpose.
DETECTORS = {
    "Scaled Manhattan": ScaledManhattanDetector,
    "Nearest Neighbour": NearestNeighbourDetector,
    "Manhattan": ManhattanDetector,
    "Euclidean": EuclideanDetector,
}


# ---------------------------------------------------------------------------
# Backend-facing API: enroll -> verify
# ---------------------------------------------------------------------------
# These two functions are what the Flask backend calls. They wrap the primary
# detector and return / accept plain dicts so a profile can be JSON-encoded into
# SQLite and read back later. No detector object is ever persisted.


def enroll(samples, feature_order=None, threshold_k=DEFAULT_THRESHOLD_K):
    """Build a storable profile from a user's enrollment samples.

    Parameters
    ----------
    samples : array-like, shape (n_samples, n_features)
        Timing vectors captured while the user repeatedly typed the password.
    feature_order : list[str] or None
        Names of the features, in the exact order they appear in each sample.
        Recorded in the profile so `verify` can reject a mismatched sample.
    threshold_k : float
        Sets the accept/reject boundary at mean + k * std of the genuine
        training scores. Stored in the profile; can be tuned per deployment.

    Returns
    -------
    dict
        JSON-serialisable profile: mean vector, MAD vector, decision threshold,
        feature order and sample count. Store this as-is in SQLite.
    """
    X = np.asarray(samples, dtype=float)
    if X.ndim != 2 or X.shape[0] < 2:
        raise ValueError("enroll needs at least 2 samples as a 2-D array")

    detector = ScaledManhattanDetector().fit(X)

    # Calibrate a per-user threshold using leave-one-out. Scoring a training
    # sample against a model built from ITSELF is over-optimistic (the sample
    # sits almost on the mean), so instead we hold each sample out, fit on the
    # rest, and score the held-out one. These leave-one-out scores approximate
    # how genuine but unseen samples behave, giving a threshold that admits the
    # real user without being fooled by the overfit self-distances.
    n = X.shape[0]
    loo_scores = np.empty(n)
    for i in range(n):
        rest = np.delete(X, i, axis=0)
        loo_scores[i] = ScaledManhattanDetector().fit(rest).score(X[i])[0]
    threshold = float(loo_scores.mean() + threshold_k * loo_scores.std())

    return {
        "detector": ScaledManhattanDetector.name,
        "mean": detector.mean_.tolist(),
        "mad": detector.mad_.tolist(),
        "threshold": threshold,
        "threshold_k": float(threshold_k),
        "feature_order": list(feature_order) if feature_order is not None else None,
        "n_samples": int(X.shape[0]),
    }


def verify(profile, sample, feature_order=None):
    """Score a single login attempt against a stored profile.

    Parameters
    ----------
    profile : dict
        A profile previously returned by `enroll` (as read back from SQLite).
    sample : array-like, shape (n_features,)
        The timing vector for this login attempt.
    feature_order : list[str] or None
        If both this and the profile's feature order are given, they must match;
        otherwise a ValueError is raised (guards against feature-order drift
        between enrollment and verification).

    Returns
    -------
    dict
        {score, threshold, accepted} where `accepted` is True when the sample is
        close enough to the enrolled profile to be treated as the genuine user.
    """
    stored_order = profile.get("feature_order")
    if stored_order is not None and feature_order is not None:
        if list(stored_order) != list(feature_order):
            raise ValueError("feature_order mismatch between profile and sample")

    mean = np.asarray(profile["mean"], dtype=float)
    mad = np.asarray(profile["mad"], dtype=float)
    x = np.asarray(sample, dtype=float).ravel()
    if x.shape[0] != mean.shape[0]:
        raise ValueError(
            f"sample has {x.shape[0]} features, profile expects {mean.shape[0]}"
        )

    score = float((np.abs(x - mean) / mad).sum())
    threshold = float(profile["threshold"])
    return {"score": score, "threshold": threshold, "accepted": score <= threshold}
