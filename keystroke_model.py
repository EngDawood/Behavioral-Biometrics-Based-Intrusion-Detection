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
    "tempo_factor",
    "DEFAULT_THRESHOLD_K",
    "TEMPO_MIN",
    "TEMPO_MAX",
]

# How many standard deviations above the mean genuine (training) score the
# accept/reject boundary sits, when a profile does not specify its own threshold.
# Larger  -> more permissive (fewer legitimate users locked out, more intruders let in).
# This is a starting heuristic for the live demo; it can be tuned per deployment.
DEFAULT_THRESHOLD_K = 1.5

# Bounds on the tempo factor (see `tempo_factor`). A genuine user who is tired,
# unwell or typing one-handed runs slower more or less uniformly, and that is
# worth forgiving. An arbitrarily large factor is not: without a clamp, the
# normalisation would rescale ANY sample onto the profile's tempo, so an impostor
# typing at half or triple speed would be handed the correction for free. These
# bounds say "up to twice as slow, or twice as fast, is a bad day; beyond that is
# a different person".
TEMPO_MIN = 0.5
TEMPO_MAX = 2.0


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

    Raises
    ------
    ValueError
        If fewer than 2 samples are supplied, or if the samples show no variation
        at all (identical samples yield a threshold of 0, which would reject the
        genuine user forever). The backend turns this into an HTTP 400.
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

    # Every leave-one-out score being 0 means the samples carry no variation at
    # all -- typically a replayed or scripted capture. Such a profile would get a
    # threshold of 0, and a threshold of 0 can only ever accept a byte-identical
    # replay: the genuine user, who is never that precise, would be locked out of
    # their own account forever. Refuse the enrollment instead of storing it.
    if not loo_scores.any():
        raise ValueError(
            "enrollment samples are identical -- type the phrase naturally each "
            "time so the profile has some variation to learn from"
        )

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


def tempo_factor(sample, mean, lo=TEMPO_MIN, hi=TEMPO_MAX):
    """How much slower (>1) or faster (<1) this sample runs than the profile.

    The *median* per-feature ratio, not the mean: a median ignores a handful of
    wild features (one fumbled key, one pause to think) and reports the pace of
    the sample as a whole. The result is clamped to [lo, hi] -- see TEMPO_MIN.

    Returns 1.0 when the profile carries no usable (strictly positive) mean, so
    the caller can always divide by the result.
    """
    mean = np.asarray(mean, dtype=float)
    x = np.asarray(sample, dtype=float).ravel()
    usable = mean > 0
    if not usable.any():
        return 1.0
    return float(np.clip(np.median(x[usable] / mean[usable]), lo, hi))


def verify(profile, sample, feature_order=None, tempo_normalise=False):
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
    tempo_normalise : bool
        Divide the sample by its own tempo factor before scoring, so the decision
        is made on the *shape* of the rhythm rather than its speed. This is the
        anomaly-tolerance knob: a genuine user who is unwell, injured or simply
        tired types the same pattern more slowly, and without this every feature
        drifts in the same direction at once and the sum crosses the threshold.
        An impostor who types at the right speed but the wrong pattern is
        unaffected -- the ratios between features are what identifies a person,
        and normalising deliberately preserves them.

        It is not free: an impostor whose rhythm happens to be the right SHAPE at
        the wrong speed is helped too, which is why `tempo_factor` clamps how far
        the correction can reach. Off by default; the backend turns it on.

    Returns
    -------
    dict
        {score, raw_score, tempo, threshold, accepted, deviations}. `score` is
        what the decision uses; `raw_score` is the same sum before any tempo
        correction, and `tempo` is the factor that was divided out (1.0 = the
        enrolled pace), so the caller can report *why* an attempt was forgiven.
        Both are equal and tempo is 1.0 when `tempo_normalise` is False.
        `deviations` is the per-feature |x - mean| / MAD vector `score` sums over
        -- it says *which* timings drifted, not just by how much overall.
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

    raw_score = float((np.abs(x - mean) / mad).sum())

    tempo = 1.0
    if tempo_normalise:
        tempo = tempo_factor(x, mean)

    # Scored on the tempo-corrected vector, so `deviations` explains the decision
    # that was actually made rather than one the server did not use.
    deviations = np.abs(x / tempo - mean) / mad
    score = float(deviations.sum())
    threshold = float(profile["threshold"])
    return {
        "score": score,
        "raw_score": raw_score,
        "tempo": tempo,
        "threshold": threshold,
        "accepted": score <= threshold,
        "deviations": deviations.tolist(),
    }
