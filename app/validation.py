"""
app/validation.py
=================

The boundary guard. Phrase policy and timing-vector coercion, and nothing else.

Pure functions over plain Python values -- no Flask, no SQLite, no numpy. Every
one of them raises `ValueError`, which each route already turns into a 400.
"""

from __future__ import annotations

import math

from app.config import PHRASE_MAX, PHRASE_MIN


# --- phrase policy ----------------------------------------------------------
def expected_features(phrase: str) -> int:
    """Timing-vector length for a phrase: H, DD, UD per key, plus final Enter."""
    return 3 * (len(phrase) + 1) - 2


def validate_phrase(phrase: str) -> str | None:
    """Check a user-chosen phrase against the policy. Returns an error or None.

    Mirrors the client-side check in index.html; this copy is authoritative.
    Printable ASCII only: IME / non-Latin input produces key events that do not
    map 1:1 to characters, which breaks keystroke capture in the browser.
    """
    if len(phrase) < PHRASE_MIN:
        return f"phrase must be at least {PHRASE_MIN} characters"
    if len(phrase) > PHRASE_MAX:
        return f"phrase must be at most {PHRASE_MAX} characters"
    if not all("!" <= c <= "~" for c in phrase):
        return "phrase must use printable ASCII characters only, without spaces"
    if not any(c.isdigit() for c in phrase):
        return "phrase must include at least one number"
    if not any(not c.isalnum() for c in phrase):
        return "phrase must include at least one symbol"
    return None


# --- request payload validation --------------------------------------------
# Timing vectors arrive as JSON from a client we do not control, so they are
# checked here rather than trusted into numpy. Two failures made this necessary:
# a sample of the wrong SHAPE (a dict, say) raised TypeError deep inside numpy
# and escaped as a 500, and a sample of nulls became a vector of NaN that scored
# NaN, sailed through the comparisons as a "reject", and was serialised into the
# response as bare `NaN` -- which is not valid JSON.


def clean_sample(sample, n_features: int | None = None) -> list[float]:
    """Coerce one timing vector to a list of finite floats, or raise ValueError."""
    if not isinstance(sample, (list, tuple)):
        raise ValueError("sample must be a list of timing numbers")
    if n_features is not None and len(sample) != n_features:
        raise ValueError(f"each sample must carry {n_features} timing features")
    cleaned = []
    for value in sample:
        # bool is a subclass of int; True as a timing value is a bug, not a 1.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("timing features must be numbers")
        value = float(value)
        if not math.isfinite(value):
            raise ValueError("timing features must be finite numbers")
        cleaned.append(value)
    return cleaned


def clean_samples(samples, n_features: int, minimum: int) -> list[list[float]]:
    """Coerce a batch of enrollment vectors, or raise ValueError."""
    if not isinstance(samples, (list, tuple)) or len(samples) < minimum:
        raise ValueError(f"need at least {minimum} samples")
    return [clean_sample(s, n_features) for s in samples]


def clean_feature_order(feature_order):
    """Feature names must be a list of strings, or absent entirely."""
    if feature_order is None:
        return None
    if not isinstance(feature_order, (list, tuple)):
        raise ValueError("feature_order must be a list of feature names")
    return [str(name) for name in feature_order]
