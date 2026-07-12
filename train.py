"""
train.py
========

Offline benchmark evaluation for the Behavioral Biometrics-Based Intrusion
Detection project.

Reproduces the protocol of Killourhy & Maxion (2009) on the CMU Keystroke
Dynamics Benchmark dataset and reports the Equal Error Rate (EER) of each
detector, with the primary detector (Scaled Manhattan) first.

This script owns the *evaluation protocol* (how subjects are split into train /
genuine / impostor sets). The *matching logic* lives in keystroke_model.py and is
imported here, so the benchmark and the live Flask demo score samples with
exactly the same code.

    Scope: this is the OFFLINE benchmark only. It uses the CMU pre-extracted
    timing features (hardware clock, microsecond precision). It is reported in a
    separate section from the live browser demo, whose millisecond-precision
    timers are not directly comparable.

Usage
-----
    python train.py                        # auto-loads or downloads the dataset
    python train.py --data path/to.csv     # use a specific local file
    python train.py --save results.csv     # also write per-subject EERs

Expected result: Scaled Manhattan ~9.6% mean EER, plain Manhattan ~15.3%,
Euclidean ~17%.
"""

from __future__ import annotations

import argparse
import os
import urllib.request

import numpy as np
import pandas as pd

from keystroke_model import DETECTORS

META = ["subject", "sessionIndex", "rep"]
CMU_URL = "https://www.cs.cmu.edu/~keystroke/DSL-StrongPasswordData.txt"
LOCAL_CANDIDATES = [
    "DSL-StrongPasswordData.txt",
    "DSLStrongPasswordData.csv",
    "DSL-StrongPasswordData.csv",
]


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
def load_dataset(path=None):
    """Load the CMU dataset from `path`, a known local name, or the CMU site."""
    if path is None:
        path = next((p for p in LOCAL_CANDIDATES if os.path.exists(p)), None)
    if path is None:
        path = "DSL-StrongPasswordData.txt"
        print(f"No local dataset found -- downloading from {CMU_URL}")
        urllib.request.urlretrieve(CMU_URL, path)

    sep = "," if path.endswith(".csv") else r"\s+"
    df = pd.read_csv(path, sep=sep, engine="python")
    print(f"Loaded {path}: {df.shape[0]} rows, {df.shape[1]} columns")
    return df


def get_splits(df, features, subject):
    """Killourhy & Maxion (2009) splits for one genuine subject.

    train    : first 200 reps of the subject (sessions 1-4)
    genuine  : last 200 reps of the subject (sessions 5-8)
    impostor : first 5 reps of every other subject
    """
    train = df[(df.subject == subject) & (df.sessionIndex <= 4)][features].values
    genuine = df[(df.subject == subject) & (df.sessionIndex > 4)][features].values
    impostor = df[
        (df.subject != subject) & (df.sessionIndex == 1) & (df.rep <= 5)
    ][features].values
    return train, genuine, impostor


# ---------------------------------------------------------------------------
# Metric
# ---------------------------------------------------------------------------
def equal_error_rate(user_scores, impostor_scores):
    """EER: threshold where miss rate (genuine rejected) == false-alarm rate."""
    P = len(user_scores)
    N = len(impostor_scores)
    thresholds = np.unique(np.concatenate([user_scores, impostor_scores]))

    miss = np.array([1.0 - (user_scores <= t).sum() / P for t in thresholds])
    fa = np.array([(impostor_scores <= t).sum() / N for t in thresholds])

    idx = np.argmin(np.abs(miss - fa))
    return (miss[idx] + fa[idx]) / 2.0


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def evaluate_detector(df, features, subjects, detector_cls):
    """Mean/std EER for one detector across all subjects."""
    eers = []
    for subject in subjects:
        train, genuine, impostor = get_splits(df, features, subject)
        detector = detector_cls().fit(train)
        eer = equal_error_rate(
            detector.score(genuine), detector.score(impostor)
        )
        eers.append(eer)
    return np.array(eers)


def run(data_path=None, save_path=None):
    df = load_dataset(data_path)
    features = [c for c in df.columns if c not in META]
    subjects = sorted(df["subject"].unique())
    print(f"Subjects: {len(subjects)} | timing features: {len(features)}\n")

    per_subject = {}
    summary_rows = []
    for name, detector_cls in DETECTORS.items():
        eers = evaluate_detector(df, features, subjects, detector_cls)
        per_subject[name] = eers
        summary_rows.append(
            {
                "Detector": name,
                "Mean EER (%)": round(eers.mean() * 100, 2),
                "Std Dev (%)": round(eers.std() * 100, 2),
            }
        )

    summary = pd.DataFrame(summary_rows)
    print("Benchmark results (Killourhy & Maxion 2009 protocol):\n")
    print(summary.to_string(index=False))
    print("\nPrimary detector: Scaled Manhattan "
          f"({summary.iloc[0]['Mean EER (%)']}% mean EER)")

    if save_path:
        out = pd.DataFrame(per_subject, index=subjects)
        out.index.name = "subject"
        out.to_csv(save_path)
        print(f"\nPer-subject EERs written to {save_path}")

    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default=None, help="path to the CMU dataset file")
    parser.add_argument("--save", default=None, help="write per-subject EERs to CSV")
    args = parser.parse_args()
    run(data_path=args.data, save_path=args.save)


if __name__ == "__main__":
    main()
