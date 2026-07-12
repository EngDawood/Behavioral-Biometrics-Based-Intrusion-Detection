# Keystroke Dynamics — Live Demo (Flask)

Browser demo for the **Behavioral Biometrics-Based Intrusion Detection** project.
A user enrolls a typing profile by typing a fixed phrase several times; on
verification, the server decides whether a new typing sample matches the enrolled
rhythm — accepting the genuine user and rejecting intruders who know the password
but type differently.

## Scope

This is the **live demo only**. It collects keystroke timings in the browser
(millisecond precision) and stores them in SQLite. It is deliberately kept
separate from the **offline CMU benchmark** (`train.py` / the evaluation
notebook), which uses microsecond-precision hardware-clock data. The two are
never mixed — but both score samples with the **same** `keystroke_model` module
(Scaled Manhattan distance), so the demo and the benchmark tell one coherent
story.

Rigorous accuracy figures (EER, ROC, confusion matrix) come from the offline
benchmark. This demo is a demonstration of the mechanism in real time, not a
source of benchmark numbers: its threshold is calibrated from genuine samples
only (no impostor data exists at enrollment), so it cannot hit the benchmark's
EER-optimal operating point.

## Run

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

The database (`demo.db`) and a seed admin are created automatically on first run.

Admin dashboard: <http://127.0.0.1:5000/admin> — default login `admin` / `admin123`
(change `ADMIN_PASSWORD` in `app.py`).

## How it works

1. **Enroll** — the browser captures keydown/keyup timestamps as you type the
   phrase, builds Hold / Down-Down / Up-Down features (the same feature families
   as the CMU benchmark), and posts several samples. The backend stores the raw
   samples, then calls `keystroke_model.enroll` to build and store a profile.
2. **Verify** — the browser posts one sample. The backend loads the profile,
   calls `keystroke_model.verify`, logs the attempt, and returns accept/reject.
3. **Admin** — every attempt is logged and shown on the dashboard.

The backend owns the decision; the browser never scores anything.

## Files

| File | Role |
|------|------|
| `app.py` | Flask routes, SQLite access, admin auth |
| `keystroke_model.py` | Shared matcher (enroll/verify + detectors) — identical to the benchmark's |
| `schema.sql` | The six tables: users, admins, enrollment_samples, profiles, attempts, sessions |
| `templates/index.html` | Enroll + verify UI with keystroke capture |
| `templates/admin.html` | Admin login + attempts dashboard |

## Tuning

- `REQUIRED_SAMPLES` (app.py) — enrollment repetitions. More samples give a more
  reliable profile; 10 is a good balance.
- `DEFAULT_THRESHOLD_K` (keystroke_model.py) — accept/reject boundary at
  `mean + k · std` of the leave-one-out genuine scores. Lower `k` rejects more
  intruders but risks locking out the real user; higher `k` is more permissive.
  Default 1.5.
