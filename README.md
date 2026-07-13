# Keystroke Dynamics — Intrusion Detection Service (Flask)

Browser-based **Behavioral Biometrics-Based Intrusion Detection** system. A user
enrolls a typing profile by typing a fixed phrase several times; on each login the
server decides whether the new typing rhythm matches — and, beyond a single
decision, watches for *runs* of failed attempts and treats them as intrusions.

## What it does

- **Enroll → verify** — the browser captures keystroke timings (Hold / Down-Down /
  Up-Down), the backend builds and stores a per-user profile, and scores each
  login attempt with the Scaled Manhattan detector.
- **Three-tier decision** — accept / suspicious / reject, based on how far the
  score sits above the user's threshold.
- **Intrusion detection + lockout** — a run of consecutive failed verifications
  (default 3) is flagged as an intrusion and temporarily locks the account
  (default 5 min). Locked logins are refused before scoring.
- **Admin monitoring** — a dashboard with live statistics, an intrusion-alert
  feed, currently-locked accounts, the recent attempt log, and a per-user
  drill-down with unlock / delete controls.
- **Rate limiting** — per-IP cap on verification requests.

All intrusion and lock state is *derived from the `attempts` table* — no extra
tables or columns — so the six-table ERD from Chapter 4 is unchanged.

## Scope

This is the **live system**. It collects browser keystroke timings (millisecond
precision) in SQLite and is kept separate from the **offline CMU benchmark**
(`train.py` / the evaluation notebook), which uses microsecond hardware-clock data.
Both score samples with the SAME `keystroke_model` module (Scaled Manhattan), so
the two modes stay aligned while their methodologies stay separate. Rigorous
accuracy figures (EER, ROC, DET, confusion matrix) come from the benchmark; the
live system's threshold is calibrated from genuine samples only, so it cannot reach
the benchmark's EER-optimal operating point.

## Run

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

The database (`demo.db`) and a seed admin are created automatically on first run.

Optional — to show a populated dashboard from the start, seed synthetic data first
(this resets `demo.db`):

```bash
python seed_demo.py
```

Admin dashboard: <http://127.0.0.1:5000/admin> — default login `admin` / `admin123`
(change `ADMIN_PASSWORD` in `app.py`).

## Files

| File | Role |
|------|------|
| `app.py` | Flask routes, decision + intrusion logic, SQLite access, admin auth |
| `keystroke_model.py` | Shared matcher (enroll/verify + detectors) — identical to the benchmark's |
| `schema.sql` | The six tables: users, admins, enrollment_samples, profiles, attempts, sessions |
| `templates/index.html` | Enroll + verify UI with keystroke capture |
| `templates/admin.html` | Admin login + monitoring dashboard |
| `templates/admin_user.html` | Per-user drill-down (history, unlock, delete) |
| `seed_demo.py` | Optional: fill the DB with synthetic users + attempts |

## Tuning (top of `app.py`)

| Setting | Meaning |
|---------|---------|
| `REQUIRED_SAMPLES` | Enrollment repetitions (default 10). |
| `SUSPICIOUS_MARGIN` | Score band for "suspicious": `(threshold, threshold × margin]`. |
| `FAIL_LOCK_STREAK` | Consecutive failures that trigger an intrusion + lock (default 3). |
| `LOCK_COOLDOWN_MIN` | Lock duration in minutes (default 5). |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | Per-IP verify cap and window. |
| `DEFAULT_THRESHOLD_K` (in `keystroke_model.py`) | Accept boundary at `mean + k · std` of leave-one-out genuine scores. |

## How the decision flows

1. **Rate check** — too many verifies from one IP → `429`.
2. **Lock check** — account in a failed-streak cooldown → `423`, refused before scoring.
3. **Score** — the shared matcher returns a distance; the band (accept / suspicious /
   reject) follows from the margin over the threshold.
4. **Log + detect** — the attempt is written to `attempts`; if it completes a
   failure streak, the response flags an intrusion and the account locks.

The backend owns every decision; the browser only captures timings.
