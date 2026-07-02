# mini-siem

Lightweight SSH log parser and threat detector written in Python. Parses `auth.log` style files, detects brute force attempts, compromised accounts, and password spray attacks, and can optionally hand the detected events to an LLM for SOC-analyst-style triage.

## What it detects

- **Potential brute force** — IP with 5+ failed logins within a 10-minute window, no successful login
- **Compromise** — IP with 5+ failed logins within a 10-minute window followed by a successful login
- **Password spray** — single username targeted from 3+ distinct IPs (excluding IPs already flagged for brute force/compromise)

## Project structure

```
mini-siem/
├── app/
│   ├── main.py                    # entry point, CLI, output
│   ├── parser.py                  # log parsing, event extraction
│   ├── config.py                  # thresholds and constants
│   └── detections/
│       ├── brute_force.py         # brute force and compromise detection
│       └── spray.py               # password spray detection
├── triage/
│   ├── transform.py               # flattens detection results into a list of events (stdin -> data/events.json)
│   ├── triage.py                  # sends each event to an OpenAI model for severity/summary/action triage
│   └── data/
│       ├── events.json            # output of transform.py
│       └── results.json           # output of triage.py
├── assets/
│   ├── event_types_assets.py      # log line -> event type patterns
│   └── get_user_assets.py         # username extraction patterns
└── logs/
    └── traning_logs_auth.log      # sample training log
```

## Requirements

Python 3.9+

Install dependencies:

```bash
pip install -r Requirements.txt
```

The `triage/` step calls the OpenAI API, so you'll also need an API key. Create a `.env` file in the project root:

```
OPENAI_API_KEY=your-api-key
OPENAI_MODEL=gpt-4o-mini
```

## Usage

### Detection

```bash
# default output (print), default log
python app/main.py

# specify a log file
python app/main.py --log /var/log/auth.log

# JSON output
python app/main.py --output json

# CSV output
python app/main.py --output csv

# save to file
python app/main.py --output json > report.json
python app/main.py --output csv > report.csv
```

### LLM triage (optional)

Flatten the detection results into individual events, then send them to an LLM for severity assessment, reasoning, and a recommended action:

```bash
python app/main.py --output json | python triage/transform.py
python triage/triage.py
```

This writes `triage/data/events.json` (flattened events) and `triage/data/results.json` (one `{summary, severity, reasoning, recommended_action}` object per event).

## Output example

```
==================================================
Failed logins   : 21
Invalid user    : 19
Accepted logins : 3
Unique IPs      : 17
Unique users    : 13

--- Potential Brute Force from IPs ---
  203.0.113.45 | count: 9 | severity: MED

--- Successful Brute Force from IPs (COMPROMISE) ---
  198.51.100.23 | count: 8 | severity: CRITICAL

--- Password Spray on Users ---
  admin | unique source IPs: 8 | severity: HIGH
```

## Configuration

Thresholds are in `app/config.py`:

```python
SPRAY_THRESHOLD = 3        # minimum unique source IPs to flag spray
WINDOW_MINUTES = 10        # time window for brute force detection
BRUTE_FORCE_THRESHOLD = 5  # minimum failed logins within window
```
