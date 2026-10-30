# Foren-Sight

A lightweight digital-forensics helper that turns scattered logs into one chronological timeline and flags
potentially suspicious sequences of events.

ForenSight is **not** a replacement for full forensic platforms such as Autopsy, The Sleuth Kit or Plaso. It
focuses on one job: multi-source log normalization, event correlation and suspicious-activity detection.

> Intended for authorized forensic analysis and testing. Findings are indicators for investigators, not proof
> of wrongdoing.

## The problem

Investigators often have to reconstruct an incident from large volumes of log data produced by different
systems. Each source records time, users and addresses in its own way, so normalizing, organizing and
correlating events by hand is slow, and meaningful sequences of activity are easy to miss.

## What it does

1. Reads **CSV**, **JSON** and Windows **EVTX** files.
2. Validates the file: *Recognized*, *Partially recognized* or *Unrecognized*.
3. Normalizes every event into one format: Timestamp, Source, Event Type, User, Source IP, Target, Details.
4. Builds a chronological forensic timeline (all times in UTC).
5. Runs three rule-based detections and explains each finding.
6. Shows the results on the website (a PDF investigation report is planned).

Nothing is stored: uploads are analyzed in memory and discarded.

## Install and run

Requires Python 3.10 or newer.

```
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Input formats

**CSV / JSON** use these exact column names / keys (case and spacing are ignored, synonyms are not guessed):

| Field | Meaning | Example |
|---|---|---|
| Timestamp | when it happened | `2026-03-14 10:02:10` |
| System | machine or log source | `web-server-01` |
| Activity | what happened | `FAILED_LOGIN` |
| User | account involved | `jdoe` |
| Ip Address | where it came from | `192.168.1.25` |
| Target | file, service or object affected | `SSH` |
| Details | extra context | `Invalid password` |

Activity values the rules understand: `FAILED_LOGIN`, `SUCCESSFUL_LOGIN`, `SPECIAL_PRIVILEGES_ASSIGNED`,
`OBJECT_ACCESS`, `PROCESS_CREATED`. Other values are kept on the timeline but not used by the rules.

JSON may be a list of objects, a single object, or JSON Lines (one event per line, file extension `.jsonl`).

**Windows EVTX** (Security log only):

| Event ID | Meaning | Activity |
|---:|---|---|
| 4624 | Successful logon | `SUCCESSFUL_LOGIN` |
| 4625 | Failed logon | `FAILED_LOGIN` |
| 4672 | Special privileges assigned to new logon | `SPECIAL_PRIVILEGES_ASSIGNED` |
| 4663 | Object access | `OBJECT_ACCESS` |
| 4688 | New process created | `PROCESS_CREATED` |

Other Event IDs are ignored and counted. Event 4663 needs *object access auditing* and 4688 needs *process
creation auditing* to be enabled in Windows, otherwise they are never written to the log.

**Time zones:** timestamps with a zone (`Z`, `+01:00`) or Unix epoch are converted to UTC. Timestamps with no
zone are treated as UTC and the user is told. Day/month formats such as `03/04/2026` are refused because they
are ambiguous.

## Detection rules

The thresholds live at the top of `processing/correlation.py`.

| Rule | Pattern | Window |
|---|---|---|
| Possible brute force | 3+ failed logins, then a successful login, same user (and same IP when both events have one) | 5 minutes |
| Possible privilege abuse | successful login, then special privileges assigned, then object access, same user (and same Windows session when known) | 10 minutes from the login |
| Suspicious data/object activity | 5+ object accesses on 3+ different objects by one user, with a process started by that user nearby | 2 minutes (+2 minute margin for the process) |

Severity is Low / Medium / High. For example, 3-4 failures before a login is Low (people mistype passwords),
10+ is High, and a privilege sequence that follows a brute-force pattern is High.

System and service accounts (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`, machine accounts
ending in `$`, `DWM-*`, `UMFD-*`) stay on the timeline but are not fed to the rules, to avoid constant false
alarms. The page tells the user how many events were left out.

## How it is built

```
Upload -> parse -> validate -> normalize -> timeline -> correlate -> display -> PDF
```

| Folder | Role |
|---|---|
| `app.py` | Flask app: connects the website to the pipeline |
| `parsers/` | read CSV, JSON, EVTX faithfully; report anything skipped or repaired |
| `processing/` | validator, normalizer, timeline, correlation engine |
| `reports/` | PDF report (planned) |
| `templates/`, `static/` | the website |
| `test_data/` | sample inputs and the automated tests |

## Testing

```
python -m unittest discover -s test_data -v
```

The tests give known input and check the exact expected output, including cases that must **not** raise an
alert (too few failures, different IP, wrong order, outside the time window).

To test real Windows logs, run `test_data/evtx/generate_test_events.ps1` in an administrator PowerShell on a
PC you own, or export your own log with `wevtutil epl Security security.evtx`. Keep such files private and
out of Git.

## Limitations

- Limited Windows Event ID coverage (five Security events).
- Limited CSV/JSON schema support (seven fixed columns).
- Rule-based, not machine-learning-based. False positives and false negatives are possible: the thresholds
  trade one against the other, and activity outside the rules is not detected.
- Distributed attacks (one user attacked from many IPs) are not linked, because the rule requires the same IP.
- Timestamps without a time zone are assumed to be UTC.
- No disk or image forensics and no malware analysis.
- No case management, database or permanent storage.
- Not a replacement for comprehensive forensic platforms.
