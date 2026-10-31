# Multi-Host Correlation Demo (Phase 2.2)

This demo shows one incident spanning two hosts: an account is brute-forced on `web01`, and the stolen password is then used to log in on `db01`. Drishti Nexus reports it as **one incident with three linked alerts**, not as unrelated alerts in two files.

**Dataset substitution (agreed 2026-10-31).** The plan asked for this demo on Splunk BOTS. BOTS ships as Splunk indexes, not raw logs, so it is deferred. The public datasets we do ingest can't show this pattern either: LogHub SSH and Linux are single-host, and Mordor PsExec has Windows lateral movement but no brute force before it. The demo therefore uses a small committed fixture, [`testdata/fixtures/multihost/`](../../testdata/fixtures/multihost/). Its alert counts are pinned by `TestIntegration_MultiHostLateralMovement`.

## Run it

```bash
drishti analyze testdata/fixtures/multihost
drishti scan -output demo.json testdata/fixtures/multihost   # JSON + CSV with the linked alerts
```

A directory is expanded to the files beneath it. Files are merged in **event-time order**, so the result doesn't depend on file order: `db01/` sorts first, yet its 10:21 login is correctly read *after* web01's 10:14 compromise. Both files are named `auth.log`, so each one's evidence label is its path, and every cited line stays unambiguous.

## Incident timeline: `INC-00001`

| Time (UTC) | Host | Evidence | Event | Alert |
|---|---|---|---|---|
| 10:14:01–10:14:11 | web01 | `web01/auth.log:3-8` | 6 × `Failed password for deploy from 203.0.113.50` | **ALERT-000001** Excessive Authentication Failures · medium · T1110 |
| 10:14:14 | web01 | `web01/auth.log:9` | `Accepted password for deploy from 203.0.113.50` | **ALERT-000002** Authentication Brute Force · high · T1110.001 (supersedes ALERT-000001) |
| 10:21:40 | db01 | `db01/auth.log:3` | `Accepted password for deploy from 10.0.0.11` (web01's address) | **ALERT-000003** Lateral Movement Candidate · critical · T1021 |

Links recorded on the alerts (`related_alerts`): 000001 ↔ 000002 ↔ 000003, all in `INC-00001`. The lateral alert cites the compromising login on web01 *and* the login on db01. Its `first_seen` is the compromise (10:14:14) and its `last_seen` is the lateral login (10:21:40).

## Actual output (excerpt)

```
   SECURITY ALERTS (3 in 1 incidents)

[2025-03-10 10:14:14Z] Lateral Movement Candidate  (ALERT-000003, INC-00001, x1) [T1021: Lateral Movement]
  Severity: CRITICAL
  Details: Lateral movement candidate: "deploy" was brute-forced on web01, then logged in on db01 7m26s later
  Evidence: testdata/fixtures/multihost/web01/auth.log:9, testdata/fixtures/multihost/db01/auth.log:3

[2025-03-10 10:14:01Z] Authentication Brute Force  (ALERT-000002, INC-00001, x1) [T1110.001: Credential Access]
  Severity: HIGH
  Details: Brute force: 6 failed attempts followed by a successful login from 203.0.113.50 on web01 within 5m0s

✓ Evidence unchanged after analysis: testdata\fixtures\multihost\db01\auth.log
✓ Evidence unchanged after analysis: testdata\fixtures\multihost\web01\auth.log
```

## What it does not catch (honest gaps)

- **Post-compromise activity is not linked.** At 10:22:03 on db01, `deploy` runs `sudo pg_dumpall`, a full database dump. Successful sudo is deliberately not alerted (Phase 1 false-positive fix), and nothing yet ties "first sudo by a just-compromised account" to the incident. This is a candidate for Phase 2.5 ("user who doesn't normally use sudo").
- **Only one cross-host pattern.** Brute force on A → login on B. Pass-the-hash, Windows 4624 logon-type correlation and RDP chains are not modelled.
- **No brute force, no link.** An attacker who already has the password, such as a phished account, triggers nothing cross-host.
- **The host comes from the log line.** Formats without a host name (Apache access logs, some JSON) can't take part.
