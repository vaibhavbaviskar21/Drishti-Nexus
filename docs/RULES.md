# Drishti Nexus - Detection Rules

Drishti Nexus has 6 built-in rules. All of them are:

- **Deterministic and explainable.** Every alert names the indicator or threshold that fired and cites the evidence lines (`file:line`).
- **Event-time based.** Windows are measured on the log's own timestamps, never the wall clock, so historical files behave the same as live ones.
- **Configurable** in `configs/config.yaml`. Rule `name`s must match the names below exactly; unknown names are reported as warnings. The effective settings of every rule are recorded in the audit log of each session.
- **Offline.** No external lookups.

---

## How alerts are built (all rules)

| Concept | Behaviour |
|---|---|
| **Correlation key** | `host=<source>` plus `ip=<remote IP>` when the parser extracted one. Authentication rules count per host+IP, so failures from one IP never combine with a success from another. |
| **Aggregation** | If a rule fires again for the same key within its `time_window` (measured from the last occurrence), the existing alert's `count` and `last_seen` are updated. No new alert is created. One attack burst gives one alert. |
| **Incidents** | Alerts sharing a correlation key and no more than `incident_gap` apart (default 30m) get the same `incident_id` (`INC-00001`). |
| **Linking** | When Brute Force fires for a host+IP that already has an open Excessive Failures alert, the two are cross-linked in `related_alerts`. The lower-fidelity one is marked `details.superseded_by`, and both share an incident. |
| **Evidence** | `related_logs` lists the contributing entry IDs (`auth.log:1234`), capped at 50. Threshold rules cite every failure in the window, not just the trigger. |
| **IDs** | `ALERT-000001`, `INC-00001`: sequential and deterministic, so the same input and config give the same IDs. |

### Authentication events
Rules 1 and 2 use structured fields extracted by the parser:

| Field | Meaning |
|---|---|
| `auth_result` | `failure`, `success`, or `info` |
| `auth_event` | Kind of event, e.g. `password_failed`, `invalid_user`, `pam_failure`, `accepted`, `windows_logon_failed` |
| `auth_count`, `user`, `src_ip` | Attempts represented by the line, the account, and the remote address |

Recognised sources:
- sshd: `Failed …`, `Accepted …`, `Invalid user …`, and `message repeated N times: [ Failed … ]` (counts N).
- PAM `authentication failure` and `check pass; user unknown`.
- logind/ftpd `Authentication failed`.
- Windows 4624, 4625 and 4771.

Lines that are auth-related but are *not* attempts are tagged `info` and never counted: `PAM 5 more authentication failures`, `Disconnecting: Too many authentication failures`, `session opened`.

**One attempt counts once.** A single sshd login attempt usually writes 2–3 lines (`Invalid user`, `pam_unix … authentication failure`, `Failed password`), all with the same PID within a few seconds. They are collapsed into one attempt. A repeat of the *same* line kind from the same PID is a new attempt.

Formats without an extractor fall back to keyword matching ("failed/invalid/incorrect" + "auth/login/password/user"). Structured events that are not authentication events (e.g. Windows 4103 script blocks) are never keyword-matched.

---

## 1. Authentication Brute Force
**Severity** high · **config** `threshold: 3`, `time_window: 5m`

Fires on a **successful** login when the same host+IP had **≥ threshold failed attempts in the window ending at the success**. Both ends are inclusive: a failure exactly 5m00s before counts, one at 5m01s does not.

```
Failed password for admin from 192.168.1.100 port 1 ssh2
Failed password for admin from 192.168.1.100 port 2 ssh2
Failed password for admin from 192.168.1.100 port 3 ssh2
Accepted password for admin from 192.168.1.100 port 4 ssh2   ← ALERT, cites all 4 lines
```

Does **not** fire for: 2 failures then a success; failures from different IPs; failures logged *after* the success.

## 2. Excessive Authentication Failures
**Severity** medium · **config** `threshold: 5`, `time_window: 10m`

Fires when one host+IP reaches **≥ threshold failed attempts within the window** (inclusive). The alert's `timestamp` is the first failure in the window. Further failures in the same burst increase `count` on the same alert.

Does **not** fire for: 4 failures in 10 minutes; 2 failures in 6 minutes; 5 failures spread over 10m01s.

## 3. Privilege Escalation Indicator
**Severity** medium, high when the entry is ERROR or worse · **config** `time_window: 10m` (aggregation)

Fires only for **failed or denied** escalation. The message must contain a denial word (`failed`, `failure`, `incorrect`, `not in sudoers`, `permission denied`, `not allowed`, `authentication failure`). It must also involve an escalation mechanism: the program is `sudo`, `su`, `runas`, `pkexec` or `doas`, or the message contains one of the whole words `sudo`, `runas`, `pkexec`, `elevate`, `user account control`, `uac`, or `su -`.

```
bob : user NOT in sudoers ; TTY=pts/1 ; USER=root ; COMMAND=/bin/sh   ← ALERT
pam_unix(sudo:auth): authentication failure; logname=bob               ← ALERT
alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=apt update   ← no alert (normal sudo)
Failed password for root from 1.2.3.4                                   ← no alert (that is brute force)
```

## 4. Suspicious Command Execution
**Severity** high · **config** `time_window: 10m` (aggregation per host + indicator)

Indicators must start at a word boundary (`ncat ` does not match the username `concat`):

| Group | Indicators |
|---|---|
| Shells / interpreters | `cmd.exe`, `powershell`, `bash -i`, `sh -c`, `eval(`, `exec(`, `system(` |
| Encoded / obfuscated | `base64 -d`, `frombase64`, `-encodedcommand`, `-enc `, `char(`, `chr(` |
| Download / network | `wget `, `curl `, `invoke-webrequest`, `nc -e`, `netcat`, `ncat ` |
| Attack tooling | `mimikatz`, `psexec`, `wmic ` |

## 5. Injection Pattern Detected
**Severity** critical · **config** `time_window: 10m` (aggregation per host+IP + type)

| Type | Signatures |
|---|---|
| SQL Injection | `' OR '1'='1`, `' OR 1=1`, `'; DROP TABLE`, `UNION SELECT`, `UNION ALL SELECT`, `admin'--`, URL-encoded variants (case-insensitive) |
| Command Injection | `; ls`, `; cat `, `\| cat `, `& dir`, `; whoami`, `\| whoami`, `$(`, `; rm -rf`, a closed `` `…` `` pair (a lone backtick in prose does not count) |
| Path Traversal | `../`, `..\`, `%2E%2E%2F` |

## 6. Time-based Anomaly
**Severity** low · **config** `normal_hours` (`start`, `end`, `timezone`), `time_window: 1h` (aggregation per host)

Fires for authentication attempts or ERROR-or-worse entries outside normal hours. The start hour is inside, the end hour is outside: with 9–17, 09:00 is normal and 17:00 is not. Hours are evaluated in `normal_hours.timezone` (default UTC). It is skipped for an entry that already raised Brute Force or Excessive Failures. It is disabled when `start == end`.

> Known limitation: this is the noisiest rule on real data (see BASELINE.md). Per-host behavioural baselines are planned for Phase 2.1.

## 7. Lateral Movement Candidate
**Severity** critical · **config** `time_window: 30m` · **ATT&CK** T1021

Fires when an account that was the subject of an **Authentication Brute Force** alert on host A (failures, then a successful login) logs in successfully on a **different** host B within the window after that success. The boundary is inclusive, and a login on B *before* the compromise on A does not count. The alert joins the brute-force alert's incident and the two are cross-linked, so the timeline reads failures → brute force → lateral login.

It needs at least two hosts, so pass several files or a directory: `drishti scan logs/`. Files are merged in event-time order, so the file order on the command line does not matter. Entries without a host (`unknown`) never take part. Excessive Failures alone does not arm the rule: without a success there is no evidence the password was obtained.

---

## Configuration example

```yaml
rules:
  - name: "Excessive Authentication Failures"
    enabled: true
    severity: "medium"
    threshold: 3        # more sensitive (default 5)
    time_window: "5m"   # shorter window (default 10m)
  - name: "Time-based Anomaly"
    enabled: false      # e.g. 24/7 operations
normal_hours: {start: 9, end: 17, timezone: "Asia/Kolkata"}
incident_gap: "30m"
```

## Limitations
- Rules see log content only: no packet capture or flow data.
- Cross-host correlation covers one pattern (brute force on A → login on B). The host comes from the log line itself; files whose format carries no host name cannot take part.
- No behavioural baselines yet (Phase 2.1). No Sigma support yet (Phase 2.4). ATT&CK mapping: [ATTACK_MAPPING.md](ATTACK_MAPPING.md).
- Detection state survives restarts only with the SQLite backend (`tail -db`).
