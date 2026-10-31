# MITRE ATT&CK Mapping

Every Drishti Nexus rule carries exactly one MITRE ATT&CK (Enterprise) technique. The tag is set when the alert is created and appears on every alert:

| Where | Fields |
|---|---|
| JSON report (`scan -output x.json`) | `mitre_technique_id`, `mitre_technique_name`, `mitre_tactic` |
| CSV export | `MITRETechniqueID`, `MITRETechniqueName`, `MITRETactic` columns |
| SQLite backend | stored inside each alert's JSON body |
| `analyze` / `tail` console output | `[T1110.001: Credential Access]` suffix |

The table lives in [`internal/detection/attack.go`](../internal/detection/attack.go). `TestATTACK_DocumentListsEveryRule` fails if the table below and the code disagree.

## Mapping

| Rule | Technique | Name | Tactic |
|---|---|---|---|
| Authentication Brute Force | T1110.001 | Brute Force: Password Guessing | Credential Access |
| Excessive Authentication Failures | T1110 | Brute Force | Credential Access |
| Privilege Escalation Indicator | T1548 | Abuse Elevation Control Mechanism | Privilege Escalation |
| Suspicious Command Execution | T1059 | Command and Scripting Interpreter | Execution |
| Injection Pattern Detected | T1190 | Exploit Public-Facing Application | Initial Access |
| Time-based Anomaly | T1078 | Valid Accounts | Initial Access |
| Lateral Movement Candidate | T1021 | Remote Services | Lateral Movement |

## Method

A technique is tagged only when the rule's logic is a reasonable proxy for it, not when the activity *could* be an instance of it. When a rule cannot tell sub-techniques apart, it gets the parent technique. Each rule gets one tactic: the one its evidence supports. ATT&CK lists some techniques, such as T1078, under several tactics.

## Rationale per rule

**Authentication Brute Force → T1110.001.** The rule fires when several failed passwords from one source IP against one host are followed by a success. That is password guessing against a known account. It is not spraying (T1110.003), which spreads one password over many accounts, and it is not stuffing (T1110.004), which needs breached credentials.

**Excessive Authentication Failures → T1110.** The rule only counts failures per host and IP. It doesn't look at whether the usernames vary, so it can't tell guessing, spraying and stuffing apart. It gets the parent technique.

**Privilege Escalation Indicator → T1548.** It fires on *failed or denied* `sudo`, `su`, `runas`, `pkexec`, `doas` and UAC attempts. These are the mechanisms covered by T1548 (T1548.002 UAC, T1548.003 sudo), so it gets the parent technique. The plan also suggested **T1068 (Exploitation for Privilege Escalation)**, but that was **deliberately not mapped**: nothing in the rule looks for exploitation, and tagging it would overstate what was detected.

**Suspicious Command Execution → T1059.** The rule matches interpreter and command-line indicators: `cmd.exe`, `powershell`, `bash -i`, `-encodedcommand`. Some indicators point to more specific techniques: `mimikatz` (T1003 OS Credential Dumping), `psexec` (T1569.002 Service Execution), `wget`/`curl` (T1105 Ingress Tool Transfer). Tags are per rule, not per indicator, so the alert carries T1059. The matched indicator is in `details.indicator`, so an analyst can refine the tag.

**Injection Pattern Detected → T1190.** SQL injection, command injection and path traversal in web/application requests are exploitation attempts against a public-facing application.

**Time-based Anomaly → T1078 (contextual).** Authentication or error activity outside configured business hours is not evidence of a technique by itself. T1078 is the closest fit: legitimate credentials used at an unusual time. Treat this tag as **context for other alerts in the same incident**, not as a finding on its own.

**Lateral Movement Candidate → T1021.** It fires when an account that was brute-forced successfully on host A then logs in on host B within the rule's window. Logging into another host's remote service with gained credentials is T1021. The parent technique is used because the rule doesn't know whether the service was SSH (T1021.004), RDP (T1021.001) or SMB (T1021.002).

## Not mapped

- **rpc.statd format-string exploitation** (seen in loghub-linux, T1203/T1190). There is no rule for it yet; it is a known detection gap in [BASELINE.md](../BASELINE.md).
- **Sigma rules (Phase 2.4)** carry their own `attack.*` tags. Those will be read from each rule's `tags:` field, not from this table.
