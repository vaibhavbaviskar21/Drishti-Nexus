# Compliance Mapping

Plan item 3.3. Every alert carries an ATT&CK technique ([ATTACK_MAPPING.md](ATTACK_MAPPING.md)); each technique maps to the controls in PCI DSS 4.0.1, ISO/IEC 27001:2022 (Annex A) and the HIPAA Security Rule (45 CFR Part 164) that the alert is **evidence for**. The HTML and PDF reports list them under "Compliance references".

**What this is not.** A reference list for auditors and responders. It does not assess compliance, does not say a control failed, and does not cover any control fully. An alert under PCI 8.3.4 means "here is evidence about invalid authentication attempts", not "8.3.4 is violated".

Source of truth: `internal/detection/compliance.go`. Mapping is keyed by the parent technique, so Sigma sub-techniques (`T1003.001`, `T1569.002`) inherit it. `TestCompliance_EveryRuleTechniqueMapped` fails CI if a native rule or a shipped Sigma rule has a technique with no mapping, or a mapping that misses one of the three frameworks.

## Controls every scan supports

Running detection over the logs and keeping the hash-chained audit trail is itself evidence for automated log review, whatever fires:

| Framework | Control | Title |
|---|---|---|
| PCI DSS 4.0.1 | 10.4.1.1 | Automated mechanisms perform audit log reviews |
| ISO/IEC 27001:2022 | A.8.16 | Monitoring activities |
| HIPAA | 164.308(a)(1)(ii)(D) | Information system activity review |

## Per technique

| Technique (rules) | PCI DSS 4.0.1 | ISO/IEC 27001:2022 | HIPAA | Why |
|---|---|---|---|---|
| T1110 Brute Force (Brute Force, Excessive Failures) | 8.3.4, 10.2.1.4 | A.8.5, A.5.17 | 164.308(a)(5)(ii)(C), 164.312(d) | Repeated failed logins: evidence on lockout limits, logging of invalid access, and log-in monitoring. |
| T1078 Valid Accounts (Time Anomaly) | 8.2.6, 10.2.1.1 | A.5.18, A.8.5 | 164.308(a)(5)(ii)(C) | A valid login at an unusual hour points to stale or misused accounts and access-rights review. |
| T1548 Abuse Elevation Control (Privilege Escalation) | 7.2.2, 10.2.1.2 | A.8.2 | 164.312(a)(1) | sudo/su use, against least privilege and privileged-access controls. |
| T1059 Command and Scripting Interpreter (Suspicious Command) | 10.2.1.2 | A.8.18, A.8.7 | 164.308(a)(5)(ii)(B) | Download tools, netcat and similar commands, for malware protection and privileged-utility controls. |
| T1190 Exploit Public-Facing Application (Injection, Sigma) | 6.2.4, 6.4.2 | A.8.8, A.8.26 | 164.308(a)(1)(ii)(B) | SQLi/XSS/traversal attempts against web apps, for secure development and web-attack protection. |
| T1021 Remote Services (Lateral Movement Candidate) | 1.3.1, 8.4.2 | A.8.20, A.8.22 | 164.312(a)(1) | A credential used across hosts after a brute force, for segmentation and MFA on internal access. |
| T1003 OS Credential Dumping (Sigma) | 8.3.2, 5.2.1 | A.5.17, A.8.7 | 164.312(d) | LSASS access (Mimikatz), for protection of stored authentication factors and anti-malware. |
| T1569 System Services (Sigma, PsExec) | 2.2.4, 10.2.1.2 | A.8.2, A.8.18 | 164.312(a)(1) | Remote service creation, for limiting enabled services and privileged-tool use. |

HIPAA citations are to the Security Rule as in force; check them against any final rule changes before an audit.

## Adding a rule

Give the rule an ATT&CK technique first. If its parent technique is not in `techniqueControls`, add a row covering all three frameworks and a line in the table above; the test tells you if you forget.
