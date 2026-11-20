# Sigma Rules

Drishti Nexus evaluates [Sigma](https://sigmahq.io) rules directly against parsed log entries. There is no SIEM, no rule conversion and no network access, so a folder of rules on a USB stick is enough to update detection on an air-gapped host.

```bash
drishti scan -sigma rules/sigma logs/
```

The folder is searched recursively for `*.yml` / `*.yaml`. Each usable rule becomes a detection rule named `Sigma: <title>`, evaluated after the built-in rules:

- **Severity:** from `level` (informational → low).
- **ATT&CK:** from the `attack.tNNNN[.NNN]` and `attack.<tactic>` tags.
- **Aggregation:** like other content rules, one alert per host per 10 minutes, with repeats aggregated. Rules with a `| count()` condition alert once their count passes the threshold within their `timeframe`, and repeats merge over that timeframe.
- **Incidents:** matches join incidents like any other alert.
- **Audit trail:** every rule file's path and SHA-256 is recorded (`config.definitions`), and the rules appear in the session's rule list.

The built-in rules stay the fast path; Sigma is the extensible layer (plan 2.4).

## Supported subset

| Feature | Support |
|---|---|
| Field selections (map = AND, list of maps = OR, list of values = OR) | ✓ |
| Modifiers `contains`, `startswith`, `endswith`, `re`, `cidr`, `all`, `exists` | ✓ |
| Wildcards `*` `?`, escapes `\*` `\?` `\\` (other backslashes are literal, so Windows paths work) | ✓ |
| Case-insensitive matching (Sigma default; `re` is case-sensitive) | ✓ |
| `null` values (field absent or empty) | ✓ |
| Keyword lists (searched in the event message) | ✓ |
| Conditions: `and`, `or`, `not`, parentheses, `1 of` / `any of` / `all of` with `*` patterns, `them`, a list of conditions | ✓ |
| `\| count() [by field] > N` / `>= N` with `timeframe` (s, m, h, d) | ✓ counted per group in event time; the alert cites the counted lines and records count, threshold, group and window |
| `\| count(field) [by group] > N` (distinct values of field) | ✓ e.g. distinct usernames per source IP |
| `<` / `<=` thresholds, `near`, other aggregation functions, an aggregation without `timeframe` or inside a list of conditions | ✗ rule skipped |
| Other modifiers (`base64offset`, `windash`, `utf16le`, …) | ✗ rule skipped |
| Multi-document rule collections | ✗ rule skipped |

A rule that needs anything unsupported is **skipped with the reason**, never half-applied. Skipped rules and their reasons are printed on load and written to the audit trail (`config.warnings`). A rule folder with no usable rules is an error.

## Field and log-source mapping

Sigma's Windows taxonomy uses the events' own field names (`Image`, `CommandLine`, `TargetImage`, `GrantedAccess`, `ServiceName`, …). These are exactly the keys the Windows JSON, Windows Event XML and CSV parsers produce, so they are looked up directly (case-insensitive). Aliases cover sources that name a field differently:

| Sigma field | Also read from |
|---|---|
| `Image` | `NewProcessName` (Security 4688) |
| `ParentImage` | `ParentProcessName` (Security 4688) |
| `User` | `SubjectUserName`, `TargetUserName` |
| `Message` | the entry's message |
| `Computer`, `Hostname` | the entry's host |

| Log source | Matches entries with |
|---|---|
| `product: windows` / `linux` | an `EventID` field / no `EventID` field |
| `category: process_creation` | Security 4688, or Sysmon 1 |
| `category: process_access` / `network_connection` / `registry_set` / `file_event` | Sysmon 10 / 3 / 13 / 11 |
| `category: ps_script` / `ps_module` | 4104 / 4103 |
| `service: security` / `system` / `sysmon` / `powershell` | the matching `Channel` |
| `service: auth` / `sshd` / `syslog` (Linux) | no extra filter (syslog text carries no reliable channel) |

Any other category, service or product makes the rule unsupported. Mapping a new log source is one line in [`internal/sigma/sigma.go`](../internal/sigma/sigma.go).

## Shipped rules

| Rule | ATT&CK | Tested on (real data) |
|---|---|---|
| [Format String Exploitation Attempt in a Service Log](../rules/sigma/lnx_format_string_exploit.yml) | T1190, Initial Access | loghub-linux: **7 alerts = all 7 rpc.statd exploit attempts (20 lines), 0 false positives**. This closes the Phase 1 detection gap. |
| [LSASS Memory Read With Credential-Dumping Access Rights](../rules/sigma/win_lsass_access_credential_dump.yml) | T1003.001, Credential Access | Mordor Mimikatz: **1 alert**, the PowerShell process opening LSASS with `0x1010`. The 3 benign svchost accesses don't match. |
| [Service Installed That Runs Encoded PowerShell](../rules/sigma/win_service_install_encoded_powershell.yml) | T1569.002, Execution | Mordor PsExec: **1 alert**, Empire's `Updater` service. |

| [SSH Password Spraying or User Enumeration From One Source](../rules/sigma/lnx_ssh_password_spraying.yml) | T1110.003, Credential Access | loghub-ssh: **303 alerts from 124 source IPs**, each trying > 4 account names within 10 minutes. Spot-checked: 0101, 0, 1234 from one IP within seconds; up to 28 names in 7 minutes. 0 alerts on the benign set and on loghub-linux. |

The first three stay silent on the benign set and the 655k-line SSH corpus, and the spraying rule stays silent on the benign set (`TestIntegration_SigmaDatasets`). Community rules from [SigmaHQ](https://github.com/SigmaHQ/sigma) can be dropped in next to them. Rules outside the supported subset are listed as skipped.
