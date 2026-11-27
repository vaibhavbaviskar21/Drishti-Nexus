# Incident Reports

`drishti scan` can write an analyst-facing incident report next to the JSON and CSV exports (plan 3.1):

```bash
drishti scan -report case-42.html -pdf case-42.pdf logs/
```

- `-report <path>` writes one self-contained HTML file: inline CSS, no JavaScript, no fonts, images or links to anything outside the file. It opens in any browser on an air-gapped workstation and has a print stylesheet (A4), so "Print → Save as PDF" also works.
- `-pdf <path>` writes the same content as a PDF for case files.

Both flags are optional and combine with every other `scan` flag (`-sigma`, `-parsers`, `-db`, `-ecs`, ...).

Report files are outputs like the JSON and CSV: the path is checked against the evidence first (`CheckOutputPath`, so a report can never overwrite a source log), the file is written through `storage.CreateOutput`, and its SHA-256 is recorded in the session's `outputs` in the `session_end` audit record. A report cannot contain its own hash, so the audit log is where to verify it.

## Sample

[`docs/report/sample-incident-report.html`](report/sample-incident-report.html) / [`.pdf`](report/sample-incident-report.pdf) was generated from the Phase 0 Mordor dataset (Empire PsExec over DCERPC/svcctl; see `testdata/DATASETS.md` to fetch it) with the shipped Sigma rules:

```bash
drishti scan -sigma rules/sigma -output drishti-scan-sample.json \
  -report docs/report/sample-incident-report.html -pdf docs/report/sample-incident-report.pdf \
  testdata/datasets/mordor/empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608.json
```

It shows 3 incidents: Empire PowerShell launched on WORKSTATION5, then the PsExec-style service (`Updater`, encoded PowerShell, Sigma T1569.002) installed on WORKSTATION6. The **Remote Service Execution** alert (network logon by `pgustavo` from WORKSTATION5, then the service install 2 ms later) sits in WORKSTATION5's incident, so the hop between the two machines reads as one timeline. The `Injection Pattern Detected` (T1190) alerts in the sample are the built-in injection rule firing on PowerShell script-block text. They are kept, not hidden, because the report shows what the engine actually produced.

The cross-host lateral-movement demo (`docs/demo/MULTIHOST_DEMO.md`) gives a smaller report with one incident of 3 alerts:

```bash
drishti scan -report multihost.html -pdf multihost.pdf testdata/fixtures/multihost
```

## Sections

1. **Summary**: incidents, alerts, parsed entries, physical lines, evidence files and analysis time; alerts per rule; every MITRE ATT&CK technique observed with its tactic and alert count. Below it, **compliance references**: the PCI DSS 4.0.1, ISO/IEC 27001:2022 and HIPAA controls each observed technique is evidence for (a reference for auditors, not an assessment; see `docs/COMPLIANCE_MAPPING.md`).
2. **Parse quality**: how many entries were `Clean` (a format parser matched exactly), `Partial` (matched, but something was repaired or assumed: encoding, truncation, DST, inferred year) or `BestEffort` (no parser matched; raw text kept), plus entries per parser and per repair. Read this before trusting a quiet report: a scan that is mostly `BestEffort` had little structure to detect on.
3. **Incidents**: alerts that share an incident ID (same correlation key within the incident gap, see `docs/RULES.md`), first as a table, then as one timeline per incident, oldest first. Each alert shows its time and last occurrence, severity, rule, description, ATT&CK tag, rule details (thresholds, users, IPs) and related alerts, then its **cited evidence**: the entry ID (`<file>:<line>`, the exact line in the evidence file), timestamp, source and parsed message. To keep the report readable, at most 10 cited lines are shown per alert and each message or detail value is cut at 400 characters (whitespace collapsed); the full list of cited IDs is in the JSON report. If an entry was not kept in memory (`-alerts-only`, or the in-memory store cap), only its ID is shown; the line is still in the evidence file at that ID.
4. **Chain of custody**: each evidence file's path, size and SHA-256 before and after analysis, marked `unchanged` or `CHANGED`; the detection config path and hash (or "built-in defaults"); every custom parser or Sigma rule file with its hash; and the JSON/CSV/ECS outputs written before the report, with their hashes. See `docs/CHAIN_OF_CUSTODY.md`.
5. **Audit session**: session ID (the key into `drishti_audit.log`), the command and arguments, the OS user and host that ran it, tool / Go version and platform, start time, report time, the hash of the `session_start` audit record, and the effective configuration: normal hours, incident gap, adaptive thresholds, assumed timezone, storage, each rule's enabled flag / severity / threshold / window, and any warnings (skipped Sigma rules, config problems).

The "after" hashes are computed when the report is built. The scan re-hashes the evidence once more for the `session_end` record, and `drishti audit verify` checks the audit chain.

## AI summaries (optional, off by default)

Everything above is deterministic. `report.Data.AISummaries` is reserved for the optional local-model narrative (plan Phase 5). When it is empty, which is always the case unless that feature is enabled, nothing is rendered. When present, it gets its own section headed **"AI-generated summaries (not evidence)"** after the incidents, showing the model name, whether every claim was matched against the incident's data, and any unsupported claims in red.

## Implementation

- `internal/report`: `Build(res)` turns a pipeline result into `Data`; `WriteHTML` renders it with `html/template` from an embedded template; `WritePDF` renders the same `Data` with a small built-in PDF writer.
- **Escaping:** log content is attacker-controlled. HTML values are escaped by `html/template` (no `template.HTML` is ever built from data). In the PDF, text is reduced to WinAnsi bytes with control characters removed and `( ) \` escaped, so a log line cannot inject PDF operators. Both are covered by tests.
- **PDF approach:** a minimal PDF 1.4 writer (`internal/report/pdfdoc.go`, stdlib only) using the standard Helvetica / Helvetica-Bold / Courier fonts that every PDF reader provides, so nothing is embedded. No headless browser, no cgo, no new dependency. `github.com/go-pdf/fpdf` was considered, but it pulls several transitive modules (barcode, PDF import, `golang.org/x/image`) into a tool meant to be audited and run air-gapped. The trade-off: characters outside Windows-1252 (e.g. CJK) print as `?` in the PDF; the HTML report shows them correctly.
