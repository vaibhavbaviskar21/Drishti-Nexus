# Chain of Custody & Audit Trail

Drishti Nexus is used on evidence. Its results are only worth citing if anyone can show three things later:
1. The tool never altered the source logs.
2. Exactly which bytes were analysed.
3. With which rules and settings, by whom, and when.

This document describes how each guarantee is implemented and how to verify it.

| Guarantee | Mechanism | Verified by |
|---|---|---|
| Source logs are never modified | Single read-only open path; static check over the codebase | `TestEvidenceOpenedReadOnly`, `TestOpenEvidenceIsReadOnly` |
| Exactly which bytes were analysed | SHA-256 before **and after** analysis | `TestHashFileAndEvidence`, `TestIntegration_ChainOfCustody` |
| Which rules, settings, user, time | Session record in an append-only, hash-chained audit log | `TestAuditLogChainAppendAndVerify` |
| The audit log itself wasn't edited | Each record hashes the previous one; `drishti audit verify` | `TestAuditLogTamperDetection` |
| Reports can be tied back to evidence | Audit section in JSON; custody columns on every CSV row | `internal/storage/export.go` |
| A report can't overwrite evidence | Output paths checked against every evidence file | `TestCheckOutputPathRefusesEvidence` |

---

## 1. Read-only access to evidence

- **One entry point.** Every source log is opened through `audit.OpenEvidence`, which calls `os.OpenFile(path, os.O_RDONLY, 0)` ([`internal/audit/evidence.go`](../internal/audit/evidence.go)). Hashing, scanning, `tail` and resume all use it.
- **Enforced statically.** `TestEvidenceOpenedReadOnly` parses every non-test Go file and fails CI if any call to `os.Open`, `OpenFile`, `Create`, `WriteFile`, `ReadFile`, `Truncate`, `Remove`, `Rename` or `Chmod` appears outside a reviewed allow-list. The allow-list covers the audit log, report outputs, the config file and generated test data, each with a reason. Adding a new file access anywhere forces a review.
- **Enforced at runtime.** A write to an evidence handle fails (`TestOpenEvidenceIsReadOnly`).
- **Reports never overwrite evidence.** Before writing, `audit.CheckOutputPath` compares the output path with every evidence file, both as an absolute path and by `os.SameFile` (catches `./x`, `a/../x`, hard links). It refuses on a match.

## 2. Evidence hashing

For every input file, at session start (before any parsing), Drishti Nexus records:

| Field | Meaning |
|---|---|
| `path`, `abs_path` | As given, and resolved |
| `size_bytes`, `mod_time` | From the filesystem (UTC) |
| `sha256` | SHA-256 of the full file, read through `OpenEvidence` |

When the session ends, each file is **re-hashed**:

| Field | Meaning |
|---|---|
| `sha256_after` | SHA-256 at the end of analysis |
| `unchanged` | `sha256_after == sha256` |

If any file changed during analysis, the command reports `✗ EVIDENCE HASH CHANGED DURING ANALYSIS` and exits non-zero. The mismatch is also written to the audit log.

**Growing files (`tail`).** A live log legitimately grows, so a whole-file re-hash would always differ. Instead, the prefix that was hashed at start (`size_bytes` bytes) is re-hashed at the end. `unchanged=true` then proves that nothing already analysed was rewritten, only appended to. `bytes_analyzed` records how far analysis got.

## 3. Audit log

Every `scan`, `analyze`, `tail` and `serve -log` session appends **two** records to the audit log. The default path is `drishti_audit.log` in the working directory; override it with `-audit-log`.

- **`session_start`** is written after hashing and before processing. A crashed or killed session therefore still leaves a trace.
- **`session_end`** contains the results, the re-verified hashes, the outputs written (with their own SHA-256) and the final status (`ok`, `interrupted`, `error: …`).

Each record contains:

| Field | Content |
|---|---|
| `session_id` | Random 64-bit ID, also written into every report |
| `command`, `args` | Exactly how the tool was invoked |
| `started_at`, `finished_at` | UTC |
| `os_user`, `hostname`, `platform` | Who ran it, and where |
| `tool_version`, `go_version` | Build identification (set with `-ldflags -X …/version.Version=`) |
| `config.config_path`, `config.config_sha256` | Which config file, and its hash |
| `config.rules[]` | Effective name, enabled, severity, threshold and time window of **every** rule (defaults merged with config) |
| `config.normal_hours`, `config.incident_gap` | Other settings that change results |
| `config.assumed_timezone` | The zone applied to timestamps without an offset (`-tz`) |
| `config.storage` | `memory` or `sqlite:<path>` |
| `config.warnings` | Config problems (unknown rule names, etc.) and resume events |
| `evidence[]` | Section 2 |
| `outputs[]` | Reports written, with their SHA-256 |
| `results` | Lines, entries, parse-quality breakdown, alerts per rule, incident count |

### Tamper evidence

The file is opened with `O_APPEND|O_CREATE|O_WRONLY` (mode `0600`) and `fsync`ed after each record. Earlier records are never rewritten. Each line is an envelope:

```json
{"prev_hash":"<record_hash of previous line>","record":{...session...},"record_hash":"<sha256(prev_hash || record bytes)>"}
```

The first record's `prev_hash` is 64 zeros. The hash covers the record's exact bytes. So:
- **Editing** any record changes its `record_hash`.
- **Deleting, inserting or reordering** records breaks the next record's `prev_hash`.
- **Appending after a corrupted last line** is refused, so the chain cannot be silently forked.

Verify the chain at any time:

```text
$ drishti audit verify -audit-log drishti_audit.log
✓ drishti_audit.log: 42 records, 21 sessions — hash chain intact
```

On failure it names the first bad line and whether the content was modified or the chain broken.

**Limits, stated honestly.** A hash chain is *tamper-evident*, not tamper-proof. Someone with write access can rewrite the whole file and recompute every hash. To anchor the log, copy the latest `record_hash` somewhere the analyst does not control, such as the case notes, a ticket or a write-once medium. Any later rewrite of earlier history then becomes detectable. Signing records with a per-examiner key is a candidate for Phase 6.

## 4. Reports

**JSON (`scan -output report.json`)** embeds the complete `session_start` record under `audit`. That covers evidence hashes, rules, config hash, user and timezone assumption. It also embeds `audit_log` and `audit_record_hash`, the record's position in the chain. The report can therefore be checked against both the evidence (re-hash it) and the audit log (find the hash).

**CSV (`…-alerts.csv`)** has one row per alert. Every row carries:

| Column | Meaning |
|---|---|
| `EvidenceFile`, `EvidenceSHA256` | The file the alert was derived from, and its hash |
| `EvidenceLines` | `file:line` IDs of every contributing log line (capped at 50) |
| `AuditSessionID`, `AuditRecordHash`, `ToolVersion` | Binds the row to its session and audit record |

So a single row pasted into a ticket is still citable.

The hashes of both report files are recorded in the session's `outputs[]`. A later edit to a report is detectable against the audit log.

## 5. Determinism

Re-running the same version and config on the same evidence produces identical findings:
- Entry IDs are `<file>:<line>`.
- Alert IDs (`ALERT-000001`) and incident IDs (`INC-00001`) are sequential in processing order.
- No IDs or decisions depend on wall-clock time.

Timestamps are normalised to UTC. The original text (`timestamp_raw`), its offset (`tz_offset`) and any assumption (`tz_assumed`, `year_inferred`, `dst`) are kept on every entry, so a normalised time can always be traced back to what the log actually said.

## 6. Crash recovery and custody

With `-db case.db`, `tail` checkpoints its byte offset, line number and detection-engine state into SQLite. Each checkpoint commits atomically with all data written before it. The checkpoint also stores the SHA-256 of the file's first 4 KB:
- **On resume**, a file whose start no longer matches (rotated or replaced) is **refused**. Findings from one file are never continued against different evidence.
- **On resume, the session is a new audit session.** The resume point is recorded in `config.warnings`.
- **Replaying lines after a crash is idempotent**, because IDs are deterministic (`TestFollow_ResumeAfterCrash`).

## 7. Operating checklist

1. Work on a forensic copy. Record its hash in your case notes *before* running the tool, so it can be compared with `evidence[].sha256`.
2. Pass `-tz` with the source host's zone when the logs have no offsets. It is recorded in every report.
3. Keep the audit log with the case. Run `drishti audit verify`, then copy the last `record_hash` into your notes.
4. Cite alerts by `AlertID` + `EvidenceLines` + `EvidenceSHA256`.
