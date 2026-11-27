# Drishti Nexus — Baseline Report Card

This is the measured report card the implementation plan requires at the end of every phase.
Every number here comes from a file in [`benchmarks/results/`](benchmarks/results/) and can be reproduced:

```bash
bash scripts/fetch-datasets.sh        # public datasets, SHA-256 pinned
make genbenign                        # deterministic synthetic benign set (seed 42, fixed end date)
go run ./cmd/benchmark -suite -sigma rules/sigma -out benchmarks/results/latest.json
```

| Phase | Date | Build | Results file |
|---|---|---|---|
| 0 (re-measured) | 2026-10-04 | commit `f5f55a9` | [`phase0-remeasured.json`](benchmarks/results/phase0-remeasured.json) |
| 1 | 2026-10-04 | Phase 1 working tree, go1.25.5 windows/amd64 | [`phase1.json`](benchmarks/results/phase1.json) |
| **2** | **2026-11-01** | **branch `phase2-to-6`, go1.25.5 windows/amd64, with `-sigma rules/sigma`** | [**`phase2.json`**](benchmarks/results/phase2.json) |

Sections 1–7 below are the Phase 1 report card, kept for history. **The Phase 2 report card is section 0.**

---

## 0. Phase 2 report card

### 0.1 False positives (synthetic benign set: every alert is a false positive)

| Rule | Phase 0 | Phase 1 | **Phase 2** | What changed in Phase 2 |
|---|---:|---:|---:|---|
| Time-based Anomaly | 0* | 79 | **38** | Per-host hour profile (2.5): after 3 days of history, an off-hours event alerts only if the host was active at that hour on < half its prior days |
| Excessive Authentication Failures | 4,024 | 8 | **8** | Unchanged. All 8 are console-login bursts from the generator (see §4) |
| Privilege Escalation Indicator | 17,610 | 0 | **0** | Severity now comes from corroboration (2.5), not the keyword |
| Authentication Brute Force | 6,860 | 0 | **0** | |
| Injection / Suspicious Command / Lateral Movement | — | 0 | **0** | |
| Sigma (3 shipped rules) | — | — | **0** | |
| **Total** | **28,494** | **87** | **46** | |
| **False positives per 1,000 benign lines** | 569.9 | 1.74 | **0.92** (−47% vs Phase 1) | |

\* Phase 0 timestamps were `time.Now()`, i.e. always "inside business hours".

The same host profile cut Time-based Anomaly on real data: **loghub-linux 431 → 219**, **loghub-ssh 30 → 4**.

### 0.2 Detection on attack data

*Added 2026-11-20:* the shipped Sigma rule for SSH password spraying / user enumeration (`count(user) by src_ip > 4` in 10 minutes) raises **303 alerts from 124 source IPs on loghub-ssh**, and 0 on the benign set and on loghub-linux. The numbers below are without it.

| Dataset | Phase 1 | **Phase 2** | Phase 2 additions |
|---|---|---|---|
| loghub-ssh (655k) | 1,711 alerts | **1,595** | Adaptive thresholds (2.1) quiet the host-level bucket of IP-less failures (EF 1,680 → 1,590). **Every one of the 554 attacking IPs still gets exactly as many alerts as before.** |
| loghub-linux | 775 | **570** | **Sigma: 7 alerts = all 7 rpc.statd format-string exploit attempts (20 lines), 0 false positives.** This was a Phase 1 detection gap. |
| mordor-mimikatz | 2 | **3** | **Sigma: LSASS read with credential-dumping rights (T1003.001)**: the one Mimikatz access, not the 3 benign svchost accesses |
| mordor-psexec | 6 | **7** (8 since 2026-11-27) | **Sigma: service installed running encoded PowerShell (T1569.002)**: Empire's `Updater` service. *2026-11-27:* **Remote Service Execution** links the WS5 → WS6 hop into WS5's incident |
| multihost fixture | — | **3 alerts, 1 incident** | **Lateral Movement Candidate (2.2)**: brute force on web01 → login on db01 7m26s later, linked into one incident ([demo](docs/demo/MULTIHOST_DEMO.md)) |

Incident counts went up on loghub-ssh (1,094 → 1,370) although alerts went down. Fewer low-severity Time-based Anomaly alerts no longer keep attackers' Excessive Failures incidents open across quiet gaps, so later bursts after a > 30-minute gap start new incidents.

**Adaptive thresholds (2.1), measured:** on loghub-ssh, 204 Excessive Failures alerts fired at a raised threshold (each records `static_threshold`, `baseline_mean`, `baseline_stddev`, `baseline_windows`). The 90 alerts the feature removed all belong to one key, the per-host bucket of failures that carry no source IP. On the benign set the feature changes nothing (its 8 EF bursts are not from a learned noisy source). A sustained attack cannot raise its own threshold: windows at or above the threshold are never learned (`TestAdaptive_AttacksAreNotLearned`).

### 0.3 Parsing and formats (2.6, NTRO)

| Input | Real sample | Result |
|---|---|---|
| CEF 0/1 (bare or in any syslog envelope) | logstash-codec-cef test suite (Apache-2.0), ArcSight spec examples | All cases parsed (escapes, `=` in values, dotted/bracketed keys) |
| LEEF 1.0 / 2.0 | IBM LEEF spec examples | Tab, caret and hex delimiters; `devTime` beats the envelope time |
| CSV with header | LogHub OpenSSH 2k structured CSV, LogHub Windows CSV | 100% Clean. **The CSV raises exactly the same alerts, with the same counts, as the raw OpenSSH log.** |
| Windows Event XML | Microsoft's documented 4625 event | Failed logon classified, host/user/IP/time exact |
| YAML-defined (`-parsers`) | LogHub HDFS and ZooKeeper (200 lines each) | 0% → **100% Clean** with the shipped definitions |
| ECS export (`scan -ecs`) | every format | Raw line, `file:line`, evidence SHA-256 and session on every event |

Alert counts on every benchmark dataset were unchanged by the new parsers. In a controlled parse benchmark, CEF/LEEF detection added no measurable cost.

### 0.4 Throughput

Sustained run: `cmd/benchmark -repeat N` runs the whole dataset N times back to back in one process (full pipeline: read, parse, 7 native rules + 3 Sigma rules, in-memory store), sampling the live heap every 250 ms. Raw results: `benchmarks/results/phase2-throughput-ssh.json`, `phase2-throughput-json.json`.

| Input | Passes | Lines processed | Wall time | Throughput | Per day at that rate | Peak live heap |
|---|---|---|---|---|---|---|
| LogHub SSH (syslog, 655,147 lines, 73 MB) | 10 | 6,551,470 | 187.5 s | **34,932 lines/s** (3.9 MB/s) | ~3.0 billion lines | **10 MB** |
| Mordor Mimikatz (Windows JSON events, 6,026 lines, 43 MB) | 20 | 120,520 | 45.6 s | **2,644 events/s** (19 MB/s) | ~228 million events | **5 MB** |

**Machine:** Intel Core i3-1005G1 laptop (2 cores / 4 threads, 1.2 GHz base), Windows 11, Go 1.25.5, measured 2026-11-07. **These are lower bounds:** the machine was at 64–100% CPU from unrelated work during the run (the benchmark ran at high priority). The pipeline is single-threaded, so this is roughly one core's worth.

What it shows:
- **Memory stays flat.** Peak live heap does not grow with input size (10 MB after 6.5 M lines), because detection state is pruned to the rule windows. Long-running `tail` sessions do not leak.
- **Cost is linear.** Allocation per pass is constant (2.9 GB per SSH pass, 29 GB for 10), so throughput holds over the run.
- **"Billions of events per day"** is reachable for syslog-style auth logs on one commodity core; Windows JSON events are ~13× more expensive per event (larger records, Sigma field matching), so a JSON-heavy feed needs per-host parallel runs.

Method note: an earlier `-repeat` passed the same file N times to one pipeline. The pipeline merges files by timestamp, so the N copies interleaved and every detection window held N identical events; cost grew quadratically (10 passes allocated 547 GB). That measured an impossible input, not the engine, and was replaced by back-to-back passes before these numbers were taken. A real single source producing thousands of failures inside one window would hit the same per-event window scan; see `docs/LIMITATIONS.md`.

### 0.5 Quality gates

| Gate | Status |
|---|---|
| `go test ./...` (unit, fixture and dataset integration tests) | Pass |
| golangci-lint v2.5.0 | 0 issues |
| gosec v2.22.8 | 0 issues |
| GitHub Actions | Green on PR #1. PR #2 (2.6 ECS/formats) and this branch run the same gates plus a container build and a smoke scan |

### 0.6 Known gaps after Phase 2

1. **Excessive Failures on the benign set (8)** are a generator artifact (console login failures from random daemons), not a rule defect.
2. **Sigma subset:** `near`, `<` thresholds, aggregation functions other than `count()` and some modifiers are not supported (`count()` aggregations were added on 2026-11-20). Such rules are skipped and listed, never half-applied ([SIGMA.md](docs/SIGMA.md)).
3. **BOTS** is still not ingested (Splunk index format). Windows coverage comes from Mordor JSON, Windows Event XML and CSV.
4. **Year inference** for year-less syslog still relies on file mtime. loghub-linux spans a year boundary, and its alerts show 2016/2017 mixed (`year_inferred` is recorded on every entry).
5. **Host profiles and privilege history start empty**, so the first days of any analysis behave like the static rules. That is by design: the history has to be earned.

---

## 1. Datasets

| Dataset | Lines | Source | Ground truth / use |
|---|---:|---|---|
| `loghub-ssh` | 655,147 | [LogHub](https://github.com/logpai/loghub) OpenSSH, Zenodo 8196385 | Real sshd log from a lab server under sustained internet brute force |
| `loghub-linux` | 25,567 | LogHub Linux | Real `/var/log/messages` from one host. Mostly system noise, some real brute-force bursts, and one real rpc.statd exploit |
| `mordor-mimikatz` | 6,026 | [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | Windows Security/Sysmon/PowerShell JSON, Empire Mimikatz `logonpasswords` |
| `mordor-psexec` | 4,348 | OTRF Security-Datasets | Windows events, Empire PsExec lateral movement |
| `synthetic-benign` | 50,000 | `cmd/genbenign` | **Benign by construction**, so every alert is a false positive |
| `fixture-openssh-2k` | 2,000 | First 2k lines of LogHub OpenSSH | Committed fixture; always runs in CI |

Not included, by agreement for Phase 1:
- **EVTX-ATTACK-SAMPLES** is binary `.evtx`, and there is no EVTX parser yet. Windows coverage comes from the Mordor JSON exports instead.
- **Splunk BOTS** is distributed as Splunk indexes, not raw logs. It is deferred to Phase 2/4.

---

## 2. Corrections to the Phase 0 report

Re-measuring on real data showed that several Phase 0 claims were wrong. They are corrected here so this report card stays trustworthy.

| Phase 0 claim | What was actually happening |
|---|---|
| "SSH.log: 648,415 lines, **100% parse success**, 300k lines/s" | Plain BSD syslog (no `<PRI>`) matched no parser. **Every line** went to the generic fallback with `source=unknown` and `timestamp=time.Now()`. "Success" only meant "not nil". |
| "SSH.log is a public IR dataset" | By 2026-10-04 `SSH.log` had been overwritten with a CRLF copy of the synthetic benign file. It was removed, and the real dataset is now fetched with a pinned checksum. |
| "Phase 1: 14,783 benign alerts (29.6% FP)" | Measured on uncommitted code that **collapsed 655,147 SSH lines into 139 entries**: plain syslog lines were glued into 512 KB "multi-line" blobs. Low alert counts came from parsing almost nothing. |
| Benign set reproducible with seed 42 | The generator anchored timestamps to `time.Now()` and wrote them out of order. It now takes a fixed `-end` date and writes in chronological order, so output is byte-identical across runs. |

---

## 3. Parsing

### Structured parse rate
A line counts as **structured** when a format-specific parser produced it (`Clean` or `Partial`). The generic fallback (`BestEffort`) keeps raw text only.

| Dataset | Phase 0 (`f5f55a9`) | **Phase 1** | Phase 1 `Clean` |
|---|---:|---:|---:|
| loghub-ssh | **0%** (100% generic fallback) | **100%** | 100% |
| loghub-linux | **0%** | **100%** | 99.92% (20 `Partial`, see below) |
| mordor-mimikatz | 100% JSON, but `source=""` (key `Hostname` not recognized) | **100%**, host extracted | 100% |
| mordor-psexec | 100% JSON, `source=""` | **100%**, host extracted | 100% |
| synthetic-benign | **0%** | **100%** | 100% |

Every entry now carries `parse_quality`, the `parser` that produced it, and a `file:line` ID that cites the exact evidence line.

### Parse-failure catalog (task 1.1)
These were found by feeding every dataset through the parser and by adversarial unit tests. Every case is now handled and covered by a test.

| # | Failure / malformed-line case | Phase 0 behaviour | Phase 1 behaviour | Test |
|---|---|---|---|---|
| 1 | BSD syslog without `<PRI>` (auth.log, messages) | Generic fallback: no host, fake time | Dedicated parser, hand-written header splitter | `TestSyslog_FormatDetection` |
| 2 | Tags with spaces or parens (`syslogd 1.4.1:`, `sshd(pam_unix)[pid]:`) | Not parsed | Parsed: tag, program, pid | `TestSplitTag` |
| 3 | `<PRI>` severity mapped backwards (syslog 2=crit became Notice) | Wrong severity on every PRI message | Correct mapping (7−n) | `TestSyslog_FormatDetection` |
| 4 | RFC 5424 nil structured data `-` | Message became `"- msg"` | Correct | same |
| 5 | Year-less timestamps (RFC 3164) | Always current year, so December logs read in January landed 11 months in the future | Year inferred from file mtime (≤48h ahead), with Feb 29 handling. Recorded in `year_inferred` | `TestSyslog_YearInference`, `TestInferYear` |
| 6 | Zone-less timestamps | Implicit UTC/local mix | Interpreted in `-tz` (default UTC), stored as UTC. Original offset kept in `tz_offset`, raw string in `timestamp_raw`, `tz_assumed` flagged | `TestSyslog_TimezoneNormalised…` |
| 7 | DST: nonexistent wall time (spring forward) | Silent, arbitrary | Shifted forward by the gap, `dst=nonexistent`, `Partial` | `TestResolveLocal_NonexistentSpringForward` |
| 8 | DST: ambiguous wall time (fall back) | Silent, could run time backwards | Earliest instant not before the previous entry, `dst=ambiguous`, `Partial` | `TestResolveLocal_AmbiguousFallBack`, `TestRegistry_DSTFlagMarksEntryPartial` |
| 9 | UTF-8 BOM, CRLF line endings | `\r` left in messages | Stripped (BOM noted, not downgraded) | `TestRegistry_CRLFAndBOM` |
| 10 | Latin-1 / invalid UTF-8, NUL bytes | Garbled | Decoded/removed, `encoding_repaired`, `Partial` | `TestDecodeMixedEncoding` |
| 11 | Lines > 64 KB | `bufio.Scanner` **aborted the whole file** ("token too long") | `LineReader` truncates at 1 MB, flags `truncated`, continues | `TestLineReader_OversizedLineDoesNotAbortFile` |
| 12 | Pretty-printed (multi-line) JSON | Not reassembled at HEAD; swallowed following records in the working tree | Brace/string-aware assembly | `TestRegistry_MultilineJSON` |
| 13 | Raw newline inside a JSON string | Swallowed every following record | Record ends where its braces balance; newline escaped; `json_repaired` | `TestRegistry_JSONWithEmbeddedNewlineInString` |
| 14 | Truncated JSON at EOF | Lost | Emitted, `json_incomplete`, not `Clean` | `TestRegistry_UnterminatedJSONAtEOF` |
| 15 | Java/Python stack traces | One entry per frame | Folded into the parent entry (`line_count`) | `TestRegistry_StackTraceFoldedIntoEntry` |
| 16 | JSON key case (`Hostname`, `Message`) and ECS `host.name` | Not found | Case-insensitive lookup, ECS objects | `TestJSON_FieldExtraction` |
| 17 | Epoch milliseconds | Read as seconds (year 55,000) | Detected | same |
| 18 | Apache request line with raw spaces/quotes (typical of injection attempts) | Rejected, fell to generic | Whole quoted request captured, then split | `TestApache_CombinedAndCommon` |
| 19 | Lines with no timestamp | `time.Now()` fabricated | Inherit previous entry's time (`timestamp_inherited`), else zero (`timestamp_missing`). **Never invented** | `TestRegistry_TimestampInheritedForTimelessLines` |
| 20 | Entry IDs from wall-clock µs | Duplicate IDs; memory eviction removed the wrong entries | Deterministic `file:line` | `TestRegistry_EveryPlainSyslogLineIsOneEntry` |

**Residual non-Clean lines on real data:** 20 of 25,567 in `loghub-linux`, all the same thing. They are an rpc.statd format-string exploit (`gethostbyname error for ^X…%8x%8x…%hn` plus raw shellcode bytes, the CVE-2000-0666 pattern). They are correctly flagged `Partial` / `encoding_repaired=latin1`. **No rule currently detects this exploit.** That is noted as a detection gap for Phase 2.

---

## 4. Detection and false positives

### Benign set (every alert is a false positive)

| Metric | Phase 0 (`f5f55a9`) | **Phase 1** |
|---|---:|---:|
| Alerts on 50,000 benign lines | 28,494 | **87** |
| False positives per 1,000 benign lines | 569.9 | **1.74** (−99.7%) |
| Privilege Escalation alerts on 10,082 legitimate `sudo`/`su` lines | 17,610: **100% of legitimate sudo/su**, plus 7,528 lines that merely mention "root" | **0 (0%)** |
| Authentication Brute Force | 6,860 | **0** |
| Excessive Authentication Failures | 4,024 | 8 |
| Time-based Anomaly | 0 (timestamps were `time.Now()`, i.e. inside business hours) | 79 |

*(Phase 0 figures were re-measured on the regenerated, chronologically ordered benign set. On the original unordered file Phase 0 reported 38,976.)*

**Manual review of the 87 remaining false positives:**
- **8 Excessive Authentication Failures.** All are bursts of 5–6 `pam_unix(login:auth): authentication failure` lines on one host within 10 minutes. The generator emits about 2,500 console-login failures a week from random daemons, which is not realistic benign traffic. The rule behaves exactly as specified, so this is a generator artifact.
- **79 Time-based Anomaly.** The generator spreads activity uniformly over 24 hours, so about two thirds of logins fall outside 09:00–17:00. Each alert aggregates one host-hour (42–95 events each). Real environments need per-host baselines, which is **Phase 2.1 (adaptive thresholds)**.

### Attack datasets

| Dataset | Phase 0 alerts | **Phase 1 alerts / incidents** | Notes |
|---|---:|---:|---|
| loghub-ssh (655k) | did not finish in 15 min | **1,711 / 1,101** | 1,680 Excessive Failures, one per attacking IP burst. **1 confirmed brute-force success** (`Accepted password for curi from 123.255.103.142` after 5 failures) |
| loghub-ssh, first 50k lines | 61,175 (more alerts than lines), 158.8 s | **99 / 72**, 0.9 s | |
| loghub-linux | 6,953 | **775 / 592** | 344 Excessive Failures are real SSH brute-force bursts. 431 Time-based Anomaly are off-hours noise (Phase 2.1) |
| mordor-mimikatz | **0** | **2 / 1** | Empire PowerShell stager (`powershell`) + injection pattern in the script block: **true positives** |
| mordor-psexec | **0** | **6 / 3** | PowerShell/`cmd.exe` execution across WORKSTATION5/6: true positives |

### What changed in detection (Phase 1.3 and correctness fixes)
- **Event-time windows.** Pruning used `time.Now()`, which silently broke every window on historical logs.
- **Keying by host + source IP**, not hostname only. A failure from one IP plus a success from another is no longer a "brute force".
- **Attempt de-duplication.** One sshd login attempt writes 2–3 lines (pam_unix + `Failed password` + `Invalid user`, same PID). It now counts once, and `message repeated N times` counts N.
- **Structured auth fields** (`auth_result`, `user`, `src_ip`) from the parser. Keyword matching is only a fallback for formats without an extractor, and never applies to structured Windows events.
- **Aggregation.** Repeats of a rule on the same key within its window update one alert (`count`, `last_seen`) instead of creating new ones.
- **Linking.** Brute Force and the Excessive Failures alert for the same host+IP share an `incident_id`, are cross-linked in `related_alerts`, and the lower-fidelity alert is marked `superseded_by`.
- **Incidents.** Alerts with the same correlation key within `incident_gap` (default 30m) share a deterministic `INC-nnnnn`.
- **Evidence.** Threshold alerts cite every contributing line (capped at 50), not just the trigger.
- **Config honoured.** Thresholds, windows, severity and `enabled` now come from `configs/config.yaml`. Phase 0 hard-coded them, and two config names didn't match their rules. Unknown names produce warnings in the audit trail.
- **False-positive fixes.** These were found on real data and pinned by tests:
  - Privilege escalation fired on any "root"/"sudo" mention.
  - A lone backtick counted as command injection ("process \`syslogd' …").
  - `uac` matched inside obfuscated PowerShell.
  - `ncat` matched inside the username "concat".
  - Plain `bash`/`curl` substrings counted as suspicious commands.

---

## 5. Performance

| Dataset | Phase 0 | **Phase 1** |
|---|---:|---:|
| loghub-ssh 655,147 lines | did not finish (> 900 s; O(n²) window scans) | **9.5 s, ~69k lines/s** |
| loghub-ssh first 50k | 158.8 s (315 lines/s) | **0.9 s** |
| synthetic-benign 50k | 2.2 s | **0.5 s** (~101k lines/s) |
| mordor (JSON, ~5 KB/event) | ~1 s | 0.4–1.4 s (4–11k events/s; JSON decoding dominates) |

Full pipeline: parse, detect, de-duplicate, correlate and hash, single core, in-memory store.

---

## 6. Quality gates

| Gate | Status |
|---|---|
| `go test ./...`, fixture + dataset integration tests | Pass |
| `golangci-lint` v2.5.0 (`.golangci.yml`) | 0 issues |
| `gosec` v2.22.8 | 0 issues (1 justified `#nosec`: seeded `math/rand` in the test-data generator) |
| GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) | Workflow added. Runs gofmt, build, and tests (race detector, Linux + Windows), golangci-lint and gosec. **Its first green run on GitHub happens on the next push.** |

Integration tests assert each dataset's alert counts stay in a known range ([`internal/pipeline/integration_test.go`](internal/pipeline/integration_test.go)). A change that moves a number outside its range fails CI until this report is updated.

---

## 7. Known gaps carried into Phase 2

1. **Time-based Anomaly is the dominant false-positive source** on real data (431 on loghub-linux). It needs per-host behavioural baselines (Phase 2.1).
2. **The rpc.statd format-string exploit in loghub-linux is not detected.** There is no rule for format-string or shellcode patterns.
3. **Correlation is single-key** (host + IP). Cross-host and cross-source correlation is Phase 2.2.
4. **No EVTX binary parser**, and BOTS isn't ingested yet.
5. **Year inference assumes the file's mtime** is close to its last entry. Copies that don't preserve mtime need to be checked manually (`year_inferred` is recorded on every entry).
