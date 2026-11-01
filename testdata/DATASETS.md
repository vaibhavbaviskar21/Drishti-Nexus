# Benchmark & Test Datasets

```
testdata/
├── DATASETS.md                 ← this file
├── fixtures/                   ← small, committed; every test run uses them
│   ├── sample_auth.log         ← 21-line auth log with one of each attack type
│   ├── edge_cases.log          ← BOM, CRLF, Latin-1, NUL, multi-line/malformed JSON, stack trace, RFC 5424, Apache injection
│   └── loghub_openssh_2k.log   ← first 2,000 lines of LogHub OpenSSH
├── benign/
│   └── auth_benign.log         ← generated: make genbenign (gitignored, deterministic)
└── datasets/                   ← fetched: make datasets (gitignored, SHA-256 pinned)
    ├── loghub-ssh/SSH.log
    ├── loghub-linux/Linux.log
    └── mordor/*.json
```

## Getting the data

```bash
make datasets     # bash scripts/fetch-datasets.sh: downloads, verifies SHA-256, extracts
make genbenign    # go run ./cmd/genbenign: byte-identical on every run
```

Integration tests (`internal/pipeline/integration_test.go`) skip any dataset that is missing. `go test -short` skips them all.

## Datasets

| Name | Lines | Source | License | What it is |
|---|---:|---|---|---|
| `loghub-ssh` | 655,147 | [LogHub](https://github.com/logpai/loghub) via [Zenodo 8196385](https://zenodo.org/records/8196385) `SSH.tar.gz` | Research use, see LogHub | Real sshd log from a lab server exposed to internet brute force |
| `loghub-linux` | 25,567 | LogHub, Zenodo 8196385 `Linux.tar.gz` | same | Real `/var/log/messages` from one host (2005): system noise, SSH/FTP brute force, one rpc.statd format-string exploit |
| `mordor/empire_mimikatz_logonpasswords_*.json` | 6,026 | [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) `atomic/windows/credential_access/host` | MIT | Windows Security/Sysmon/PowerShell events (JSON lines) during Empire Mimikatz `logonpasswords` |
| `mordor/empire_psexec_dcerpc_tcp_svcctl_*.json` | 4,348 | OTRF `atomic/windows/lateral_movement/host` | MIT | Windows events during Empire PsExec lateral movement |
| `benign/auth_benign.log` | 50,000 | `cmd/genbenign` (seed 42, end 2025-12-31, 7 days) | — | Synthetic auth.log/syslog, **benign by construction**, in chronological order. Every alert on it is a false positive |

Checksums are pinned in [`scripts/fetch-datasets.sh`](../scripts/fetch-datasets.sh). If an upstream file changes, the script fails instead of silently changing the benchmark.

## Not used (yet)

| Dataset | Why |
|---|---|
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | Binary `.evtx`; there is no EVTX parser. Windows coverage uses the Mordor JSON exports instead (agreed for Phase 1). To use these samples now, convert them to JSON lines first (e.g. `evtx_dump -o jsonl`). |
| [Splunk BOTS v1–v3](https://github.com/splunk/botsv3) | Distributed as pre-indexed Splunk data (multi-GB), not raw logs. Deferred to Phase 2/4. |

## Running the benchmark

```bash
go run ./cmd/benchmark -suite -out benchmarks/results/latest.json   # all datasets above
go run ./cmd/benchmark -file some.log                                 # one file
go run ./cmd/benchmark -suite -cpuprofile cpu.prof                    # with profiling
```

Phase results are committed under [`benchmarks/results/`](../benchmarks/results/) and summarised in [`BASELINE.md`](../BASELINE.md).

## Format fixtures (Phase 2.6)

| File | Source | License | What it pins |
|---|---|---|---|
| `fixtures/loghub_openssh_2k_structured.csv` | [LogHub](https://github.com/logpai/loghub) `OpenSSH/OpenSSH_2k.log_structured.csv`, verbatim (CRLF) | Research use, see LogHub | The same 2,000 events as `loghub_openssh_2k.log`, as CSV: alerts must match the raw log |
| `fixtures/loghub_windows_200_structured.csv` | LogHub `Windows/Windows_2k.log_structured.csv`, header + first 200 rows | same | Date+Time split timestamps |
| `fixtures/windows_events.xml` | Microsoft's documented example for event 4625 ("An account failed to log on"), with the docs page's tree markers removed; pretty-printed, then the same event on one line | Microsoft docs | Windows Event XML parsing and logon classification |
| `fixtures/cef_leef.log` | Written for the test | — | A brute force seen only in vendor CEF/LEEF raises the same alert as sshd |
