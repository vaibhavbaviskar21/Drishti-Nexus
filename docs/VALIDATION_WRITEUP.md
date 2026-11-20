# Drishti Nexus on Public Attack Data: What It Catches, What It Misses

*Draft for the Phase 4 public write-up. The practitioner feedback section stays empty until real sessions happen ([FEEDBACK_LOG.md](../FEEDBACK_LOG.md)).*

Drishti Nexus is a single offline binary that parses security logs, detects attacks with deterministic, explainable rules, and keeps a chain of custody for every result. We ran it against public datasets with known activity and against a benign set where every alert is by definition a false positive. Every number below is reproducible from the repository ([BASELINE.md](../BASELINE.md), `benchmarks/results/phase2.json`).

## Headline numbers

- **Known attack behaviours detected: 6 of 7 (86%)** across the public datasets (table below).
- **False positives: 0.92 per 1,000 benign log lines** (46 on a 50,000-line benign week), down from 569.9 in the original build.
- **Parse coverage: 100% structured** on every benchmark dataset. CEF, LEEF, CSV, Windows XML and YAML-defined formats are parsed as well.
- **Throughput: ~35,000 syslog lines/s sustained (≈3 billion lines/day) and ~2,600 Windows JSON events/s**, single-threaded on a 2-core i3 laptop with flat memory (10 MB peak heap after 6.5 M lines; see BASELINE §0.4).

## Ground truth and results

The "known behaviours" are what each dataset's publisher documents it contains. We did not label them ourselves after seeing the tool's output.

| Dataset (publisher) | Documented behaviour | Detected? | By |
|---|---|---|---|
| Mordor `empire_mimikatz_logonpasswords` (OTRF) | Credential dumping from LSASS | ✅ 1 alert, the exact access event | Sigma: LSASS read with dumping rights (T1003.001) |
| same | Empire PowerShell stager execution | ✅ | Suspicious Command Execution (T1059) |
| Mordor `empire_psexec_dcerpc_tcp_svcctl` (OTRF) | Remote service creation (PsExec technique) | ✅ Empire's `Updater` service | Sigma: service running encoded PowerShell (T1569.002) |
| same | PowerShell/cmd execution on the target | ✅ | Suspicious Command Execution |
| same | **Lateral movement WORKSTATION5 → WORKSTATION6 as one linked incident** | ❌ | The cross-host rule needs a brute force first; this movement used valid credentials |
| LogHub Linux | rpc.statd format-string exploit (CVE-2000-0666) | ✅ all 7 attempts, 0 false positives | Sigma: format-string exploitation (T1190) |
| LogHub OpenSSH | Internet SSH brute force, including one successful guess | ✅ 554 attacking IPs alerted; the success (`curi` from 123.255.103.142) flagged as Brute Force | Excessive Failures / Brute Force (T1110) |

## Where the false positives come from

| Rule | Alerts on 50k benign lines | Why |
|---|---:|---|
| Time-based Anomaly | 38 | Off-hours activity on hosts whose first 3 days of history are still being learned. After that, a host's own normal hours are used. |
| Excessive Authentication Failures | 8 | Bursts of console-login failures that our generator emits unrealistically often |
| Everything else (incl. Sigma) | 0 | |

## What practitioners told us

*Pending. No sessions have taken place yet.*

## Honest limitations

- **Cross-host correlation covers one pattern:** brute force on A, then a login on B. Lateral movement with already-valid credentials (as in the PsExec dataset) is detected per host, not linked.
- **Sigma support is a subset.** `count()` aggregations work; `near`, `<` thresholds and other aggregation functions do not. Unsupported rules are skipped and listed, never half-applied.
- **Splunk BOTS isn't ingested yet** (it ships as Splunk indexes, not raw logs).
- **Baselines start empty.** The first days of any analysis use static thresholds and hours.
- Full list: [LIMITATIONS.md](LIMITATIONS.md).

## Reproduce

```bash
bash scripts/fetch-datasets.sh && make genbenign
go run ./cmd/benchmark -suite -sigma rules/sigma -out results.json
go test ./internal/pipeline/ -run 'Integration' -v    # asserts every number above stays in range
```
