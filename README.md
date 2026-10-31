# Drishti Nexus

**Portable Security Log Analysis Tool for Air-Gapped Networks**

[![CI](https://github.com/vaibhavbaviskar21/Drishti-Nexus/actions/workflows/ci.yml/badge.svg)](https://github.com/vaibhavbaviskar21/Drishti-Nexus/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.1.0--dev-blue.svg)](https://github.com/vaibhavbaviskar21/Drishti-Nexus)
[![Go](https://img.shields.io/badge/go-1.23+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A self-contained, offline-first log analysis tool designed for isolated networks and incident response.

---

# Quick Start

### Installation

**Windows:**
```powershell
# Download drishti.exe
# No installation required - just run
.\drishti.exe help
```

**From Source:**
```bash
git clone https://github.com/vaibhavbaviskar21/Drishti-Nexus.git
cd Drishti-Nexus
make build            # → bin/drishti (or: go build -o bin/drishti ./cmd/drishti)
```

### Basic Usage

```powershell
# Live monitoring (with -db, an interrupted session resumes where it stopped)
.\drishti.exe tail -db case.db auth.log

# Historical analysis (state the source host's timezone for logs without offsets)
.\drishti.exe analyze -tz Asia/Kolkata syslog

# Batch export: JSON + CSV, each carrying evidence hashes and the audit session
.\drishti.exe scan access.log -output report.json

# Web dashboard (localhost only by default)
.\drishti.exe serve -port 8080 -log testdata\fixtures\sample_auth.log

# Verify the tamper-evident audit trail
.\drishti.exe audit verify
```

---

## Features

✅ **Single Executable** - 7MB binary, no dependencies  
✅ **Offline-First** - 100% air-gap compatible  
✅ **Multi-Format** - Auto-detects Syslog, JSON, Apache, Generic  
✅ **6 Detection Rules** - Focused, high-impact security detection  
✅ **Dual Interface** - CLI and web dashboard  
✅ **Configurable** - USB-updatable rules via `configs/config.yaml` (or `config.yaml` next to the binary)  
✅ **Evidence-safe** - Read-only access, SHA-256 before/after, hash-chained audit log ([details](docs/CHAIN_OF_CUSTODY.md))  
✅ **Measured** - Benchmarked on public IR datasets every phase ([BASELINE.md](BASELINE.md))  

### Detection Rules

1. **Authentication Brute Force** - Failed → success patterns
2. **Excessive Failures** - Threshold-based detection
3. **Privilege Escalation** - Sudo, UAC, root indicators
4. **Suspicious Commands** - Shell spawning, encoded commands
5. **SQL/Command Injection** - Log-based pattern matching
6. **Time Anomaly** - Activity outside normal hours

---

## Documentation

### Essential Reading
- 📊 **[BASELINE.md](BASELINE.md)** - Measured parse rates, false positives and performance per phase
- 🔐 **[docs/CHAIN_OF_CUSTODY.md](docs/CHAIN_OF_CUSTODY.md)** - Evidence hashing and audit-trail design
- 🏗️ **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Technical architecture
- 🔍 **[docs/RULES.md](docs/RULES.md)** - Detection rule details
- ⚠️ **[docs/LIMITATIONS.md](docs/LIMITATIONS.md)** - What the tool does not do

### Additional Resources
- 🗺️ [Drishti_Nexus_Implementation_Plan.md](Drishti_Nexus_Implementation_Plan.md) - Phase-wise roadmap
- 🧪 [testdata/DATASETS.md](testdata/DATASETS.md) - Benchmark datasets
- 📋 [docs/](docs/) - Product strategy and project report

---

## Technical Specifications

| Aspect | Details |
|--------|---------|
| **Language** | Go 1.23+ (pure Go, no cgo) |
| **Binary Size** | 6.81 MB |
| **Memory** | 100-500 MB (100k log capacity) |
| **Performance** | Tens of thousands of logs/sec |
| **Formats** | Syslog, JSON, Apache/Nginx, Generic |
| **Deployment** | Single executable, no installation |

---

## What This Tool IS

✅ Portable log analysis for air-gapped networks  
✅ Incident response and security auditing  
✅ Offline-capable SOC-style triage tool  
✅ Single-binary, USB-transportable  

## What This Tool is NOT

❌ **NOT a SIEM** - No enterprise log aggregation  
❌ **NOT an IDS** - No network packet capture  
❌ **NOT an EDR** - No endpoint agents  
❌ **NOT cloud-based** - Completely offline  

**See [LIMITATIONS.md](docs/LIMITATIONS.md) for comprehensive details.**

---

## Design Philosophy

Drishti Nexus deliberately prioritizes **simplicity, explainability, and offline reliability** over scale and automation.

**Key Design Decisions:**

1. **Deterministic Rules Over ML** - Explainable, no training data needed
2. **In-Memory By Default** - Zero setup; optional SQLite (`-db`) for persistence and crash recovery
3. **Single Binary Over Microservices** - True portability
4. **Manual Updates Over Auto-Update** - Works in isolated networks
5. **Offline-First Over Cloud** - Security in air-gapped environments

*Better to have a simple, reliable tool that works in isolated environments than a complex solution requiring constant connectivity.*

---

## Configuration

Edit `configs/config.yaml` to customize (pass another file with `-config`):

```yaml
# Normal working hours (24-hour format)
normal_hours:
  start: 9
  end: 17

# Memory limit
max_log_entries: 100000

# Detection rules
rules:
  - name: "Authentication Brute Force"
    enabled: true
    severity: "high"
    threshold: 3
    time_window: "5m"
```

**Updates**: Copy `config.yaml` to the target system next to the binary via USB, restart the tool. The config file's SHA-256 and every effective threshold are recorded in the audit trail of each session.

---

## Example Output

### CLI Analysis
```
╔═══════════════════════════════════════════╗
║   Drishti Nexus - Log Analysis Report    ║
╚═══════════════════════════════════════════╝

SUMMARY STATISTICS
Total logs processed:   5,200
Processing rate:        55,430 logs/sec
Alerts detected:        1,800

SECURITY ALERTS
  🚨 Authentication Brute Force: 100
  ⚠️  Privilege Escalation: 1,000
  💉 Injection Patterns: 200
```

### Web Dashboard
- Real-time statistics and alerts
- Color-coded severity levels
- WebSocket live updates
- Clean, analyst-focused interface

---

## Use Cases

**Ideal For:**
- Incident response teams
- Security audits in isolated facilities
- Air-gapped network environments
- Portable security toolkits
- Training and education

**Not Suitable For:**
- 24/7 enterprise monitoring (use proper SIEM)
- Real-time threat prevention (use IDS/IPS)
- Network traffic analysis (use packet capture tools)

---

## Building from Source

### Requirements
- Go 1.23 or higher
- Windows/Linux/macOS

### Build Commands

**Windows:**
```powershell
.\scripts\build.ps1          # → bin\drishti.exe
```

**Linux/macOS:**
```bash
make build                  # → bin/drishti
```

**Tests, lint and benchmarks:**
```bash
make test                   # unit + integration (fetch datasets first for the full suite)
make datasets               # public datasets → testdata/datasets/ (checksum-pinned)
make benchmark              # → benchmarks/results/latest.json
make ci                     # gofmt + tests + golangci-lint + gosec (same as GitHub Actions)
```

**Cross-platform:**
```bash
make build-all
```

---

## Project Structure

```
DrishtiNexus/
├── cmd/
│   ├── drishti/           # The CLI binary (main package)
│   ├── benchmark/         # Benchmark harness → benchmarks/results/
│   └── genbenign/         # Deterministic benign dataset generator
├── internal/
│   ├── audit/             # Evidence hashing, read-only access, hash-chained audit log
│   ├── cli/               # scan / analyze / tail / audit commands
│   ├── config/            # Config loading
│   ├── detection/         # Rules, aggregation, incident correlation, state snapshots
│   ├── models/            # LogEntry, Alert, Config
│   ├── parser/            # Syslog (BSD/3164/5424), JSON, Apache, generic; time/DST handling
│   ├── pipeline/          # Shared ingest pipeline; tail follow + checkpoint/resume
│   ├── storage/           # In-memory and SQLite backends, JSON/CSV export
│   ├── version/           # Build version
│   └── web/               # Web dashboard (embedded assets)
├── configs/config.yaml    # Detection rules and settings
├── testdata/
│   ├── fixtures/          # Small committed logs used by tests
│   ├── benign/            # Generated benign set (make genbenign)
│   └── datasets/          # Fetched public datasets (make datasets, gitignored)
├── benchmarks/results/    # Committed benchmark results per phase
├── scripts/               # build.ps1, fetch-datasets.sh
├── docs/                  # Architecture, rules, custody design, limitations, report
├── BASELINE.md            # Phase-by-phase report card
└── Drishti_Nexus_Implementation_Plan.md
```

---

## Contributing

This is a focused, single-purpose tool. Extensions welcome:
- Additional log parsers (EVTX, CEF, custom)
- More detection rules (file access, DNS anomalies)
- Performance optimizations

**Out of scope**: ML models, distributed architecture, standalone GUI

---

## License

MIT License

---

Built for security professionals working in air-gapped and isolated network environments.

For detailed technical architecture, see [ARCHITECTURE.md](docs/ARCHITECTURE.md)
