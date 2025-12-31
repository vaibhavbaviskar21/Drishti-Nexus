# Drishti Nexus

**Portable Security Log Analysis Tool for Air-Gapped Networks**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/yourusername/drishti-nexus)
[![Go](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A self-contained, offline-first log analysis tool designed for isolated networks and incident response.

---

## Quick Start

### Installation

**Windows:**
```powershell
# Download drishti.exe
# No installation required - just run
.\drishti.exe help
```

**From Source:**
```bash
git clone <repository-url>
cd DrishtiNexus
go build -ldflags="-s -w" -o drishti.exe .
```

### Basic Usage

```powershell
# Live monitoring
.\drishti.exe tail auth.log

# Historical analysis
.\drishti.exe analyze syslog

# Batch export
.\drishti.exe scan access.log -output report.json

# Web dashboard
.\drishti.exe serve -port 8080 -log test.log
```

---

## Features

✅ **Single Executable** - 7MB binary, no dependencies  
✅ **Offline-First** - 100% air-gap compatible  
✅ **Multi-Format** - Auto-detects Syslog, JSON, Apache, Generic  
✅ **6 Detection Rules** - Focused, high-impact security detection  
✅ **Dual Interface** - CLI and web dashboard  
✅ **Configurable** - USB-updatable rules via `config.yaml`  

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
- 📖 **[ABSTRACT.md](ABSTRACT.md)** - Project overview (500 words)
- 🏗️ **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical architecture
- 🔍 **[RULES.md](RULES.md)** - Detection rule details
- 🎥 **[DEMO_SCRIPT.md](DEMO_SCRIPT.md)** - Video demo guide

### Additional Resources
- 📚 [docs/GUIDE.md](docs/GUIDE.md) - Educational walkthrough
- 📋 [docs/](docs/) - Development documentation

---

## Technical Specifications

| Aspect | Details |
|--------|---------|
| **Language** | Go 1.21+ |
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

**See [LIMITATIONS.md](LIMITATIONS.md) for comprehensive details.**

---

## Design Philosophy

Drishti Nexus deliberately prioritizes **simplicity, explainability, and offline reliability** over scale and automation.

**Key Design Decisions:**

1. **Deterministic Rules Over ML** - Explainable, no training data needed
2. **In-Memory Over Database** - Zero setup, excellent performance
3. **Single Binary Over Microservices** - True portability
4. **Manual Updates Over Auto-Update** - Works in isolated networks
5. **Offline-First Over Cloud** - Security in air-gapped environments

*Better to have a simple, reliable tool that works in isolated environments than a complex solution requiring constant connectivity.*

---

## Configuration

Edit `config.yaml` to customize:

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

**Updates**: Copy `config.yaml` to target system via USB, restart tool.

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
- Go 1.21 or higher
- Windows/Linux/macOS

### Build Commands

**Windows:**
```powershell
go build -ldflags="-s -w" -o drishti.exe .
```

**Linux/macOS:**
```bash
make build
# or
go build -ldflags="-s -w" -o drishti .
```

**Cross-platform:**
```bash
make build-all
```

---

## Project Structure

```
DrishtiNexus/
├── drishti.exe        # Single executable
├── config.yaml        # Detection rules
├── test.log           # Sample data
├── README.md          # This file
├── ARCHITECTURE.md    # Technical docs
├── RULES.md           # Rule details
├── ABSTRACT.md        # Project abstract
├── internal/          # Source code
│   ├── models/        # Data structures
│   ├── parser/        # Log parsers
│   ├── storage/       # In-memory storage
│   ├── detection/     # Detection engine
│   ├── cli/           # CLI commands
│   └── web/           # Web dashboard
└── docs/              # Additional documentation
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
