# Drishti Nexus - Technical Architecture

> **Phase 1 changes (2026-10).** Every command now runs the shared pipeline in `internal/pipeline`:
> 1. Hash the evidence (`internal/audit`).
> 2. Open it read-only.
> 3. Run `LineReader` → `ParserRegistry`, which assembles multi-line records and normalises time to UTC.
> 4. Run the detection `Engine` (event-time windows, aggregation, incidents).
> 5. Write to storage: in-memory, or SQLite with `-db`.
> 6. Re-verify hashes and append to the audit log.
>
> The binary lives in `cmd/drishti`. See [CHAIN_OF_CUSTODY.md](CHAIN_OF_CUSTODY.md) for the custody design, [RULES.md](RULES.md) for current rule behaviour, and [../BASELINE.md](../BASELINE.md) for measured performance. Sections below that describe the original design still apply except where these documents say otherwise.

---

## System Overview

Drishti Nexus is a portable log analysis tool consisting of:
- Log parsing engine (4 parsers)
- In-memory storage with indexes
- Detection engine (6 rules)
- CLI interface (4 commands)
- Web dashboard with WebSocket support

**Design Philosophy**: Offline-first, single-binary, deterministic detection.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────┐
│            Log Sources                      │
│   (Syslog, JSON, Apache, Generic)           │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│         Parser Engine                       │
│  • Auto-detection                           │
│  • Format normalization                     │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│      In-Memory Storage & Indexing           │
│  • Time-based buckets                       │
│  • Source indexing                          │
│  • LRU eviction (100k default)              │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│       Detection Engine                      │
│  • 6 rule-based detectors                   │
│  • Pattern matching                         │
│  • Stateful tracking                        │
└──────────────────┬──────────────────────────┘
                   │
       ┌───────────┴───────────┐
       │                       │
┌──────▼─────┐         ┌───────▼────────┐
│ CLI Output │         │  Web Dashboard │
│            │         │  (WebSocket)   │
└────────────┘         └────────────────┘
```

---

## Component Structure

```
DrishtiNexus/
├── main.go                 # Entry point, CLI routing
├── config.yaml             # Detection rules configuration
│
├── internal/
│   ├── models/             # Data structures
│   │   └── log_entry.go    # LogEntry, Alert, Config
│   │
│   ├── parser/             # Log format parsing
│   │   ├── parser.go       # Parser interface & registry
│   │   ├── syslog.go       # RFC 3164/5424 syslog
│   │   ├── json.go         # JSON logs
│   │   ├── apache.go       # Apache/Nginx access logs
│   │   └── generic.go      # Fallback parser
│   │
│   ├── storage/            # In-memory data management
│   │   ├── memory.go       # Storage with LRU eviction
│   │   └── export.go       # JSON/CSV export
│   │
│   ├── detection/          # Threat detection
│   │   ├── engine.go       # Detection coordinator
│   │   └── rules.go        # 6 detection rule implementations
│   │
│   ├── cli/                # Command-line interface
│   │   ├── tail.go         # Live monitoring
│   │   ├── analyze.go      # Historical analysis
│   │   └── scan.go         # Batch processing
│   │
│   └── web/                # Web interface
│       ├── server.go       # HTTP & WebSocket server
│       ├── templates/
│       │   └── index.html  # Dashboard HTML
│       └── static/
│           ├── css/style.css   # Styles
│           └── js/app.js       # Client logic
│
└── test.log                # Sample data
```

---

## Data Model

### LogEntry (Normalized)
```go
type LogEntry struct {
    ID        string                 // Unique identifier
    Timestamp time.Time              // Parsed timestamp
    Source    string                 // Hostname or IP
    Facility  string                 // Log source type
    Severity  Severity               // 0-7 severity level
    Message   string                 // Parsed message
    RawLog    string                 // Original line
    Fields    map[string]interface{} // Extracted fields
    Tags      []string               // Categorization
}
```

### Alert
```go
type Alert struct {
    ID          string
    Timestamp   time.Time
    RuleName    string                 // Which rule detected it
    Severity    string                 // critical/high/medium/low
    Description string
    RelatedLogs []string               // Log entry IDs
    Details     map[string]interface{}
    Count       int                    // Occurrences
}
```

---

## Parser Engine

### Supported Formats

1. **Syslog (RFC 3164)**: `<PRI>Month DD HH:MM:SS host tag: message`
2. **Syslog (RFC 5424)**: `<PRI>VERSION TIMESTAMP HOST APP PROCID MSGID SD MESSAGE`
3. **JSON**: Flexible field extraction (timestamp, level, message, source)
4. **Apache/Nginx**: Common and Combined log formats
5. **Generic**: Fallback for unrecognized formats

### Parser Selection

```
Input log line
  ↓
Try SyslogParser.CanParse()
  ↓ (if yes)
SyslogParser.Parse()
  ↓ (if no)
Try JSONParser.CanParse()
  ↓ (if yes)
JSONParser.Parse()
  ↓ (continue...)
```

Auto-detection based on line structure.

---

## Storage Layer

### In-Memory Storage

- **Data structure**: Slice of pointers to LogEntry
- **Capacity**: 100,000 entries (default, configurable)
- **Eviction**: LRU - oldest 20% removed when full
- **Memory usage**: 500B - 2KB per entry = 50-200 MB typical

### Indexes

1. **Time-based**: `map[timeBucket][]*LogEntry`
   - Bucket format: "2006-01-02T15" (hourly)
   - Fast time-range queries

2. **Source-based**: `map[source][]*LogEntry`
   - Fast per-host queries

### Concurrency

- Thread-safe via `sync.RWMutex`
- Read lock for queries
- Write lock for additions/evictions

---

## Detection Engine

### Detection Rules (6 Total)

| Rule | Type | Stateful | Configurable |
|------|------|----------|--------------|
| Authentication Brute Force | Pattern | Yes | threshold, time_window |
| Excessive Auth Failures | Threshold | Yes | threshold, time_window |
| Privilege Escalation | Pattern | No | enabled/disabled |
| Suspicious Commands | Pattern | No | enabled/disabled |
| SQL/Command Injection | Signature | No | enabled/disabled |
| Time-based Anomaly | Time | No | normal_hours |

### Detection Flow

```
LogEntry
  ↓
For each rule:
  ↓
  rule.Analyze(entry)
  ↓
  Returns Alert or nil
  ↓
Aggregate alerts
  ↓
Store in AlertStorage
```

### State Tracking

Stateful rules maintain:
- `failedLogins map[string][]time.Time` - Track failures per source
- `authEvents map[string]*AuthTracker` - Track auth patterns
- Cleaned periodically (old entries removed)

---

## CLI Commands

### 1. tail
- **Purpose**: Live log monitoring
- **Usage**: `drishti tail <logfile>`
- **Output**: Colorized terminal output with inline alerts
- **Performance**: Real-time line-by-line processing

### 2. analyze
- **Purpose**: Historical analysis
- **Usage**: `drishti analyze <logfile>`
- **Output**: Statistical report with alert summary
- **Performance**: Batch processing of entire file

### 3. scan
- **Purpose**: Batch processing with export
- **Usage**: `drishti scan <logfile> [-output <file>]`
- **Output**: JSON + CSV files
- **Use case**: Offline report generation

### 4. serve
- **Purpose**: Web dashboard
- **Usage**: `drishti serve [-port 8080] [-log <file>]`
- **Output**: HTTP server on specified port
- **Features**: REST API + WebSocket updates

---

## Web Interface

### Technology Stack
- **Backend**: gorilla/mux (routing), gorilla/websocket
- **Frontend**: Vanilla JavaScript (no frameworks)
- **Assets**: Embedded in binary via `go:embed`

### API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Serve dashboard HTML |
| `/api/stats` | GET | Statistics (JSON) |
| `/api/logs` | GET | Recent logs (JSON) |
| `/api/alerts` | GET | All alerts (JSON) |
| `/api/ws` | WebSocket | Real-time updates |

### WebSocket Protocol

```
Client connects → Server accepts
  ↓
New log processed → Server detects alert
  ↓
Server.BroadcastUpdate(alert)
  ↓
All connected clients receive update
```

Push-based updates (no polling required).

---

## Build Process

### Single Binary Compilation

```bash
go build -ldflags="-s -w" -o drishti.exe .
```

**Flags**:
- `-s`: Strip debugging symbols
- `-w`: Strip DWARF debug info
- Result: ~7 MB executable

### Embedded Assets

```go
//go:embed templates/* static/*
var embeddedFS embed.FS
```

HTML, CSS, JS files compiled into binary.

### Cross-platform

```bash
GOOS=windows GOARCH=amd64 go build ...  # Windows
GOOS=linux GOARCH=amd64 go build ...    # Linux
GOOS=darwin GOARCH=amd64 go build ...   # macOS
```

Same code, different targets.

---

## Configuration

### config.yaml Structure

```yaml
rules:
  - name: "Rule Name"
    enabled: true/false
    severity: "low|medium|high|critical"
    threshold: <number>         # Optional
    time_window: "5m|10m|1h"    # Optional

normal_hours:
  start: 9    # 0-23
  end: 17     # 0-23

max_log_entries: 100000
```

**Load process**:
1. Read config.yaml on startup
2. Parse YAML → Config struct
3. Pass to detection engine
4. Rules initialized based on config

**Update process**:
1. Edit config.yaml
2. Copy to target system (USB if air-gapped)
3. Restart drishti
4. New config loaded

---

## Performance Profile

### Benchmarks (Tested)

| Operation | Speed | Hardware |
|-----------|-------|----------|
| Log parsing | 50k logs/sec | Modern CPU, mixed formats |
| Detection | 50k logs/sec | 6 rules enabled |
| Memory usage | 100-500 MB | 100k logs |
| Binary size | 6.81 MB | Embedded assets included |

**Factors affecting performance**:
- Log format complexity (regex vs simple parsing)
- Number of enabled rules
- Hardware (CPU, RAM speed)
- Stateful rule state size

---

## Security Considerations

### What This Tool Analyzes
- Log file **content** only
- No network traffic capture
- No endpoint monitoring
- No active scanning

### Isolation Model
- Reads files (read-only)
- Writes exports (user-specified location)
- No network connections (except `serve` mode on localhost)
- No privilege escalation required

### Air-gap Compatibility
- Zero external dependencies
- No internet required
- Config updates via file copy
- Portable binary

---

## Limitations

### By Design
- **Not a SIEM**: Single log file at a time, limited retention
- **Not an IDS**: No network packet analysis
- **Not an EDR**: No endpoint agents
- **Not cloud-based**: Completely offline

### Technical
- **Memory cap**: 100k logs default (configurable)
- **No hot reload**: Restart required for config changes
- **Single-threaded parsing**: Sequential log processing
- **No persistence**: In-memory only, cleared on exit

See [LIMITATIONS.md](LIMITATIONS.md) for comprehensive details.

---

## Extension Points

### Adding a New Parser

1. Implement `Parser` interface:
   ```go
   type Parser interface {
       Parse(line string) (*LogEntry, error)
       CanParse(line string) bool
       Name() string
   }
   ```

2. Register in `ParserRegistry`:
   ```go
   parsers: []Parser{
       NewSyslogParser(),
       NewYourParser(),  // Add here
   }
   ```

### Adding a New Detection Rule

1. Implement `DetectionRule` interface:
   ```go
   type DetectionRule interface {
       Analyze(entry *LogEntry) *Alert
       Name() string
   }
   ```

2. Register in `Engine.initializeRules()`:
   ```go
   rules: []DetectionRule{
       &YourDetector{engine: e},  // Add here
   }
   ```

3. Add config in `config.yaml`

---

## Dependencies

### External Libraries

| Library | Purpose | Why |
|---------|---------|-----|
| `github.com/gorilla/mux` | HTTP routing | Mature, simple router |
| `github.com/gorilla/websocket` | WebSocket support | Real-time updates |
| `github.com/fatih/color` | Terminal colors | CLI readability |
| `gopkg.in/yaml.v3` | YAML parsing | Config file format |

### Standard Library

Heavy use of Go standard library:
- `encoding/json` - JSON handling
- `time` - Timestamp parsing
- `regexp` - Pattern matching
- `net/http` - Web server
- `bufio` - File reading
- `sync` - Concurrency primitives

---

## Development Workflow

### Directory Structure Rationale

- `internal/` - Private packages (not importable externally)
- `models/` - Shared data structures
- `parser/`, `storage/`, `detection/` - Domain separation
- `cli/`, `web/` - Interface layers

### Testing Strategy

- Unit tests for parsers (format detection, extraction)
- Unit tests for detection rules (pattern matching)
- Integration test with `test.log`
- Manual verification via all 4 CLI commands

---

## Deployment

### Minimal Deployment

1. Copy `drishti.exe` to target system
2. Create `config.yaml` (or use defaults)
3. Run commands

**No installation, no setup, no dependencies.**

### Air-gapped Deployment

1. Build on internet-connected machine
2. Copy binary + config to USB drive
3. Transfer to air-gapped system
4. Execute directly

---

## References

- [README.md](../README.md) - User documentation
- [RULES.md](../RULES.md) - Detection rule details
- [LIMITATIONS.md](LIMITATIONS.md) - Scope and constraints
