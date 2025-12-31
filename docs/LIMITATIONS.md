# Drishti Nexus - Limitations

---

## What Drishti Nexus Is NOT

This document explicitly states what Drishti Nexus **does not do** and **is not designed for**.

---

### ❌ NOT a SIEM (Security Information and Event Management)

**What SIEMs do:**
- Centralized log aggregation from hundreds/thousands of sources
- Long-term log retention (months/years)
- Complex correlation across multiple systems
- Compliance reporting
- User behavior analytics
- Advanced dashboards and visualizations
- Integration with ticketing systems
- Automated workflow orchestration

**What Drishti Nexus does:**
- ✅ Single log file analysis at a time
- ✅ In-memory storage (100k log limit by default)
- ✅ 6 basic detection rules
- ✅ Simple web dashboard
- ✅ Offline operation

**Bottom line:** Drishti Nexus is a **log triage tool**, not an enterprise SIEM.

---

### ❌ NOT an IDS (Intrusion Detection System)

**What IDS does:**
- Monitors network traffic in real-time
- Deep packet inspection (DPI)
- Protocol analysis
- Signature-based network attack detection
- Anomaly-based traffic analysis
- Inline blocking (IPS mode)

**What Drishti Nexus does:**
- ❌ Does NOT capture network packets (PCAP)
- ❌ Does NOT analyze network traffic
- ❌ Does NOT perform deep packet inspection
- ✅ Only analyzes network-related events **as observed in log files** (firewall logs, proxy logs)

**Bottom line:** Drishti Nexus analyzes **log entries**, not **network packets**.

---

### ❌ NOT an EDR (Endpoint Detection and Response)

**What EDR does:**
- Endpoint agent deployment
- Real-time process monitoring
- File integrity monitoring (FIM)
- Memory analysis
- Behavioral detection
- Automated response and remediation
- Threat hunting across endpoints

**What Drishti Nexus does:**
- ❌ No agents or endpoint monitoring
- ❌ No real-time process tracking
- ❌ No automated response
- ✅ Only analyzes logs that may contain endpoint events (Windows Event Logs, syslog)

**Bottom line:** Drishti Nexus is **passive log analysis**, not **active endpoint monitoring**.

---

### ❌ NOT a Cloud Service

**What cloud security services do:**
- Hosted infrastructure
- Automatic updates
- Centralized management
- API-based integrations
- Threat intelligence feeds
- Multi-tenancy
- Scalability to millions of events

**What Drishti Nexus does:**
- ✅ **Completely offline** - no internet required
- ✅ Runs locally on single machine
- ✅ No external APIs or cloud dependencies
- ✅ Updates via file copy (USB/removable media)

**Bottom line:** Drishti Nexus is **air-gap compatible**, not cloud-dependent.

---

## Specific Capability Limitations

### 1. No Network Traffic Analysis

**Drishti Nexus does NOT:**
- Capture network packets (PCAP/pcapng)
- Analyze NetFlow/IPFIX/sFlow
- Perform protocol decoding
- Reconstruct TCP streams
- Extract files from network traffic

**Drishti Nexus DOES:**
- Parse firewall logs for blocked/allowed connections
- Detect patterns in web server access logs
- Identify suspicious activity in proxy logs

**Scope:** Log-based network event analysis only.

---

### 2. No Threat Intelligence Integration

**Drishti Nexus does NOT:**
- Query external threat feeds (STIX/TAXII)
- Lookup IP reputation services
- Check against malware databases
- Integrate with threat intelligence platforms (TIPs)
- Download IOC (Indicators of Compromise) lists

**Drishti Nexus DOES:**
- Use static pattern matching for known attack signatures
- Detect common attack patterns (SQL injection, command injection)

**Scope:** Built-in, static detection rules only. No external lookups.

---

### 3. No Advanced Correlation

**Drishti Nexus does NOT:**
- Correlate events across multiple log sources automatically
- Build attack timelines spanning days/weeks
- Track multi-stage attack chains
- Perform root cause analysis
- Map to MITRE ATT&CK framework

**Drishti Nexus DOES:**
- Track stateful patterns within one log stream (e.g., failed → success login)
- Detect immediate threats in individual log entries

**Scope:** Simple, deterministic rule-based detection on single log files.

---

### 4. No Machine Learning / AI

**Drishti Nexus does NOT:**
- Build behavioral baselines
- Use anomaly detection via ML models
- Perform predictive analysis
- Adapt detection rules automatically
- Cluster similar events

**Drishti Nexus DOES:**
- Use threshold-based anomaly detection (e.g., >5 failed logins)
- Apply time-based anomaly detection (activity outside normal hours)

**Scope:** Deterministic, explainable detection only. No black-box ML.

---

### 5. No Automated Response

**Drishti Nexus does NOT:**
- Block IP addresses
- Quarantine endpoints
- Terminate processes
- Modify firewall rules
- Send alerts to external systems

**Drishti Nexus DOES:**
- Detect and display alerts
- Export findings to JSON/CSV for manual review

**Scope:** Detection and reporting only. No automated remediation.

---

### 6. No Real-time Alerting

**Drishti Nexus does NOT:**
- Send email/SMS/Slack notifications
- Integrate with SOAR platforms
- Trigger webhooks
- Create tickets in ticketing systems

**Drishti Nexus DOES:**
- Display alerts in terminal (CLI mode)
- Show alerts in web dashboard
- Export alerts to CSV for review

**Scope:** On-screen alerts and file export only.

---

### 7. No Distributed Architecture

**Drishti Nexus does NOT:**
- Run across multiple servers
- Aggregate logs from multiple collectors
- Scale horizontally
- Support clustering or high availability

**Drishti Nexus DOES:**
- Run as single process on one machine
- Analyze one log file at a time

**Scope:** Single-node, single-user tool.

---

### 8. No Log Forwarding / Collection

**Drishti Nexus does NOT:**
- Collect logs from remote systems
- Listen on syslog port (UDP 514)
- Poll log APIs
- Parse Windows Event Channels directly

**Drishti Nexus DOES:**
- Read log files that you provide manually
- Parse various log formats once they're in a file

**Scope:** Bring your own log files. No active collection.

---

## Memory and Performance Limitations

### Memory Model

**Realistic Estimates:**
- Each log entry: **500 bytes to 2 KB** (depending on message length and extracted fields)
- Default capacity: **100,000 log entries**
- Estimated memory usage: **50 MB to 200 MB** for logs alone
- Total process memory: **100 MB to 500 MB** (includes indexes, alerts, application overhead)

**Cap:**
- Hard limit: Configurable via `max_log_entries` in `config.yaml`
- Default: 100,000 entries
- Eviction: LRU (Least Recently Used) - oldest 20% removed when limit reached
- Warning: Displays message when eviction occurs

**Not suitable for:**
- Millions of log entries (use a real SIEM)
- Long-term log retention (days/weeks)
- Continuous 24/7 operation with log accumulation

**Suitable for:**
- Triage of recent logs (hours to days)
- Incident investigation on specific log files
- Portable analysis in isolated environments

---

### Processing Limitations

**Performance:**
- Parsing speed: ~50,000 logs/second (tested)
- Detection speed: ~50,000 logs/second (simple rules)
- Web dashboard: Real-time for <100k logs, may lag with larger datasets

**Not suitable for:**
- Real-time analysis of high-volume log streams (>100k logs/second)
- Continuous processing of growing log files (use `tail -f` with pipe instead)

**Suitable for:**
- Batch processing of log files (5k to 500k entries)
- Interactive analysis via web dashboard
- Quick scans of specific time windows

---

## Update and Maintenance Limitations

### Offline Updates

**How updates work:**
1. Edit `config.yaml` on a connected machine
2. Copy file to USB drive
3. Transfer to air-gapped system
4. Replace `config.yaml`
5. Restart Drishti Nexus

**Limitations:**
- ❌ No automatic updates
- ❌ No hot reload of rules (must restart)
- ❌ No version checking or update notifications

**Scope:** Manual file-based configuration updates only.

---

### Rule Extensibility

**What you can do:**
- Enable/disable existing 6 rules
- Adjust thresholds and time windows
- Modify normal hours for time-based anomaly

**What you CANNOT do (without code changes):**
- Add new detection rules via config alone
- Create complex correlation logic
- Define custom log parsers

**Scope:** Configuration tuning of existing rules. New rules require Go code changes and recompilation.

---

## Deployment Limitations

### Single Binary, But...

**What "single binary" means:**
- ✅ All code and web assets embedded in .exe
- ✅ No separate DLL files or dependencies
- ✅ No installation required

**What it does NOT mean:**
- ❌ No automatic service installation
- ❌ No Windows Service or systemd integration
- ❌ No startup scripts included

**Scope:** Portable executable, but manual deployment.

---

### Platform Support

**Tested:**
- ✅ Windows (x64)

**Theoretically supported (untested):**
- Linux (x64, ARM)
- macOS (x64, M1/M2)

**Not supported:**
- 32-bit systems
- Embedded systems (Raspberry Pi may work but untested)

---

## Use Case Fit

### ✅ Good Use Cases

- **Incident response**: Analyze logs from compromised system
- **Security audit**: Quick triage of server logs
- **Training**: Learn log analysis and security detection
- **Air-gapped environments**: Analyze logs without internet
- **Portable toolkit**: USB-bootable security analysis

### ❌ Bad Use Cases

- **Enterprise SOC**: Use Splunk, ELK, QRadar instead
- **Real-time monitoring**: Use IDS/IPS or SIEM
- **Compliance logging**: Use certified SIEM solutions
- **Long-term retention**: Use log management platforms
- **High-volume streams**: Use stream processing (Kafka, etc.)

---

## Comparison Table

| Feature | SIEM | IDS/IPS | EDR | Drishti Nexus |
|---------|------|---------|-----|---------------|
| Log aggregation | ✅ Multi-source | ❌ | ✅ | ❌ Single file |
| Network traffic analysis | Partial | ✅ | ❌ | ❌ |
| Endpoint monitoring | Via agents | ❌ | ✅ | ❌ |
| Real-time alerting | ✅ | ✅ | ✅ | ❌ |
| Long-term storage | ✅ | Partial | ✅ | ❌ (100k cap) |
| Automated response | Partial | ✅ | ✅ | ❌ |
| Offline operation | ❌ | Partial | ❌ | ✅ |
| Single binary | ❌ | ❌ | ❌ | ✅ |
| Air-gap compatible | ❌ | Partial | ❌ | ✅ |
| Cost | $$$$$ | $$$$ | $$$$ | Free |
| Setup complexity | High | Med-High | Med-High | None |
| Target users | Enterprises | Enterprises | Enterprises | Individuals, SMBs |

---

## Summary

**Drishti Nexus is a focused, portable log triage tool designed for:**
- Air-gapped and isolated networks
- Incident response and forensic analysis
- Quick security assessments
- Educational purposes
- Environments where traditional SIEM/IDS/EDR is overkill or unavailable

**Drishti Nexus is NOT designed for:**
- Enterprise-scale security operations
- Real-time threat prevention
- Comprehensive compliance monitoring
- Production security monitoring
- Network traffic analysis

**Know the limitations. Use the right tool for the right job.**
