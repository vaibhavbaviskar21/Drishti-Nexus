# Drishti Nexus  
**Portable, Offline Log Analysis Tool for Air-Gapped Environments**

Author: Vaibhav Baviskar  
Category: Cyber Security | Systems Engineering  
Technology: Go (Golang)

---

## 1. Introduction

Many critical infrastructure systems, military networks, and high-security environments operate in complete isolation from the internet, commonly known as **air-gapped networks**. While air-gapping improves security, it also makes log analysis and security monitoring significantly more difficult.

Most enterprise SIEM solutions depend on centralized infrastructure, agents, storage backends, and frequent updates. These requirements are often impractical in isolated or restricted environments. As a result, security teams are forced to rely on manual log inspection during incidents, which is slow and error-prone.

**Drishti Nexus** is designed to address this gap.

---

## 2. Solution Overview

Drishti Nexus is a **single-binary, offline-first security log analysis tool** developed in **Go (Golang)**. It runs without installation, agents, internet connectivity, or external services.

The tool is packaged as a lightweight executable (~7 MB) that can be deployed via removable media such as a USB drive and executed instantly on isolated systems. It provides **SOC-style log visibility** focused on fast triage and incident response rather than long-term log storage.

### Key Characteristics

- Fully offline operation  
- Single executable, no dependencies  
- Portable deployment via USB or removable media  
- Deterministic, rule-based detection  
- Command-line and local web interfaces  

---

## 3. High-Level Architecture

Drishti Nexus follows a lightweight, modular architecture optimized for portability and clarity.

### Core Components

- **Log Parsing Engine**  
  Automatically detects and normalizes multiple log formats including Syslog, JSON, Apache/Nginx, and generic text logs.

- **In-Memory Storage & Indexing**  
  Stores logs in memory with time-based and source-based indexing. Uses LRU eviction to control memory usage.

- **Detection Engine**  
  Applies deterministic, rule-based detections using thresholds, pattern matching, and short time-window correlations.

- **Output Interfaces**  
  Provides both CLI output and a local web dashboard for analysis.

---

## 4. Workflow (End-to-End)

**Log ingestion → Format detection → Normalization → In-memory indexing → Rule evaluation → Alerts & output**

---

## 5. Detection Engine

The detection engine is **fully deterministic and explainable**.

Logs are first normalized into a common structure. A fixed set of rules is then applied, including:

- Authentication brute-force patterns  
- Excessive authentication failures  
- Privilege escalation indicators  
- Suspicious command execution  
- SQL and command injection patterns  
- Time-based anomalies (off-hours activity)

Each alert is tied to a specific rule and threshold, making it easy to understand why it was triggered.

No machine learning models or external threat intelligence feeds are used.

---

## 6. Functional Interface

Drishti Nexus provides four primary operational modes:

### `tail`
Live log monitoring mode.  
Continuously reads logs and displays entries in real time with color-coded severity and immediate alert highlighting.

### `analyze`
Historical analysis mode.  
Processes a log file to generate summary statistics, severity distribution, and detected security events.

### `scan`
Batch processing mode.  
Analyzes logs in bulk and exports results in JSON and CSV formats for offline reporting and review.

### `serve`
Local web interface mode.  
Launches a lightweight web dashboard with real-time updates using WebSockets for interactive analysis.

---

## 7. Performance Characteristics

- Tested with **tens of thousands of log entries per run**
- In-memory processing for high speed
- LRU eviction when memory limits are reached
- Typical memory usage: **100–500 MB**, depending on workload
- Designed for **short, focused analysis sessions**, not long-term retention

---

## 8. Update Model (Offline)

Drishti Nexus does not rely on over-the-air updates.

Detection rules and configuration are externalized and updated using **approved removable media**, following standard air-gapped operational practices. This allows rules to be reviewed, tuned, and version-controlled offline based on new incident learnings.

---

## 9. Scope and Limitations

### Intended Use

- Portable log triage
- Incident response support
- Security audits in isolated environments
- Training and educational use

### Intentional Limitations

- Not a full SIEM replacement
- No packet capture or PCAP analysis
- No live threat intelligence feeds
- Not designed for continuous 24/7 monitoring

These limitations are deliberate to preserve portability, simplicity, and offline reliability.

---

## 10. Conclusion

Drishti Nexus demonstrates that effective security log analysis does not require cloud services or heavy infrastructure. By focusing on **offline operation, portability, and explainable detection**, it provides a practical solution for security teams working in air-gapped and restricted environments.

The project serves both as a functional security tool and as a systems engineering showcase built with real-world constraints in mind.

---

**Version:** 1.0.0  
**Binary Size:** ~7 MB  
**Language:** Go (Golang)  
**Execution Model:** Single executable, offline-first  

