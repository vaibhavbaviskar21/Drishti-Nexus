# Drishti Nexus

## **Portable, Offline-First Security Log Analysis Tool for Air-Gapped Networks**

## 1. Introduction

Many critical infrastructure systems, military networks, and high-security environments operate in complete isolation from the internet, commonly known as **air-gapped networks**. While air-gapping enhances security, it also makes log analysis and security monitoring significantly more difficult.

Most enterprise SIEM solutions rely on centralized infrastructure, frequent updates, and complex deployment models, which are impractical in isolated environments. As a result, security teams often lack a **simple, portable, and offline-capable tool** for log analysis and incident response.

**Drishti Nexus** is designed to address this gap.

---

## 2. Solution Overview

Drishti Nexus is a **single-binary, offline-first security log analysis tool** developed in **Go (Golang)**. It runs without installation, external services, or internet connectivity, making it suitable for deployment in air-gapped and restricted environments.

The tool is packaged as a lightweight executable that can be deployed via removable media (such as USB drives) and executed instantly on isolated systems, providing **SOC-style visibility** without cloud dependency.

### Key Characteristics

- Fully offline operation
- Single executable (no dependencies)
- Portable deployment via removable media
- Explainable, rule-based detection logic
- Command-line and web-based interfaces

---

## 3. System Architecture

Drishti Nexus follows a lightweight and modular architecture focused on portability and performance.

### Core Components

- **Log Parser Engine**Automatically detects and normalizes multiple log formats, including Syslog, JSON, Apache/Nginx, and generic logs.
- **In-Memory Storage**Stores parsed logs with time-based and source-based indexing. Implements LRU eviction to manage memory usage efficiently.
- **Detection Engine**Applies deterministic, rule-based security detections designed for explainability and offline reliability.
- **User Interfaces**

  - CLI for real-time monitoring and batch analysis
  - Local web dashboard for interactive visualization and analysis

---

### 📌 Architecture Diagram

```text
┌─────────────────────────────────────────────┐
│               Log Sources                   │
│      (Syslog, JSON, Apache, Generic)        │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│              Parser Engine                  │
│  • Auto-detection                           │
│  • Format normalization                     │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│        In-Memory Storage & Indexing          │
│  • Time-based buckets                       │
│  • Source indexing                          │
│  • LRU eviction (100k default)              │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│             Detection Engine                │
│  • 6 rule-based detectors                   │
│  • Pattern matching                         │
│  • Stateful tracking                        │
└──────────────────┬──────────────────────────┘
                   │
          ┌────────┴────────┐
          │                 │
┌─────────▼────────┐ ┌──────▼─────────┐
│    CLI Output     │ │  Web Dashboard  │
│                  │ │   (WebSocket)   │
└──────────────────┘ └─────────────────┘
```

## 4. Detection Capabilities

Drishti Nexus implements **six high-impact security detection rules**:

1. Authentication brute-force attempts
2. Excessive authentication failures
3. Privilege escalation indicators
4. Suspicious command execution
5. SQL and command injection patterns
6. Time-based activity anomalies

All detection logic is **deterministic and explainable**, avoiding machine-learning dependencies that require internet access or training data.

Detection thresholds and rules are configurable and can be updated **offline via removable media**.

---

## 5. Functional Interface

Drishti Nexus provides four core operational modes:

- **tail** – Live log monitoring with color-coded severity output
- **analyze** – Quick historical log analysis with statistics
- **scan** – Batch processing with JSON/CSV report export
- **serve** – Local web dashboard with real-time updates

These modes support both **incident response** and **post-incident investigation** workflows.

---

## 6. Performance and Limitations

### Performance

- Processes tens of thousands of log entries per second
- Binary size: ~7 MB
- Memory usage: 100–500 MB depending on workload

### Limitations

- Not a full SIEM replacement
- No network packet capture or PCAP analysis
- No external threat intelligence feeds
- Designed for portable, time-bounded analysis rather than continuous monitoring

These limitations are intentional to preserve simplicity, portability, and offline reliability.

---

## 7. Applications and Impact

Drishti Nexus is well suited for:

- Security monitoring in air-gapped environments
- Incident response in restricted networks
- Security audits and forensic analysis
- Training and educational use
- Rapid log triage without infrastructure setup

By enabling **portable and offline security analysis**, the tool improves situational awareness in environments where traditional SIEM solutions cannot operate.

---

## 8. Conclusion

Drishti Nexus demonstrates that effective security log analysis can be achieved without cloud services or heavy infrastructure. By prioritizing **offline operation, portability, and explainable detection**, it provides a practical solution for security teams working in isolated environments.

The project combines systems engineering principles with real-world cybersecurity needs, making it both a functional tool and a strong technical showcase.

---
