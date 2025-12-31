# Drishti Nexus - Detection Rules Documentation

This document provides detailed information about each detection rule implemented in Drishti Nexus.

## Rule Overview

Drishti Nexus implements 6 core detection rules optimized for high-impact security events. All rules are:

- **Deterministic**: Produce consistent, explainable results
- **Log-based**: Operate on parsed log entries only
- **Configurable**: Can be tuned via `config.yaml`
- **Offline-capable**: No external dependencies or API calls

---

## 1. Authentication Brute Force

**Severity**: High  
**Type**: Pattern-based (Stateful)

### Description

Detects brute force authentication attacks by identifying a pattern of failed login attempts followed by a successful login from the same source.

### Logic

1. Track authentication events per source IP/host
2. Count failed login attempts within a 5-minute window
3. Alert when ≥3 failures are followed by a successful login

### Threshold

- **Default**: 3 failed attempts within 5 minutes
- **Configurable**: Yes (via `config.yaml`)

### Example Triggers

```
Failed password for admin from 192.168.1.100
Failed password for admin from 192.168.1.100
Failed password for admin from 192.168.1.100
Accepted password for admin from 192.168.1.100  ← ALERT
```

### Configuration

```yaml
- name: "Authentication Brute Force"
  enabled: true
  severity: "high"
  threshold: 3
  time_window: "5m"
```

---

## 2. Excessive Authentication Failures

**Severity**: Medium  
**Type**: Threshold-based

### Description

Detects excessive authentication failures from a single source, which may indicate a brute force or credential stuffing attack.

### Logic

1. Count failed authentication attempts per source
2. Track failures within a 10-minute sliding window
3. Alert when threshold (5) is exceeded

### Threshold

- **Default**: 5 failures within 10 minutes
- **Configurable**: Yes

### Example Triggers

```
Failed password for user1 from 10.0.0.50
Failed password for user2 from 10.0.0.50
Failed password for user3 from 10.0.0.50
Failed password for user4 from 10.0.0.50
Failed password for user5 from 10.0.0.50  ← ALERT
```

### Configuration

```yaml
- name: "Excessive Authentication Failures"
  enabled: true
  severity: "medium"
  threshold: 5
  time_window: "10m"
```

---

## 3. Privilege Escalation Indicators

**Severity**: Medium (High if error)  
**Type**: Pattern-based (Stateless)

### Description

Detects privilege escalation attempts by identifying keywords associated with elevated permissions.

### Logic

Scans log messages for privilege escalation keywords:
- `sudo`, `su -`, `runas`
- `privilege`, `administrator`, `root`
- `uac`, `user account control`
- `elevate`

Severity is escalated to "high" if the log entry has ERROR or higher severity.

### Example Triggers

```
sudo: admin : USER=root ; COMMAND=/bin/bash  ← ALERT (medium)
UAC: Elevation request denied for user bob    ← ALERT (high - error)
```

### Configuration

```yaml
- name: "Privilege Escalation"
  enabled: true
  severity: "medium"
```

---

## 4. Suspicious Command Execution

**Severity**: High  
**Type**: Pattern-based (Stateless)

### Description

Detects execution of suspicious commands or tools commonly used in attacks.

### Logic

Scans for suspicious command patterns:

**Shells & Interpreters**:
- `cmd.exe`, `powershell`, `bash`, `sh -c`
- `eval(`, `exec(`, `system(`

**Encoded/Obfuscated**:
- `base64`, `frombase64`, `-encodedcommand`
- `char(`, `chr(`

**Network Tools**:
- `wget`, `curl`, `invoke-webrequest`
- `nc`, `netcat`, `ncat`

**Suspicious Processes**:
- `mimikatz`, `psexec`, `wmic`

### Example Triggers

```
Executing: powershell -encodedcommand SGVsbG8=  ← ALERT
Process started: cmd.exe /c whoami             ← ALERT
```

### Configuration

```yaml
- name: "Suspicious Command Execution"
  enabled: true
  severity: "high"
```

---

## 5. SQL/Command Injection Patterns

**Severity**: Critical  
**Type**: Signature-based (Stateless)

### Description

Detects SQL injection, command injection, and path traversal attempts as observed in log messages.

### Logic

Scans for injection signatures:

**SQL Injection**:
- `' OR '1'='1`, `' OR 1=1`
- `'; DROP TABLE`, `UNION SELECT`
- `admin'--`, `admin' #`

**Command Injection**:
- `; ls`, `| cat`, `& dir`
- `$(`, backticks
- `; rm -rf`, `| rm -rf`

**Path Traversal**:
- `../`, `..\`

### Example Triggers

```
GET /user?id=1' OR '1'='1           ← ALERT (SQL Injection)
POST /api?cmd=ls; cat /etc/passwd   ← ALERT (Command Injection)
GET /files/../../etc/passwd         ← ALERT (Path Traversal)
```

### Configuration

```yaml
- name: "Injection Patterns"
  enabled: true
  severity: "critical"
```

---

## 6. Time-based Anomaly

**Severity**: Low  
**Type**: Time-based (Stateless)

### Description

Detects authentication events or errors occurring outside configured normal business hours.

### Logic

1. Check log entry timestamp against configured normal hours
2. Only alert for:
   - Authentication successes
   - Authentication failures
   - ERROR or higher severity logs

### Threshold

- **Default**: Normal hours 09:00-17:00
- **Configurable**: Yes

### Example Triggers

With normal hours configured as 09:00-17:00:

```
02:30:00 - Accepted password for backup  ← ALERT (outside hours)
22:15:00 - Failed login for admin        ← ALERT (outside hours)
```

### Configuration

```yaml
normal_hours:
  start: 9   # 09:00
  end: 17    # 17:00

rules:
  - name: "Time-based Anomaly"
    enabled: true
    severity: "low"
```

---

## Rule Customization

### Adding Custom Rules

While Drishti Nexus v1.0 has 6 built-in rules, the architecture supports extensibility:

1. Rules can be disabled via `config.yaml`
2. Thresholds and time windows can be adjusted
3. Custom rules can be added by modifying `internal/detection/rules.go`

### Tuning for Your Environment

#### Reduce False Positives

- Increase thresholds for brute force detection
- Adjust normal hours to match your environment
- Disable low-severity rules in high-volume environments

#### Increase Sensitivity

- Decrease failure thresholds
- Expand command/injection pattern lists
- Enable all rules including time-based anomaly

### Example Tuning

For a development environment with frequent sudo usage:

```yaml
rules:
  - name: "Privilege Escalation"
    enabled: false  # Disable to reduce noise
```

For high-security production:

```yaml
- name: "Excessive Authentication Failures"
  threshold: 3      # More sensitive (default: 5)
  time_window: "5m" # Shorter window (default: 10m)
```

---

## Best Practices

1. **Baseline First**: Run in monitoring mode to understand normal patterns
2. **Tune Gradually**: Adjust one rule at a time
3. **Document Changes**: Note modifications to `config.yaml`
4. **Test Updates**: Validate rule changes with test logs before deployment
5. **Review Regularly**: Periodically review alert rates and adjust thresholds

---

## Limitations

- Rules operate on log content only - no PCAP or network flow analysis
- Stateful rules (brute force) rely on in-memory tracking (lost on restart)
- Pattern matching is case-sensitive where applicable
- No machine learning or behavioral baselines

---
