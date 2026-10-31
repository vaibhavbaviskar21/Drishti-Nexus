package detection

import (
	"drishti-nexus/internal/models"
	"fmt"
	"regexp"
	"strings"
)

var (
	backtickSubst = regexp.MustCompile("`[^`'\n]{1,200}`")
	// Short escalation keywords must be whole words ("uac" inside obfuscated script is not UAC).
	privEscWords = regexp.MustCompile(`\b(?:sudo|runas|pkexec|elevate|user account control|uac)\b|\bsu -`)
)

// BruteForceDetector detects failed → success authentication patterns:
// a success preceded by ≥ threshold failed attempts from the same host+source IP
// within the time window (boundaries inclusive).
type BruteForceDetector struct {
	engine *Engine
}

func (d *BruteForceDetector) Name() string {
	return RuleBruteForce
}

func (d *BruteForceDetector) Analyze(ev *Event) *Finding {
	if ev.AuthResult != "success" || ev.Attempts == 0 {
		return nil
	}
	s := d.engine.setting(RuleBruteForce)
	w := d.engine.failuresWithin(ev.Key, ev.Entry.Timestamp, s.Window)
	failures := w.Attempts
	if failures < s.Threshold {
		return nil
	}

	details := map[string]interface{}{
		"source":          ev.Host,
		"failed_attempts": failures,
		"threshold":       s.Threshold,
		"window":          s.Window.String(),
	}
	who := ev.Host
	if ip := fieldString(ev.Entry, "src_ip"); ip != "" {
		details["src_ip"] = ip
		who = ip + " on " + ev.Host
	}
	if user := fieldString(ev.Entry, "user"); user != "" {
		details["user"] = user
		d.engine.state.Compromised[user] = &compromise{Host: ev.Host, Key: ev.Key, At: ev.Entry.Timestamp, Evidence: ev.Entry.ID}
	}
	return &Finding{
		AggKey:      ev.Key,
		CorrKey:     ev.Key,
		Description: fmt.Sprintf("Brute force: %d failed attempts followed by a successful login from %s within %s", failures, who, s.Window),
		Details:     details,
		Evidence:    w.IDs,
		FirstSeen:   w.First,
	}
}

// ExcessiveFailuresDetector detects ≥ threshold failed attempts from the same
// host+source IP within the time window (boundaries inclusive). One alert is
// raised per burst; further failures in the burst increase its count.
type ExcessiveFailuresDetector struct {
	engine *Engine
}

func (d *ExcessiveFailuresDetector) Name() string {
	return RuleExcessiveFailures
}

func (d *ExcessiveFailuresDetector) Analyze(ev *Event) *Finding {
	if ev.AuthResult != "failure" || ev.Attempts == 0 {
		return nil
	}
	s := d.engine.setting(RuleExcessiveFailures)
	w := d.engine.failuresWithin(ev.Key, ev.Entry.Timestamp, s.Window)
	failures := w.Attempts
	if failures < s.Threshold {
		return nil
	}

	details := map[string]interface{}{
		"source":    ev.Host,
		"threshold": s.Threshold,
		"window":    s.Window.String(),
	}
	who := ev.Host
	if ip := fieldString(ev.Entry, "src_ip"); ip != "" {
		details["src_ip"] = ip
		who = ip + " on " + ev.Host
	}
	return &Finding{
		AggKey:      ev.Key,
		CorrKey:     ev.Key,
		Description: fmt.Sprintf("Excessive authentication failures from %s: %d failed attempts within %s", who, failures, s.Window),
		Details:     details,
		Count:       failures,
		Increment:   ev.Attempts,
		Evidence:    w.IDs,
		FirstSeen:   w.First,
	}
}

// PrivilegeEscalationDetector detects failed or denied privilege escalation
// attempts (normal successful sudo/su usage is not flagged).
type PrivilegeEscalationDetector struct{}

func (d *PrivilegeEscalationDetector) Name() string {
	return RulePrivilegeEsc
}

func (d *PrivilegeEscalationDetector) Analyze(ev *Event) *Finding {
	indicator := privilegeEscalationIndicator(ev.Entry)
	if indicator == "" {
		return nil
	}
	f := &Finding{
		AggKey:      ev.Host + "|" + indicator,
		CorrKey:     ev.Key,
		Description: fmt.Sprintf("Failed or denied privilege escalation (%s) on %s", indicator, ev.Host),
		Details: map[string]interface{}{
			"source":    ev.Host,
			"indicator": indicator,
			"message":   ev.Entry.Message,
		},
	}
	if ev.Entry.Severity >= models.SeverityError {
		f.Severity = "high"
	}
	return f
}

// privilegeEscalationIndicator returns the matched escalation mechanism when the
// entry shows a failed/denied attempt, or "".
func privilegeEscalationIndicator(entry *models.LogEntry) string {
	msg := strings.ToLower(entry.Message)

	denied := false
	for _, k := range []string{"failed", "failure", "incorrect", "not in sudoers", "permission denied", "not allowed", "authentication failure"} {
		if strings.Contains(msg, k) {
			denied = true
			break
		}
	}
	if !denied {
		return ""
	}

	program := strings.ToLower(fieldString(entry, "program"))
	for _, p := range []string{"sudo", "su", "runas", "pkexec", "doas"} {
		if program == p {
			return p
		}
	}
	// Cheap substring prefilter before the word-boundary regex (hot path: every auth failure).
	for _, k := range []string{"sudo", "su -", "runas", "pkexec", "elevate", "user account control", "uac"} {
		if strings.Contains(msg, k) {
			return privEscWords.FindString(msg)
		}
	}
	return ""
}

// SuspiciousCommandDetector detects suspicious command execution
type SuspiciousCommandDetector struct{}

func (d *SuspiciousCommandDetector) Name() string {
	return RuleSuspiciousCommand
}

func (d *SuspiciousCommandDetector) Analyze(ev *Event) *Finding {
	indicator := suspiciousCommandIndicator(ev.Entry)
	if indicator == "" {
		return nil
	}
	return &Finding{
		AggKey:      ev.Host + "|" + indicator,
		CorrKey:     ev.Key,
		Description: fmt.Sprintf("Suspicious command execution (%s) on %s", indicator, ev.Host),
		Details: map[string]interface{}{
			"source":    ev.Host,
			"indicator": indicator,
			"message":   ev.Entry.Message,
		},
	}
}

var suspiciousIndicators = []string{
	// Shells and interpreters
	"cmd.exe", "powershell", "bash -i", "sh -c",
	"eval(", "exec(", "system(",

	// Encoded/obfuscated
	"base64 -d", "frombase64", "-encodedcommand", "-enc ",
	"char(", "chr(",

	// Network tools
	"wget ", "curl ", "invoke-webrequest",
	"nc -e", "netcat", "ncat ",

	// Suspicious processes
	"mimikatz", "psexec", "wmic ",
}

// suspiciousCommandIndicator returns the matched indicator, or "".
func suspiciousCommandIndicator(entry *models.LogEntry) string {
	msg := strings.ToLower(entry.Message)
	for _, cmd := range suspiciousIndicators {
		if containsWordStart(msg, cmd) {
			return strings.TrimSpace(cmd)
		}
	}
	return ""
}

// containsWordStart reports whether needle occurs in s at a word start, so
// "ncat " does not match the username "concat ".
func containsWordStart(s, needle string) bool {
	for from := 0; ; {
		i := strings.Index(s[from:], needle)
		if i < 0 {
			return false
		}
		at := from + i
		if at == 0 || !isWordByte(s[at-1]) || !isWordByte(needle[0]) {
			return true
		}
		from = at + 1
	}
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// InjectionPatternDetector detects SQL/command injection patterns
type InjectionPatternDetector struct{}

func (d *InjectionPatternDetector) Name() string {
	return RuleInjection
}

func (d *InjectionPatternDetector) Analyze(ev *Event) *Finding {
	matched, attackType := containsInjectionPattern(ev.Entry)
	if !matched {
		return nil
	}
	return &Finding{
		AggKey:      ev.Key + "|" + attackType,
		CorrKey:     ev.Key,
		Description: fmt.Sprintf("%s pattern detected from %s", attackType, ev.Host),
		Details: map[string]interface{}{
			"source":      ev.Host,
			"attack_type": attackType,
			"message":     ev.Entry.Message,
		},
	}
}

// containsInjectionPattern checks for SQL/command injection patterns
func containsInjectionPattern(entry *models.LogEntry) (bool, string) {
	msg := entry.Message
	upper := strings.ToUpper(msg)

	// SQL injection patterns
	sqlPatterns := []string{
		"' OR '1'='1", "' OR 1=1", "'; DROP TABLE",
		"UNION SELECT", "UNION ALL SELECT", "' AND '1'='1",
		"' OR ''='", "ADMIN'--", "ADMIN' #",
		"%27%20OR%201=1", "UNION%20SELECT",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(upper, pattern) {
			return true, "SQL Injection"
		}
	}

	// Command injection patterns
	cmdPatterns := []string{
		"; ls", "; cat ", "| cat ", "& dir",
		"; whoami", "| whoami", "$(",
		"; rm -rf", "| rm -rf",
	}

	for _, pattern := range cmdPatterns {
		if strings.Contains(msg, pattern) {
			return true, "Command Injection"
		}
	}
	// Backtick substitution needs a closed pair; a lone ` is common in prose
	// ("process `syslogd' is using ...").
	if backtickSubst.MatchString(msg) {
		return true, "Command Injection"
	}

	// Path traversal
	if strings.Contains(msg, "../") || strings.Contains(msg, "..\\") || strings.Contains(upper, "%2E%2E%2F") {
		return true, "Path Traversal"
	}

	return false, ""
}

// TimeAnomalyDetector detects authentication activity and errors outside normal hours.
// Entries already covered by a higher-fidelity auth alert are skipped.
type TimeAnomalyDetector struct {
	engine *Engine
}

func (d *TimeAnomalyDetector) Name() string {
	return RuleTimeAnomaly
}

func (d *TimeAnomalyDetector) Analyze(ev *Event) *Finding {
	if ev.fired[RuleBruteForce] || ev.fired[RuleExcessiveFailures] {
		return nil
	}
	if !d.engine.isOutsideNormalHours(ev.Entry.Timestamp) {
		return nil
	}
	if ev.AuthResult == "" && ev.Entry.Severity < models.SeverityError {
		return nil
	}

	hour := ev.Entry.Timestamp.In(d.engine.hoursLoc).Hour()
	return &Finding{
		AggKey:      ev.Host,
		CorrKey:     ev.Key,
		Description: fmt.Sprintf("Activity outside normal hours (%02d:00 %s) on %s", hour, d.engine.hoursLoc, ev.Host),
		Details: map[string]interface{}{
			"source": ev.Host,
			"hour":   hour,
		},
	}
}

// LateralMovementDetector links hosts: an account brute-forced on host A
// (Authentication Brute Force) then logs in successfully on a different host B
// within the window. Excessive failures alone are not used: without a success
// there is no evidence the attacker obtained the password.
type LateralMovementDetector struct {
	engine *Engine
}

func (d *LateralMovementDetector) Name() string {
	return RuleLateralMovement
}

func (d *LateralMovementDetector) Analyze(ev *Event) *Finding {
	if ev.AuthResult != "success" || ev.Attempts == 0 || ev.Host == "unknown" {
		return nil
	}
	user := fieldString(ev.Entry, "user")
	c := d.engine.state.Compromised[user]
	if user == "" || c == nil || c.Host == ev.Host || c.Host == "unknown" {
		return nil
	}
	s := d.engine.setting(RuleLateralMovement)
	dt := ev.Entry.Timestamp.Sub(c.At)
	if dt < 0 || dt > s.Window {
		return nil
	}
	f := &Finding{
		AggKey:      user + "|" + c.Host + "|" + ev.Host,
		CorrKey:     c.Key,
		Description: fmt.Sprintf("Lateral movement candidate: %q was brute-forced on %s, then logged in on %s %s later", user, c.Host, ev.Host, dt),
		Details: map[string]interface{}{
			"user":             user,
			"source_host":      c.Host,
			"destination_host": ev.Host,
			"time_delta":       dt.String(),
			"window":           s.Window.String(),
		},
		Evidence:  []string{c.Evidence},
		FirstSeen: c.At,
	}
	if ip := fieldString(ev.Entry, "src_ip"); ip != "" {
		f.Details["src_ip"] = ip
	}
	if o, ok := d.engine.state.Open[RuleBruteForce+"\x00"+c.Key]; ok {
		f.LinkTo = o.AlertID
		f.Details["origin_alert"] = o.AlertID
	}
	return f
}
