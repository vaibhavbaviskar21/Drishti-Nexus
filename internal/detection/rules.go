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
	threshold, why := d.engine.threshold(ev.Key, s.Threshold)
	if failures < threshold {
		return nil
	}

	details := map[string]interface{}{
		"source":          ev.Host,
		"failed_attempts": failures,
		"threshold":       threshold,
		"window":          s.Window.String(),
	}
	for k, v := range why {
		details[k] = v
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
	threshold, why := d.engine.threshold(ev.Key, s.Threshold)
	if failures < threshold {
		return nil
	}

	details := map[string]interface{}{
		"source":    ev.Host,
		"threshold": threshold,
		"window":    s.Window.String(),
	}
	for k, v := range why {
		details[k] = v
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
type PrivilegeEscalationDetector struct {
	engine *Engine
}

func (d *PrivilegeEscalationDetector) Name() string {
	return RulePrivilegeEsc
}

// Severity comes from corroboration, not the keyword alone (Phase 2.5): none → low,
// one → the configured severity, both → high. Corroborations: outside normal hours,
// and an account never seen using sudo/su on a host with established privilege history.
func (d *PrivilegeEscalationDetector) Analyze(ev *Event) *Finding {
	e := d.engine
	actor := privilegeActor(ev.Entry)
	unusual := actor != "" && e.state.PrivUse[ev.Host] >= minPrivHistory && e.state.PrivUse[ev.Host+"|"+actor] == 0
	if isPrivilegeProgram(ev.Entry) {
		e.state.PrivUse[ev.Host]++
		if actor != "" {
			e.state.PrivUse[ev.Host+"|"+actor]++
		}
	}

	indicator := privilegeEscalationIndicator(ev.Entry)
	if indicator == "" {
		return nil
	}
	var why []string
	if e.isOutsideNormalHours(ev.Entry.Timestamp) {
		why = append(why, "outside normal hours")
	}
	if unusual {
		why = append(why, fmt.Sprintf("first privileged use by %s on %s (after %d privileged events by others)", actor, ev.Host, e.state.PrivUse[ev.Host]-1))
	}
	f := &Finding{
		AggKey:      ev.Host + "|" + indicator,
		CorrKey:     ev.Key,
		Description: fmt.Sprintf("Failed or denied privilege escalation (%s) on %s", indicator, ev.Host),
		Details: map[string]interface{}{
			"source":        ev.Host,
			"indicator":     indicator,
			"message":       ev.Entry.Message,
			"corroboration": why,
		},
	}
	if actor != "" {
		f.Details["user"] = actor
	}
	switch len(why) {
	case 0:
		f.Severity = "low"
	case 2:
		f.Severity = "high"
	}
	return f
}

// minPrivHistory is how many privileged events a host needs before "this account
// has never used sudo here" means anything.
const minPrivHistory = 20

var privPrograms = map[string]bool{"sudo": true, "su": true, "runas": true, "pkexec": true, "doas": true}

func isPrivilegeProgram(entry *models.LogEntry) bool {
	return privPrograms[strings.ToLower(fieldString(entry, "program"))] || strings.HasPrefix(entry.Message, "pam_unix(sudo") || strings.HasPrefix(entry.Message, "pam_unix(su")
}

var (
	sudoActor = regexp.MustCompile(`^\s*([A-Za-z0-9._-]+) : `)                   // "bob : 3 incorrect password attempts ; ..."
	pamActor  = regexp.MustCompile(`\b(?:logname|ruser)=([A-Za-z0-9._-]+)`)      // pam_unix(sudo:auth): ... logname=bob
	suActor   = regexp.MustCompile(`\bsu (?:for \S+ )?by ([A-Za-z0-9._-]+)\s*$`) // "FAILED su for root by mallory"
)

// privilegeActor returns the account attempting the escalation, if the line names it.
func privilegeActor(entry *models.LogEntry) string {
	if !isPrivilegeProgram(entry) {
		return ""
	}
	for _, re := range []*regexp.Regexp{sudoActor, pamActor, suActor} {
		if m := re.FindStringSubmatch(entry.Message); m != nil {
			return m[1]
		}
	}
	return fieldString(entry, "user")
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

// Phase 2.5: once a host has `threshold` days of history, an off-hours event is
// flagged only if that host was active at that hour on fewer than half of its
// prior days. Hosts that routinely work at night stop alerting; a host that
// never does still alerts, and the alert says what its history was.
func (d *TimeAnomalyDetector) Analyze(ev *Event) *Finding {
	if ev.AuthResult == "" && ev.Entry.Severity < models.SeverityError {
		return nil
	}
	e := d.engine
	local := ev.Entry.Timestamp.In(e.hoursLoc)
	seen, days := e.hostHourHistory(ev.Host, local)
	e.recordHostHour(ev.Host, local)

	if ev.fired[RuleBruteForce] || ev.fired[RuleExcessiveFailures] || !e.isOutsideNormalHours(ev.Entry.Timestamp) {
		return nil
	}
	hour := local.Hour()
	details := map[string]interface{}{"source": ev.Host, "hour": hour}
	if minDays := e.setting(RuleTimeAnomaly).Threshold; minDays > 0 && days >= minDays {
		if seen*2 >= days {
			return nil // routine for this host
		}
		details["host_history"] = fmt.Sprintf("active at %02d:00 on %d of %d prior days", hour, seen, days)
	}
	return &Finding{
		AggKey:      ev.Host,
		CorrKey:     ev.Key,
		Description: fmt.Sprintf("Activity outside normal hours (%02d:00 %s) on %s", hour, e.hoursLoc, ev.Host),
		Details:     details,
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
