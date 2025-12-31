package detection

import (
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/storage"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Engine coordinates detection rule execution
type Engine struct {
	storage *storage.MemoryStorage
	rules   []DetectionRule
	config  *models.Config

	// State tracking for stateful rules
	mu               sync.RWMutex
	failedLogins     map[string][]time.Time  // source -> timestamps
	authEvents       map[string]*AuthTracker // source -> auth tracker
	commandExecution map[string]int          // source -> count
}

// AuthTracker tracks authentication events for brute force detection
type AuthTracker struct {
	Failures  []time.Time
	Successes []time.Time
}

// NewEngine creates a new detection engine
func NewEngine(storage *storage.MemoryStorage, config *models.Config) *Engine {
	engine := &Engine{
		storage:          storage,
		config:           config,
		failedLogins:     make(map[string][]time.Time),
		authEvents:       make(map[string]*AuthTracker),
		commandExecution: make(map[string]int),
	}

	// Initialize built-in rules
	engine.initializeRules()

	return engine
}

// initializeRules sets up the core detection rules
func (e *Engine) initializeRules() {
	e.rules = []DetectionRule{
		&BruteForceDetector{engine: e},
		&ExcessiveFailuresDetector{engine: e},
		&PrivilegeEscalationDetector{engine: e},
		&SuspiciousCommandDetector{engine: e},
		&InjectionPatternDetector{engine: e},
		&TimeAnomalyDetector{engine: e},
	}
}

// AnalyzeLog analyzes a single log entry against all detection rules
func (e *Engine) AnalyzeLog(entry *models.LogEntry) []*models.Alert {
	alerts := make([]*models.Alert, 0)

	for _, rule := range e.rules {
		if alert := rule.Analyze(entry); alert != nil {
			e.storage.AddAlert(alert)
			alerts = append(alerts, alert)
		}
	}

	return alerts
}

// DetectionRule interface for all detection rules
type DetectionRule interface {
	Analyze(entry *models.LogEntry) *models.Alert
	Name() string
}

// generateAlertID creates a unique alert ID
func generateAlertID() string {
	return fmt.Sprintf("alert-%d", time.Now().UnixNano())
}

// isAuthFailure checks if a log entry indicates authentication failure
func isAuthFailure(entry *models.LogEntry) bool {
	msg := strings.ToLower(entry.Message)
	keywords := []string{
		"failed", "failure", "invalid", "incorrect",
		"authentication failed", "login failed", "access denied",
		"bad password", "invalid user", "failed login",
	}

	for _, keyword := range keywords {
		if strings.Contains(msg, keyword) {
			// Check for auth context too
			if strings.Contains(msg, "auth") || strings.Contains(msg, "login") ||
				strings.Contains(msg, "password") || strings.Contains(msg, "user") {
				return true
			}
		}
	}

	return false
}

// isAuthSuccess checks if a log entry indicates authentication success
func isAuthSuccess(entry *models.LogEntry) bool {
	msg := strings.ToLower(entry.Message)
	keywords := []string{
		"accepted", "success", "successful login", "logged in",
		"authentication successful", "session opened",
	}

	for _, keyword := range keywords {
		if strings.Contains(msg, keyword) {
			return true
		}
	}

	return false
}

// isPrivilegeEscalation checks for privilege escalation indicators
func isPrivilegeEscalation(entry *models.LogEntry) bool {
	msg := strings.ToLower(entry.Message)
	indicators := []string{
		"sudo", "su -", "runas", "elevate",
		"privilege", "administrator", "root",
		"uac", "user account control",
	}

	for _, indicator := range indicators {
		if strings.Contains(msg, indicator) {
			return true
		}
	}

	return false
}

// containsSuspiciousCommand checks for suspicious command execution patterns
func containsSuspiciousCommand(entry *models.LogEntry) bool {
	msg := strings.ToLower(entry.Message)

	suspicious := []string{
		// Shells and interpreters
		"cmd.exe", "powershell", "bash", "sh -c",
		"eval(", "exec(", "system(",

		// Encoded/obfuscated
		"base64", "frombase64", "-encodedcommand",
		"char(", "chr(",

		// Network tools
		"wget", "curl", "invoke-webrequest",
		"nc ", "netcat", "ncat",

		// Suspicious processes
		"mimikatz", "psexec", "wmic",
	}

	for _, cmd := range suspicious {
		if strings.Contains(msg, cmd) {
			return true
		}
	}

	return false
}

// containsInjectionPattern checks for SQL/command injection patterns
func containsInjectionPattern(entry *models.LogEntry) (bool, string) {
	msg := entry.Message

	// SQL injection patterns
	sqlPatterns := []string{
		"' OR '1'='1", "' OR 1=1", "'; DROP TABLE",
		"UNION SELECT", "' AND '1'='1",
		"' OR ''='", "admin'--", "admin' #",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(msg, pattern) {
			return true, "SQL Injection"
		}
	}

	// Command injection patterns
	cmdPatterns := []string{
		"; ls", "; cat", "| cat", "& dir",
		"; whoami", "| whoami", "$(", "`",
		"; rm -rf", "| rm -rf",
	}

	for _, pattern := range cmdPatterns {
		if strings.Contains(msg, pattern) {
			return true, "Command Injection"
		}
	}

	// Path traversal
	if strings.Contains(msg, "../") || strings.Contains(msg, "..\\") {
		return true, "Path Traversal"
	}

	return false, ""
}

// isOutsideNormalHours checks if timestamp is outside configured normal hours
func (e *Engine) isOutsideNormalHours(t time.Time) bool {
	hour := t.Hour()
	start := e.config.NormalHours.Start
	end := e.config.NormalHours.End

	if start == 0 && end == 0 {
		// Not configured, skip check
		return false
	}

	if start < end {
		// Normal case: e.g., 9-17
		return hour < start || hour >= end
	} else {
		// Wrap around: e.g., 22-6
		return hour >= end && hour < start
	}
}

// cleanOldEntries removes entries older than the specified duration
func (e *Engine) cleanOldEntries(m map[string][]time.Time, maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)

	for key, timestamps := range m {
		filtered := make([]time.Time, 0)
		for _, ts := range timestamps {
			if ts.After(cutoff) {
				filtered = append(filtered, ts)
			}
		}
		if len(filtered) > 0 {
			m[key] = filtered
		} else {
			delete(m, key)
		}
	}
}
