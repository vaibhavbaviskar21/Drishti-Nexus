package detection

import (
	"drishti-nexus/internal/models"
	"fmt"
	"time"
)

// BruteForceDetector detects failed → success authentication patterns
type BruteForceDetector struct {
	engine *Engine
}

func (d *BruteForceDetector) Name() string {
	return "Authentication Brute Force"
}

func (d *BruteForceDetector) Analyze(entry *models.LogEntry) *models.Alert {
	d.engine.mu.Lock()
	defer d.engine.mu.Unlock()

	// Initialize tracker if needed
	if _, ok := d.engine.authEvents[entry.Source]; !ok {
		d.engine.authEvents[entry.Source] = &AuthTracker{
			Failures:  make([]time.Time, 0),
			Successes: make([]time.Time, 0),
		}
	}

	tracker := d.engine.authEvents[entry.Source]

	// Track authentication events
	if isAuthFailure(entry) {
		tracker.Failures = append(tracker.Failures, entry.Timestamp)
	} else if isAuthSuccess(entry) {
		tracker.Successes = append(tracker.Successes, entry.Timestamp)

		// Check if there were recent failures before this success
		recentFailures := 0
		lookback := time.Minute * 5

		for _, failTime := range tracker.Failures {
			if entry.Timestamp.Sub(failTime) <= lookback && failTime.Before(entry.Timestamp) {
				recentFailures++
			}
		}

		// Alert if 3+ failures followed by success (brute force pattern)
		if recentFailures >= 3 {
			return &models.Alert{
				ID:          generateAlertID(),
				Timestamp:   entry.Timestamp,
				RuleName:    d.Name(),
				Severity:    "high",
				Description: fmt.Sprintf("Brute force attack detected: %d failed login attempts followed by successful login from %s", recentFailures, entry.Source),
				RelatedLogs: []string{entry.ID},
				Details: map[string]interface{}{
					"source":          entry.Source,
					"failed_attempts": recentFailures,
				},
				Count: 1,
			}
		}
	}

	return nil
}

// ExcessiveFailuresDetector detects excessive authentication failures
type ExcessiveFailuresDetector struct {
	engine *Engine
}

func (d *ExcessiveFailuresDetector) Name() string {
	return "Excessive Authentication Failures"
}

func (d *ExcessiveFailuresDetector) Analyze(entry *models.LogEntry) *models.Alert {
	if !isAuthFailure(entry) {
		return nil
	}

	d.engine.mu.Lock()
	defer d.engine.mu.Unlock()

	// Track failed login
	d.engine.failedLogins[entry.Source] = append(
		d.engine.failedLogins[entry.Source],
		entry.Timestamp,
	)

	// Clean old entries (older than 10 minutes)
	d.engine.cleanOldEntries(d.engine.failedLogins, 10*time.Minute)

	// Check threshold
	threshold := 5
	failures := d.engine.failedLogins[entry.Source]

	if len(failures) >= threshold {
		return &models.Alert{
			ID:          generateAlertID(),
			Timestamp:   entry.Timestamp,
			RuleName:    d.Name(),
			Severity:    "medium",
			Description: fmt.Sprintf("Excessive authentication failures from %s: %d failures in 10 minutes", entry.Source, len(failures)),
			RelatedLogs: []string{entry.ID},
			Details: map[string]interface{}{
				"source":        entry.Source,
				"failure_count": len(failures),
				"threshold":     threshold,
			},
			Count: len(failures),
		}
	}

	return nil
}

// PrivilegeEscalationDetector detects privilege escalation indicators
type PrivilegeEscalationDetector struct {
	engine *Engine
}

func (d *PrivilegeEscalationDetector) Name() string {
	return "Privilege Escalation Indicator"
}

func (d *PrivilegeEscalationDetector) Analyze(entry *models.LogEntry) *models.Alert {
	if !isPrivilegeEscalation(entry) {
		return nil
	}

	severity := "medium"
	// Escalate if error/failure in message
	if entry.Severity >= models.SeverityError {
		severity = "high"
	}

	return &models.Alert{
		ID:          generateAlertID(),
		Timestamp:   entry.Timestamp,
		RuleName:    d.Name(),
		Severity:    severity,
		Description: fmt.Sprintf("Privilege escalation activity detected from %s", entry.Source),
		RelatedLogs: []string{entry.ID},
		Details: map[string]interface{}{
			"source":  entry.Source,
			"message": entry.Message,
		},
		Count: 1,
	}
}

// SuspiciousCommandDetector detects suspicious command execution
type SuspiciousCommandDetector struct {
	engine *Engine
}

func (d *SuspiciousCommandDetector) Name() string {
	return "Suspicious Command Execution"
}

func (d *SuspiciousCommandDetector) Analyze(entry *models.LogEntry) *models.Alert {
	if !containsSuspiciousCommand(entry) {
		return nil
	}

	return &models.Alert{
		ID:          generateAlertID(),
		Timestamp:   entry.Timestamp,
		RuleName:    d.Name(),
		Severity:    "high",
		Description: fmt.Sprintf("Suspicious command execution detected from %s", entry.Source),
		RelatedLogs: []string{entry.ID},
		Details: map[string]interface{}{
			"source":  entry.Source,
			"message": entry.Message,
		},
		Count: 1,
	}
}

// InjectionPatternDetector detects SQL/command injection patterns
type InjectionPatternDetector struct {
	engine *Engine
}

func (d *InjectionPatternDetector) Name() string {
	return "Injection Pattern Detected"
}

func (d *InjectionPatternDetector) Analyze(entry *models.LogEntry) *models.Alert {
	if matched, attackType := containsInjectionPattern(entry); matched {
		return &models.Alert{
			ID:          generateAlertID(),
			Timestamp:   entry.Timestamp,
			RuleName:    d.Name(),
			Severity:    "critical",
			Description: fmt.Sprintf("%s pattern detected from %s", attackType, entry.Source),
			RelatedLogs: []string{entry.ID},
			Details: map[string]interface{}{
				"source":      entry.Source,
				"attack_type": attackType,
				"message":     entry.Message,
			},
			Count: 1,
		}
	}

	return nil
}

// TimeAnomalyDetector detects activity outside normal hours
type TimeAnomalyDetector struct {
	engine *Engine
}

func (d *TimeAnomalyDetector) Name() string {
	return "Time-based Anomaly"
}

func (d *TimeAnomalyDetector) Analyze(entry *models.LogEntry) *models.Alert {
	if !d.engine.isOutsideNormalHours(entry.Timestamp) {
		return nil
	}

	// Only alert on auth events or errors outside normal hours
	if isAuthSuccess(entry) || isAuthFailure(entry) || entry.Severity >= models.SeverityError {
		hour := entry.Timestamp.Hour()
		description := fmt.Sprintf("Activity detected outside normal hours (at %02d:00) from %s", hour, entry.Source)

		return &models.Alert{
			ID:          generateAlertID(),
			Timestamp:   entry.Timestamp,
			RuleName:    d.Name(),
			Severity:    "low",
			Description: description,
			RelatedLogs: []string{entry.ID},
			Details: map[string]interface{}{
				"source": entry.Source,
				"hour":   hour,
			},
			Count: 1,
		}
	}

	return nil
}
