package detection

import (
	"drishti-nexus/internal/models"
	"fmt"
	"testing"
	"time"
)

var day0 = time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)

// activeAt logs a successful login on host srv at hh:mm on day d.
func activeAt(e *Engine, d, hh int) []*models.Alert {
	pidSeq++
	return run(e, ok(day0.AddDate(0, 0, d).Add(time.Duration(hh)*time.Hour+15*time.Minute), "10.1.1.1", pidSeq))
}

func TestTimeAnomaly_HostProfile(t *testing.T) {
	tests := []struct {
		name      string
		priorDays int  // days of history before the test day
		nightDays int  // of which the host was also active at 02:00
		alert     bool // 02:15 login on the test day
	}{
		{"too little history: static hours", 2, 2, true},
		{"never at night", 4, 0, true},
		{"night on 1 of 3 days", 3, 1, true},
		{"night on exactly half the days", 4, 2, false}, // boundary: half counts as routine
		{"night every day", 5, 5, false},
	}
	for _, tt := range tests {
		e, _ := newTestEngine(nil)
		for d := 0; d < tt.priorDays; d++ {
			activeAt(e, d, 12) // daytime activity every day
			if d < tt.nightDays {
				activeAt(e, d, 2)
			}
		}
		alerts := activeAt(e, tt.priorDays, 2)
		a := findRule(alerts, RuleTimeAnomaly)
		if (a != nil) != tt.alert {
			t.Errorf("%s: alert=%v, want %v", tt.name, a != nil, tt.alert)
		}
		if a != nil && tt.priorDays >= 3 && a.Details["host_history"] != fmt.Sprintf("active at 02:00 on %d of %d prior days", tt.nightDays, tt.priorDays) {
			t.Errorf("%s: alert does not explain the host history: %v", tt.name, a.Details)
		}
	}
}

func privEntry(at time.Time, host, msg string) *models.LogEntry {
	e := textEntry(at, host, msg, models.SeverityInfo)
	e.Fields["program"] = "sudo"
	return e
}

func TestPrivilegeEscalation_SeverityFromCorroboration(t *testing.T) {
	night := t0.Add(-10 * time.Hour) // 02:00
	denied := func(at time.Time, user string) *models.LogEntry {
		return privEntry(at, "web01", user+" : user NOT in sudoers ; TTY=pts/1 ; PWD=/home ; USER=root ; COMMAND=/bin/sh")
	}
	withHistory := func() *Engine { // 20 routine sudo uses by alice: the host has a privilege history
		e, _ := newTestEngine(nil)
		for i := 0; i < minPrivHistory; i++ {
			run(e, privEntry(t0.Add(-48*time.Hour+time.Duration(i)*time.Minute), "web01", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"))
		}
		return e
	}
	fresh := func() *Engine { e, _ := newTestEngine(nil); return e }

	for _, tt := range []struct {
		name   string
		engine func() *Engine
		entry  *models.LogEntry
		want   string
	}{
		{"keyword only", fresh, denied(t0, "bob"), "low"},
		{"off hours", fresh, denied(night, "bob"), "medium"},
		{"usual user, office hours", withHistory, denied(t0, "alice"), "low"},
		{"never-seen user", withHistory, denied(t0, "bob"), "medium"},
		{"never-seen user at night", withHistory, denied(night, "bob"), "high"},
	} {
		a := findRule(run(tt.engine(), tt.entry), RulePrivilegeEsc)
		if a == nil || a.Severity != tt.want {
			t.Errorf("%s: alert=%v, want severity %s", tt.name, a, tt.want)
			continue
		}
		if why, _ := a.Details["corroboration"].([]string); (tt.want == "low") != (len(why) == 0) {
			t.Errorf("%s: corroboration %v does not match severity %s", tt.name, why, tt.want)
		}
	}

	// The account is read from each sudo/su line format.
	for msg, want := range map[string]string{
		"bob : 3 incorrect password attempts ; TTY=pts/0":                     "bob",
		"pam_unix(sudo:auth): authentication failure; logname=carol uid=1001": "carol",
		"FAILED su for root by mallory":                                       "mallory",
	} {
		if got := privilegeActor(privEntry(t0, "h", msg)); got != want {
			t.Errorf("privilegeActor(%q) = %q, want %q", msg, got, want)
		}
	}
}
