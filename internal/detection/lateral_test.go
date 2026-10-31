package detection

import (
	"drishti-nexus/internal/models"
	"testing"
	"time"
)

const attacker = "203.0.113.50"

// login is an sshd auth line for user on host.
func login(at time.Time, host, ip, user, result string, pid int) *models.LogEntry {
	event := "accepted"
	if result == "failure" {
		event = "password_failed"
	}
	e := authEntry(at, host, ip, result, event, pid)
	e.Fields["user"] = user
	return e
}

// bruteForceOn returns 3 failures then a success for user on host, ending at t0+3s.
func bruteForceOn(host, user string) []*models.LogEntry {
	return []*models.LogEntry{
		login(t0, host, attacker, user, "failure", 1),
		login(t0.Add(time.Second), host, attacker, user, "failure", 2),
		login(t0.Add(2*time.Second), host, attacker, user, "failure", 3),
		login(t0.Add(3*time.Second), host, attacker, user, "success", 4),
	}
}

func findRule(alerts []*models.Alert, rule string) *models.Alert {
	for _, a := range alerts {
		if a.RuleName == rule {
			return a
		}
	}
	return nil
}

func TestLateralMovement_LinksIntoBruteForceIncident(t *testing.T) {
	e, store := newTestEngine(nil)
	alerts := run(e, bruteForceOn("web01", "deploy")...)
	alerts = append(alerts, run(e, login(t0.Add(10*time.Minute), "db01", "10.0.0.11", "deploy", "success", 9))...)

	bf, lat := findRule(alerts, RuleBruteForce), findRule(alerts, RuleLateralMovement)
	if bf == nil || lat == nil {
		t.Fatalf("want brute force + lateral movement, got %v", rulesOf(alerts))
	}
	lat = alertByID(store.GetAlerts(), lat.ID) // stored copy carries the links
	if lat.IncidentID != bf.IncidentID {
		t.Errorf("lateral alert in %s, brute force in %s: should be one incident", lat.IncidentID, bf.IncidentID)
	}
	if len(lat.RelatedAlerts) == 0 || lat.RelatedAlerts[0] != bf.ID || !contains(alertByID(store.GetAlerts(), bf.ID).RelatedAlerts, lat.ID) {
		t.Errorf("alerts not cross-linked: lateral=%v", lat.RelatedAlerts)
	}
	if lat.Severity != "critical" || lat.MITRETechniqueID != "T1021" || !lat.Timestamp.Equal(t0.Add(3*time.Second)) {
		t.Errorf("severity=%s technique=%s first=%s", lat.Severity, lat.MITRETechniqueID, lat.Timestamp)
	}
	if lat.Details["source_host"] != "web01" || lat.Details["destination_host"] != "db01" {
		t.Errorf("details: %v", lat.Details)
	}
}

func TestLateralMovement_WindowBoundary(t *testing.T) {
	compromisedAt := t0.Add(3 * time.Second)
	for _, tc := range []struct {
		after time.Duration
		want  int
	}{
		{30 * time.Minute, 1},             // boundary is inclusive
		{30*time.Minute + time.Second, 0}, // just outside
		{-time.Second, 0},                 // login on B before the compromise on A
	} {
		e, _ := newTestEngine(nil)
		run(e, bruteForceOn("web01", "deploy")...)
		got := countRule(run(e, login(compromisedAt.Add(tc.after), "db01", "10.0.0.11", "deploy", "success", 9)), RuleLateralMovement)
		if got != tc.want {
			t.Errorf("login %s after compromise: %d alerts, want %d", tc.after, got, tc.want)
		}
	}
}

func TestLateralMovement_DoesNotFire(t *testing.T) {
	cases := map[string][]*models.LogEntry{
		"same host": append(bruteForceOn("web01", "deploy"),
			login(t0.Add(time.Minute), "web01", "10.0.0.11", "deploy", "success", 9)),
		"different user": append(bruteForceOn("web01", "deploy"),
			login(t0.Add(time.Minute), "db01", "10.0.0.11", "alice", "success", 9)),
		"failures without success on A": {
			login(t0, "web01", attacker, "deploy", "failure", 1),
			login(t0.Add(time.Second), "web01", attacker, "deploy", "failure", 2),
			login(t0.Add(2*time.Second), "web01", attacker, "deploy", "failure", 3),
			login(t0.Add(3*time.Second), "web01", attacker, "deploy", "failure", 4),
			login(t0.Add(4*time.Second), "web01", attacker, "deploy", "failure", 5),
			login(t0.Add(time.Minute), "db01", "10.0.0.11", "deploy", "success", 9),
		},
		"no host on destination": append(bruteForceOn("web01", "deploy"),
			login(t0.Add(time.Minute), "unknown", "10.0.0.11", "deploy", "success", 9)),
	}
	for name, entries := range cases {
		e, _ := newTestEngine(nil)
		if n := countRule(run(e, entries...), RuleLateralMovement); n != 0 {
			t.Errorf("%s: %d lateral alerts, want 0", name, n)
		}
	}
}

func TestLateralMovement_SurvivesRestore(t *testing.T) {
	e1, store := newTestEngine(nil)
	run(e1, bruteForceOn("web01", "deploy")...)
	snap, err := e1.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	e2 := NewEngine(store, &models.Config{NormalHours: models.NormalHours{Start: 9, End: 17}})
	if err := e2.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if n := countRule(run(e2, login(t0.Add(5*time.Minute), "db01", "10.0.0.11", "deploy", "success", 9)), RuleLateralMovement); n != 1 {
		t.Errorf("compromise lost across restart: %d lateral alerts", n)
	}
}

func rulesOf(alerts []*models.Alert) []string {
	var out []string
	for _, a := range alerts {
		out = append(out, a.RuleName)
	}
	return out
}

func alertByID(alerts []*models.Alert, id string) *models.Alert {
	for _, a := range alerts {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
