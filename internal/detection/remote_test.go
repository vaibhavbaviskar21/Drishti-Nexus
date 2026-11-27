package detection

import (
	"drishti-nexus/internal/models"
	"fmt"
	"strings"
	"testing"
	"time"
)

// winEvent builds a Windows event as the JSON/XML parsers produce it (EventID as a JSON number).
func winEvent(at time.Time, host string, id int, fields map[string]interface{}) *models.LogEntry {
	seq++
	f := map[string]interface{}{"EventID": float64(id)}
	for k, v := range fields {
		f[k] = v
	}
	return &models.LogEntry{ID: fmt.Sprintf("w:%d", seq), Timestamp: at, Source: host, Severity: models.SeverityInfo, Fields: f}
}

const (
	ws5, ws6 = "WORKSTATION5", "WORKSTATION6"
	ws5IP    = "172.18.39.5"
)

func netLogonOn(at time.Time, host, ip, logonType string) *models.LogEntry {
	return winEvent(at, host, 4624, map[string]interface{}{"LogonType": logonType, "IpAddress": ip, "TargetUserName": "pgustavo"})
}

func serviceOn(at time.Time, host string) *models.LogEntry {
	return winEvent(at, host, 7045, map[string]interface{}{"ServiceName": "Updater"})
}

func initiatedFrom(at time.Time, host, ip string) *models.LogEntry {
	return winEvent(at, host, 3, map[string]interface{}{"Initiated": "true", "SourceIp": ip, "Channel": "Microsoft-Windows-Sysmon/Operational"})
}

// An alert on WORKSTATION5 that the lateral-movement alert should join.
func priorActivityOn(e *Engine, host string) *models.Alert {
	return findRule(run(e, textEntry(t0.Add(-time.Minute), host, "powershell -enc SQBFAFgA", models.SeverityInfo)), RuleSuspiciousCommand)
}

func TestRemoteService_SourceKnownBeforehand(t *testing.T) {
	e, store := newTestEngine(nil)
	src := priorActivityOn(e, ws5)
	run(e, initiatedFrom(t0.Add(-30*time.Second), ws5, ws5IP))
	alerts := run(e, netLogonOn(t0, ws6, ws5IP, "3"), serviceOn(t0.Add(2*time.Millisecond), ws6))

	a := findRule(alerts, RuleRemoteService)
	if a == nil || src == nil {
		t.Fatalf("alerts: %v", rulesOf(alerts))
	}
	a = alertByID(store.GetAlerts(), a.ID)
	if a.Details["source_host"] != ws5 || a.Details["user"] != "pgustavo" || a.Details["service"] != "Updater" ||
		a.MITRETechniqueID != "T1021.002" || a.Severity != "high" || len(a.RelatedLogs) != 2 {
		t.Errorf("alert: %+v", a)
	}
	if a.IncidentID != src.IncidentID || !contains(a.RelatedAlerts, src.ID) {
		t.Errorf("not joined to %s's incident: %s vs %s", ws5, a.IncidentID, src.IncidentID)
	}
}

// The Mordor PsExec data: WORKSTATION5's own connections (which reveal its IP)
// are logged ~95 ms after the service install on WORKSTATION6.
func TestRemoteService_SourceLearnedAfterAlert(t *testing.T) {
	e, store := newTestEngine(nil)
	src := priorActivityOn(e, ws5)
	a := findRule(run(e, netLogonOn(t0, ws6, ws5IP, "3"), serviceOn(t0.Add(2*time.Millisecond), ws6)), RuleRemoteService)
	if a == nil || a.Details["source_host"] != nil {
		t.Fatalf("alert before the source is known: %+v", a)
	}
	run(e, initiatedFrom(t0.Add(95*time.Millisecond), ws5, ws5IP))
	a = alertByID(store.GetAlerts(), a.ID)
	if a.Details["source_host"] != ws5 || a.IncidentID != src.IncidentID || !strings.Contains(a.Description, ws5) {
		t.Errorf("late link failed: %+v", a)
	}
}

func TestRemoteService_DoesNotFire(t *testing.T) {
	for name, entries := range map[string][]*models.LogEntry{
		"service without logon":   {serviceOn(t0, ws6)},
		"interactive logon (2)":   {netLogonOn(t0, ws6, ws5IP, "2"), serviceOn(t0.Add(time.Second), ws6)},
		"logon outside 5m window": {netLogonOn(t0, ws6, ws5IP, "3"), serviceOn(t0.Add(5*time.Minute+time.Second), ws6)},
		"service before logon":    {serviceOn(t0, ws6), netLogonOn(t0.Add(time.Second), ws6, ws5IP, "3")},
		"loopback source":         {netLogonOn(t0, ws6, "::1", "3"), serviceOn(t0.Add(time.Second), ws6)},
		"logon on another host":   {netLogonOn(t0, ws5, "172.18.39.6", "3"), serviceOn(t0.Add(time.Second), ws6)},
	} {
		e, _ := newTestEngine(nil)
		if n := countRule(run(e, entries...), RuleRemoteService); n != 0 {
			t.Errorf("%s: %d alerts", name, n)
		}
	}
	// Exactly at the window edge still counts.
	e, _ := newTestEngine(nil)
	if n := countRule(run(e, netLogonOn(t0, ws6, ws5IP, "3"), serviceOn(t0.Add(5*time.Minute), ws6)), RuleRemoteService); n != 1 {
		t.Errorf("logon exactly 5m before: %d alerts, want 1", n)
	}
	// A host's own address never names it as the source of its own service install.
	e, _ = newTestEngine(nil)
	run(e, initiatedFrom(t0.Add(-time.Second), ws6, "172.18.39.6"))
	a := findRule(run(e, netLogonOn(t0, ws6, "172.18.39.6", "3"), serviceOn(t0.Add(time.Second), ws6)), RuleRemoteService)
	if a != nil && a.Details["source_host"] != nil {
		t.Errorf("self-logon named a source host: %v", a.Details)
	}
}
