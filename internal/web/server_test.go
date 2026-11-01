package web

import (
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/pipeline"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestServer() *Server {
	return NewServer(&models.Config{MaxLogEntries: 1000})
}

// seeded: two hosts' evidence, one incident with two alerts, one standalone alert.
func seeded() *Server {
	s := newTestServer()
	t0 := time.Date(2025, 3, 10, 10, 0, 0, 0, time.UTC)
	s.storage.AddLog(&models.LogEntry{ID: "web01/auth.log:3", Source: "web01", Timestamp: t0, RawLog: "Failed password for <script>alert(1)</script>", ParseQuality: models.QualityClean})
	s.storage.AddLog(&models.LogEntry{ID: "db01/auth.log:7", Source: "db01", Timestamp: t0.Add(time.Minute), RawLog: "Accepted password for deploy", ParseQuality: models.QualityPartial})
	s.storage.AddAlert(&models.Alert{ID: "ALERT-000001", IncidentID: "INC-00001", Timestamp: t0, LastSeen: t0.Add(time.Minute),
		RuleName: "Authentication Brute Force", Severity: "high", RelatedLogs: []string{"web01/auth.log:3", "gone:1"},
		RelatedAlerts: []string{"ALERT-000002"}, MITRETechniqueID: "T1110.001", Details: map[string]interface{}{}})
	s.storage.AddAlert(&models.Alert{ID: "ALERT-000002", IncidentID: "INC-00001", Timestamp: t0.Add(2 * time.Minute), LastSeen: t0.Add(5 * time.Minute),
		RuleName: "Lateral Movement Candidate", Severity: "critical", RelatedLogs: []string{"db01/auth.log:7"},
		MITRETechniqueID: "T1021", Details: map[string]interface{}{"source": "db01"}})
	s.storage.AddAlert(&models.Alert{ID: "ALERT-000003", Timestamp: t0, LastSeen: t0, RuleName: "Off-Hours", Severity: "low", Details: map[string]interface{}{}})
	return s
}

func get(t *testing.T, s *Server, path string, out interface{}) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if out != nil {
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("%s: content-type %q", path, ct)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: bad JSON %q: %v", path, rec.Body.String(), err)
		}
	}
	return rec
}

func TestSecurityHeaders(t *testing.T) {
	for _, p := range []string{"/", "/api/stats", "/static/js/app.js", "/static/css/style.css", "/api/alerts/nope"} {
		rec := get(t, newTestServer(), p, nil)
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: weak CSP %q", p, csp)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", p)
		}
	}
}

func TestIndexAndAssetsServed(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/", nil)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Drishti Nexus") {
		t.Fatalf("index: %d", rec.Code)
	}
	// CSP forbids inline script/handlers, so the page must not rely on them.
	if strings.Contains(body, "onclick=") || strings.Contains(body, "<script>") || strings.Contains(body, " style=") {
		t.Error("index.html contains inline script, handler or style blocked by CSP")
	}
	for _, p := range []string{"/static/js/app.js", "/static/css/style.css"} {
		if rec := get(t, s, p, nil); rec.Code != http.StatusOK {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

func TestEmptyState(t *testing.T) {
	s := newTestServer()
	var alerts, incidents, logs []interface{}
	get(t, s, "/api/alerts", &alerts)
	get(t, s, "/api/incidents", &incidents)
	get(t, s, "/api/logs", &logs)
	if len(alerts)+len(incidents)+len(logs) != 0 {
		t.Error("expected empty lists")
	}
	if body := get(t, s, "/api/incidents", nil).Body.String(); strings.TrimSpace(body) != "[]" {
		t.Errorf("incidents should be [] not %q", body)
	}
	var session *audit.Session
	if rec := get(t, s, "/api/session", &session); rec.Code != http.StatusOK || session != nil {
		t.Errorf("session: %d %v", rec.Code, session)
	}
	var stats map[string]interface{}
	get(t, s, "/api/stats", &stats)
	if stats["alert_count"].(float64) != 0 || stats["incident_count"].(float64) != 0 || stats["clean_parse_pct"].(float64) != 0 {
		t.Errorf("stats: %v", stats)
	}
}

func TestStats(t *testing.T) {
	var stats struct {
		LogCount      int            `json:"log_count"`
		AlertCount    int            `json:"alert_count"`
		IncidentCount int            `json:"incident_count"`
		Entries       int            `json:"entries"`
		CleanPct      float64        `json:"clean_parse_pct"`
		BySeverity    map[string]int `json:"alerts_by_severity"`
		ByRule        []countItem    `json:"alerts_by_rule"`
		TopSources    []countItem    `json:"top_sources"`
	}
	get(t, seeded(), "/api/stats", &stats)
	if stats.LogCount != 2 || stats.AlertCount != 3 || stats.IncidentCount != 2 || stats.Entries != 2 || stats.CleanPct != 50 {
		t.Errorf("stats: %+v", stats)
	}
	if stats.BySeverity["critical"] != 1 || len(stats.ByRule) != 3 || len(stats.TopSources) != 2 {
		t.Errorf("breakdowns: %+v", stats)
	}
}

func TestAlertsNewestFirst(t *testing.T) {
	var alerts []models.Alert
	get(t, seeded(), "/api/alerts", &alerts)
	if len(alerts) != 3 || alerts[0].ID != "ALERT-000003" {
		t.Errorf("alerts: %+v", alerts)
	}
}

func TestAlertDetailResolvesEvidence(t *testing.T) {
	var d struct {
		ID       string         `json:"id"`
		Evidence []evidenceLine `json:"evidence"`
		Hosts    []string       `json:"hosts"`
	}
	rec := get(t, seeded(), "/api/alerts/ALERT-000001", &d)
	if rec.Code != http.StatusOK || d.ID != "ALERT-000001" || len(d.Evidence) != 2 {
		t.Fatalf("detail: %d %+v", rec.Code, d)
	}
	if !d.Evidence[0].Found || d.Evidence[0].Raw != "Failed password for <script>alert(1)</script>" || d.Evidence[0].Source != "web01" {
		t.Errorf("evidence[0]: %+v", d.Evidence[0])
	}
	if d.Evidence[1].Found || d.Evidence[1].ID != "gone:1" {
		t.Errorf("evicted evidence should be reported missing: %+v", d.Evidence[1])
	}
	if len(d.Hosts) != 1 || d.Hosts[0] != "web01" {
		t.Errorf("hosts: %v", d.Hosts)
	}

	var e map[string]string
	if rec := get(t, seeded(), "/api/alerts/ALERT-999999", &e); rec.Code != http.StatusNotFound || e["error"] == "" {
		t.Errorf("missing alert: %d %v", rec.Code, e)
	}
}

func TestIncidentsGrouped(t *testing.T) {
	var incs []incident
	get(t, seeded(), "/api/incidents", &incs)
	if len(incs) != 2 {
		t.Fatalf("incidents: %+v", incs)
	}
	inc := incs[0] // latest activity first
	if inc.ID != "INC-00001" || inc.AlertCount != 2 || inc.MaxSeverity != "critical" {
		t.Errorf("incident: %+v", inc)
	}
	if strings.Join(inc.Hosts, ",") != "db01,web01" || strings.Join(inc.Techniques, ",") != "T1021,T1110.001" {
		t.Errorf("hosts/techniques: %v %v", inc.Hosts, inc.Techniques)
	}
	if !inc.FirstSeen.Equal(inc.Alerts[0].Timestamp) || inc.Alerts[0].ID != "ALERT-000001" || inc.LastSeen.Sub(inc.FirstSeen) != 5*time.Minute {
		t.Errorf("timeline: %+v", inc)
	}
	if incs[1].ID != "ALERT-000003" || incs[1].MaxSeverity != "low" {
		t.Errorf("standalone alert should be its own incident: %+v", incs[1])
	}
}

// Integration: load a real fixture through the pipeline and check custody + resolved evidence.
func TestLoadFixtureSessionAndEvidence(t *testing.T) {
	s := NewServer(&models.Config{MaxLogEntries: 100000})
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "multihost")
	s.Load([]string{fixture}, pipeline.Options{Config: &models.Config{}, Command: "serve"})

	var session audit.Session
	get(t, s, "/api/session", &session)
	if session.SessionID == "" || len(session.Evidence) != 2 || session.Evidence[0].SHA256Before == "" || len(session.Config.Rules) == 0 {
		t.Fatalf("session: %+v", session)
	}

	var incs []incident
	get(t, s, "/api/incidents", &incs)
	if len(incs) == 0 {
		t.Fatal("no incidents from multihost fixture")
	}
	var d alertDetail
	get(t, s, "/api/alerts/"+incs[0].Alerts[0].ID, &d)
	if len(d.Evidence) == 0 || !d.Evidence[0].Found || d.Evidence[0].Raw == "" {
		t.Errorf("evidence not resolved: %+v", d.Evidence)
	}
}
