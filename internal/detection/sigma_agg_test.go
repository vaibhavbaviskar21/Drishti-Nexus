package detection

import (
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/sigma"
	"fmt"
	"testing"
	"time"
)

const sprayRule = `title: Password Spraying
logsource: {product: linux}
detection:
  keywords: ['Failed password']
  timeframe: 10m
  condition: keywords | count(user) by src_ip > 2
level: high
tags: [attack.credential_access, attack.t1110.003]
`

func sprayEngine(t *testing.T) *Engine {
	t.Helper()
	r, err := sigma.Parse([]byte(sprayRule))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := newTestEngine(nil)
	e.AddSigma([]*sigma.Rule{r})
	return e
}

func spray(at time.Time, ip, user string) *models.LogEntry {
	seq++
	return &models.LogEntry{ID: fmt.Sprintf("t:%d", seq), Timestamp: at, Source: "srv", Severity: models.SeverityInfo,
		Message: "Failed password for " + user + " from " + ip + " port 22 ssh2",
		Fields:  map[string]interface{}{"user": user, "src_ip": ip}}
}

const sprayName = "Sigma: Password Spraying"

func TestSigmaAggregation_DistinctCountByGroup(t *testing.T) {
	e := sprayEngine(t)
	var alerts []*models.Alert
	// Same user retried: one distinct value, never a spray.
	for i := 0; i < 5; i++ {
		alerts = append(alerts, run(e, spray(t0.Add(time.Duration(i)*time.Second), "10.0.0.1", "root"))...)
	}
	// Another IP with 2 users: at the threshold (> 2 needed), no alert.
	alerts = append(alerts, run(e, spray(t0, "10.0.0.2", "a"), spray(t0.Add(time.Second), "10.0.0.2", "b"))...)
	if n := countRule(alerts, sprayName); n != 0 {
		t.Fatalf("%d alerts before the threshold", n)
	}
	// Third distinct user from 10.0.0.2 crosses it; a fourth aggregates into the same alert.
	alerts = run(e, spray(t0.Add(2*time.Second), "10.0.0.2", "c"), spray(t0.Add(3*time.Second), "10.0.0.2", "d"))
	a := findRule(alerts, sprayName)
	if countRule(alerts, sprayName) != 1 || a == nil {
		t.Fatalf("want one alert, got %v", rulesOf(alerts))
	}
	if a.Details["count"] != 4 || a.Details["group"] != "10.0.0.2" || a.Details["threshold"] != ">2" ||
		len(a.RelatedLogs) != 4 || a.Description != `Sigma rule "Password Spraying": 3 distinct user values for src_ip=10.0.0.2 within 10m0s (threshold >2)` || a.MITRETechniqueID != "T1110.003" || a.Severity != "high" || !a.Timestamp.Equal(t0) {
		t.Errorf("alert: %+v", a)
	}
}

func TestSigmaAggregation_WindowExpires(t *testing.T) {
	e := sprayEngine(t)
	alerts := run(e,
		spray(t0, "10.0.0.3", "a"),
		spray(t0.Add(6*time.Minute), "10.0.0.3", "b"),
		spray(t0.Add(11*time.Minute), "10.0.0.3", "c"), // "a" is now outside the 10m timeframe
	)
	if n := countRule(alerts, sprayName); n != 0 {
		t.Errorf("users spread over 11 minutes alerted (%d)", n)
	}
	if n := countRule(run(e, spray(t0.Add(12*time.Minute), "10.0.0.3", "d")), sprayName); n != 1 {
		t.Errorf("b, c, d within 10 minutes: %d alerts, want 1", n)
	}
}

func TestSigmaAggregation_SurvivesRestore(t *testing.T) {
	e1 := sprayEngine(t)
	run(e1, spray(t0, "10.0.0.4", "a"), spray(t0.Add(time.Second), "10.0.0.4", "b"))
	snap, err := e1.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	e2 := sprayEngine(t)
	e2.storage = e1.storage
	if err := e2.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if n := countRule(run(e2, spray(t0.Add(2*time.Second), "10.0.0.4", "c")), sprayName); n != 1 {
		t.Errorf("counts lost across restart: %d alerts", n)
	}
}
