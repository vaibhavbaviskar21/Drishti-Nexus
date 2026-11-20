package detection

import (
	"drishti-nexus/internal/models"
	"testing"
	"time"
)

const noisyIP = "10.9.9.9"

var pidSeq = 50000

// failBurst sends n failed logins from ip within 30 seconds starting at at.
func failBurst(e *Engine, at time.Time, ip string, n int) []*models.Alert {
	var out []*models.Alert
	for i := 0; i < n; i++ {
		pidSeq++
		out = append(out, e.AnalyzeLog(fail(at.Add(time.Duration(i)*5*time.Second), ip, pidSeq))...)
	}
	return out
}

// noisySource: 4 failed logins (below the static threshold of 5) in every other
// 10-minute window for ~6.5 hours: a probe that routinely fails, never an attack.
func noisySource(e *Engine) time.Time {
	at := t0
	for w := 0; w < 20; w++ {
		failBurst(e, at, noisyIP, 4)
		at = at.Add(20 * time.Minute)
	}
	return at.Add(30 * time.Minute)
}

func TestAdaptive_NoisySourceNeedsLargerBurst(t *testing.T) {
	e, _ := newTestEngine(nil)
	burstAt := noisySource(e)
	key := "host=srv|ip=" + noisyIP

	alerts := failBurst(e, burstAt, noisyIP, 1)
	th, why := e.threshold(key, 5)
	if th <= 5 || why == nil || why["static_threshold"] != 5 {
		t.Fatalf("threshold for a noisy source = %d (%v), want above the static 5", th, why)
	}
	// One below the learned threshold: no alert, although the static rule (5) would fire.
	alerts = append(alerts, failBurst(e, burstAt.Add(10*time.Second), noisyIP, th-2)...)
	if n := countRule(alerts, RuleExcessiveFailures); n != 0 {
		t.Fatalf("%d attempts (threshold %d) raised %d alerts", th-1, th, n)
	}
	// Exactly at the threshold: alert, explaining the raised bar.
	alerts = failBurst(e, burstAt.Add(5*time.Minute), noisyIP, 1)
	a := findRule(alerts, RuleExcessiveFailures)
	if a == nil {
		t.Fatalf("no alert at the adaptive threshold %d", th)
	}
	if a.Details["threshold"] != th || a.Details["static_threshold"] != 5 || a.Details["baseline_windows"] == nil {
		t.Errorf("alert does not explain its threshold: %v", a.Details)
	}

	// A source with no history in the same engine keeps the static threshold.
	if n := countRule(failBurst(e, burstAt, "203.0.113.77", 5), RuleExcessiveFailures); n != 1 {
		t.Errorf("new source: %d alerts at the static threshold, want 1", n)
	}
}

func TestAdaptive_AttacksAreNotLearned(t *testing.T) {
	e, _ := newTestEngine(nil)
	at := t0
	for w := 0; w < 30; w++ { // 20 failures every window for 5 hours
		failBurst(e, at, "198.51.100.66", 20)
		at = at.Add(10 * time.Minute)
	}
	if th, _ := e.threshold("host=srv|ip=198.51.100.66", 5); th != 5 {
		t.Errorf("a sustained attack raised its own threshold to %d", th)
	}
}

func TestAdaptive_Disabled(t *testing.T) {
	e, _ := newTestEngine(&models.Config{
		NormalHours: models.NormalHours{Start: 9, End: 17},
		Adaptive:    &models.AdaptiveConfig{Enabled: false},
	})
	noisySource(e)
	if th, why := e.threshold("host=srv|ip="+noisyIP, 5); th != 5 || why != nil {
		t.Errorf("disabled: threshold %d %v", th, why)
	}
}

func TestAdaptive_SurvivesRestore(t *testing.T) {
	e1, store := newTestEngine(nil)
	noisySource(e1)
	before, _ := e1.threshold("host=srv|ip="+noisyIP, 5)
	snap, err := e1.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	e2 := NewEngine(store, &models.Config{NormalHours: models.NormalHours{Start: 9, End: 17}})
	if err := e2.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if after, _ := e2.threshold("host=srv|ip="+noisyIP, 5); after != before || after <= 5 {
		t.Errorf("baseline lost across restart: %d before, %d after", before, after)
	}
}
