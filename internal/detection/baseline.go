package detection

import (
	"math"
	"time"
)

// Adaptive per-source thresholds (Phase 2.1).
//
// Each correlation key (host + source IP) learns its own normal rate of failed
// attempts per window as an exponentially weighted mean and variance. The auth
// threshold rules then require max(static threshold, mean + k·σ), so a source
// that routinely fails a few logins (a monitoring probe, a misconfigured job)
// needs a larger burst to alert, while everything else keeps the configured value.
//
// Explainability: the static threshold is always the floor, and an alert whose
// threshold was raised records the baseline that raised it.
// Poisoning: a window at or above the current threshold is an anomaly and is
// never learned, so a long attack cannot teach the baseline that attacks are normal.

type sourceBaseline struct {
	Mean        float64   `json:"mean"`     // EWMA of failed attempts per window
	Variance    float64   `json:"variance"` // EWMA of the squared deviation
	Samples     int       `json:"samples"`  // windows learned
	WindowStart time.Time `json:"window_start"`
	WindowCount int       `json:"window_count"` // attempts in the open window
}

// AdaptiveSettings controls adaptive thresholds (config: adaptive_thresholds).
type AdaptiveSettings struct {
	Enabled    bool          `json:"enabled"`
	Deviation  float64       `json:"deviation"`   // k in mean + k·σ
	Alpha      float64       `json:"alpha"`       // EWMA weight of the newest window
	MinSamples int           `json:"min_samples"` // windows needed before the baseline is trusted
	Window     time.Duration `json:"-"`           // observation window (Excessive Failures window)
	Floor      int           `json:"-"`           // anomaly cut-off while learning (Excessive Failures threshold)
}

// maxEmptyWindows bounds catch-up after a quiet gap: after 100 empty windows an
// alpha-0.1 EWMA has decayed to under 0.003% of its old value anyway.
const maxEmptyWindows = 100

// recordBaseline adds n failed attempts for key at t.
func (e *Engine) recordBaseline(key string, t time.Time, n int) {
	a := e.adaptive
	if !a.Enabled || a.Window <= 0 {
		return
	}
	b := e.state.Baselines[key]
	if b == nil {
		e.state.Baselines[key] = &sourceBaseline{WindowStart: t, WindowCount: n}
		return
	}
	if t.Before(b.WindowStart.Add(a.Window)) {
		b.WindowCount += n // out-of-order lines land in the open window
		return
	}
	e.learn(b, float64(b.WindowCount))
	empty := int(t.Sub(b.WindowStart)/a.Window) - 1
	for i := 0; i < empty && i < maxEmptyWindows; i++ {
		e.learn(b, 0)
	}
	b.WindowStart, b.WindowCount = t, n
}

// learn folds one closed window into the baseline, unless it was anomalous.
func (e *Engine) learn(b *sourceBaseline, x float64) {
	if x >= float64(e.adaptiveThreshold(b, e.adaptive.Floor)) {
		return
	}
	alpha := e.adaptive.Alpha
	if b.Samples == 0 {
		b.Mean, b.Variance = x, 0
	} else {
		d := x - b.Mean
		b.Mean += alpha * d
		b.Variance = (1 - alpha) * (b.Variance + alpha*d*d)
	}
	b.Samples++
}

func (e *Engine) adaptiveThreshold(b *sourceBaseline, static int) int {
	if b == nil || b.Samples < e.adaptive.MinSamples {
		return static
	}
	if t := int(math.Ceil(b.Mean + e.adaptive.Deviation*math.Sqrt(b.Variance))); t > static {
		return t
	}
	return static
}

// threshold returns the effective threshold for key and, when the baseline
// raised it above the static value, the details that explain why.
func (e *Engine) threshold(key string, static int) (int, map[string]interface{}) {
	if !e.adaptive.Enabled {
		return static, nil
	}
	b := e.state.Baselines[key]
	t := e.adaptiveThreshold(b, static)
	if t == static {
		return static, nil
	}
	return t, map[string]interface{}{
		"static_threshold": static,
		"baseline_mean":    math.Round(b.Mean*100) / 100,
		"baseline_stddev":  math.Round(math.Sqrt(b.Variance)*100) / 100,
		"baseline_windows": b.Samples,
	}
}
