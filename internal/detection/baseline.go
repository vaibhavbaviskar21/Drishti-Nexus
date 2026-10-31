package detection

import (
	"math"
	"sync"
	"time"
)

// BaselineTracker maintains per-source rolling statistics for adaptive thresholds.
// Instead of a hardcoded "5 failures in 10 minutes", the tracker learns each
// source's normal failure rate and flags deviations from its own baseline.
//
// The static threshold from config.yaml is always kept as a floor: we never
// require fewer events than the configured minimum to fire a rule, so behavior
// stays explainable and auditable.
//
// Design decisions:
//   - Uses an exponentially weighted moving average (EWMA) rather than a simple
//     sliding window, because EWMA is O(1) in both time and space per update,
//     has no edge effects at window boundaries, and adapts smoothly to gradual
//     changes in baseline activity (shift changes, weekends).
//   - The deviation factor (default 3.0 stddevs) is a tunable parameter, not a
//     magic number: 3σ on a roughly normal distribution catches ~0.3% of events,
//     which is a reasonable starting point for an anomaly detector.
//   - A minimum sample count (MinSamples) prevents the tracker from learning
//     from too few observations, which would make the baseline unreliable.
type BaselineTracker struct {
	mu      sync.Mutex
	sources map[string]*sourceBaseline
	config  BaselineConfig
}

// BaselineConfig controls adaptive threshold behaviour.
type BaselineConfig struct {
	// DeviationFactor is the number of standard deviations above the mean
	// before a rate is considered anomalous. Default: 3.0.
	DeviationFactor float64

	// Alpha is the EWMA smoothing factor (0 < α ≤ 1). Smaller values give
	// more weight to history; larger values track recent changes faster.
	// Default: 0.1 (≈ effective window of ~10 observations).
	Alpha float64

	// MinSamples is the minimum number of window observations before the
	// adaptive threshold is used instead of the static floor. Default: 5.
	MinSamples int

	// WindowDuration is the size of each observation window. Failures within
	// one window are counted as a single observation for the EWMA.
	// Default: matches the rule's configured time_window.
	WindowDuration time.Duration
}

// DefaultBaselineConfig returns a sensible starting configuration.
func DefaultBaselineConfig(ruleWindow time.Duration) BaselineConfig {
	return BaselineConfig{
		DeviationFactor: 3.0,
		Alpha:           0.1,
		MinSamples:      5,
		WindowDuration:  ruleWindow,
	}
}

// sourceBaseline tracks per-source failure rate statistics using EWMA.
type sourceBaseline struct {
	// EWMA of the failure count per window.
	Mean float64
	// EWMA of the squared deviation (for computing running stddev).
	Variance float64

	Samples int // total observation windows seen

	// Current window accumulator.
	WindowStart time.Time
	WindowCount int
}

// NewBaselineTracker creates a tracker with the given config.
func NewBaselineTracker(cfg BaselineConfig) *BaselineTracker {
	if cfg.DeviationFactor <= 0 {
		cfg.DeviationFactor = 3.0
	}
	if cfg.Alpha <= 0 || cfg.Alpha > 1 {
		cfg.Alpha = 0.1
	}
	if cfg.MinSamples <= 0 {
		cfg.MinSamples = 5
	}
	return &BaselineTracker{
		sources: make(map[string]*sourceBaseline),
		config:  cfg,
	}
}

// RecordFailures adds failure observations for a source key at time t.
func (bt *BaselineTracker) RecordFailures(sourceKey string, t time.Time, count int) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	b := bt.sources[sourceKey]
	if b == nil {
		b = &sourceBaseline{WindowStart: t}
		bt.sources[sourceKey] = b
	}

	// If t is within the current window, accumulate.
	if !t.Before(b.WindowStart) && t.Before(b.WindowStart.Add(bt.config.WindowDuration)) {
		b.WindowCount += count
		return
	}

	// Window boundary crossed: commit the current window as an observation,
	// then start a new window.
	if b.Samples > 0 || b.WindowCount > 0 {
		bt.commitWindow(b)
	}

	// Fast-forward through any empty windows between the last and now.
	// Each empty window is an observation of 0 failures.
	if bt.config.WindowDuration > 0 {
		elapsed := t.Sub(b.WindowStart)
		emptyWindows := int(elapsed/bt.config.WindowDuration) - 1
		if emptyWindows > 0 {
			// Cap to avoid huge loops for large time gaps.
			if emptyWindows > 100 {
				emptyWindows = 100
			}
			for i := 0; i < emptyWindows; i++ {
				b.WindowCount = 0
				bt.commitWindow(b)
			}
		}
	}

	b.WindowStart = t
	b.WindowCount = count
}

// commitWindow records the current window's count as one EWMA observation.
func (bt *BaselineTracker) commitWindow(b *sourceBaseline) {
	x := float64(b.WindowCount)
	α := bt.config.Alpha

	if b.Samples == 0 {
		b.Mean = x
		b.Variance = 0
	} else {
		diff := x - b.Mean
		b.Mean += α * diff
		b.Variance = (1 - α) * (b.Variance + α*diff*diff)
	}
	b.Samples++
	b.WindowCount = 0
}

// AdaptiveThreshold returns the dynamic threshold for a source key.
// If the source has insufficient data (< MinSamples), it returns the staticFloor.
// The result is always >= staticFloor to keep behavior auditable.
func (bt *BaselineTracker) AdaptiveThreshold(sourceKey string, staticFloor int) int {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	b := bt.sources[sourceKey]
	if b == nil || b.Samples < bt.config.MinSamples {
		return staticFloor
	}

	stddev := math.Sqrt(b.Variance)
	adaptive := int(math.Ceil(b.Mean + bt.config.DeviationFactor*stddev))

	// Never go below the static floor.
	if adaptive < staticFloor {
		return staticFloor
	}
	return adaptive
}

// IsAnomaly reports whether a count of failures for sourceKey in the current
// window significantly exceeds the learned baseline. If insufficient data,
// falls back to comparing against staticFloor.
func (bt *BaselineTracker) IsAnomaly(sourceKey string, count int, staticFloor int) bool {
	threshold := bt.AdaptiveThreshold(sourceKey, staticFloor)
	return count >= threshold
}

// Stats returns the current baseline statistics for a source key (for audit/debug).
func (bt *BaselineTracker) Stats(sourceKey string) (mean, stddev float64, samples int) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	b := bt.sources[sourceKey]
	if b == nil {
		return 0, 0, 0
	}
	return b.Mean, math.Sqrt(b.Variance), b.Samples
}

// Sweep removes tracking state for sources that have been idle for longer than
// maxIdle, bounding memory on long sessions with many distinct sources.
func (bt *BaselineTracker) Sweep(now time.Time, maxIdle time.Duration) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	for k, b := range bt.sources {
		if now.Sub(b.WindowStart) > maxIdle {
			delete(bt.sources, k)
		}
	}
}
