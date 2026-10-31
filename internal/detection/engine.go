package detection

import (
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/storage"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Canonical rule names. config.yaml entries are matched against these exactly.
const (
	RuleBruteForce        = "Authentication Brute Force"
	RuleExcessiveFailures = "Excessive Authentication Failures"
	RulePrivilegeEsc      = "Privilege Escalation Indicator"
	RuleSuspiciousCommand = "Suspicious Command Execution"
	RuleInjection         = "Injection Pattern Detected"
	RuleTimeAnomaly       = "Time-based Anomaly"
	RuleLateralMovement   = "Lateral Movement Candidate"
)

// maxRelatedLogs caps evidence references stored on one aggregated alert.
const maxRelatedLogs = 50

// RuleSettings is the effective configuration of one rule (defaults merged with config.yaml).
type RuleSettings struct {
	Name      string        `json:"name"`
	Enabled   bool          `json:"enabled"`
	Severity  string        `json:"severity"`
	Threshold int           `json:"threshold,omitempty"`
	Window    time.Duration `json:"-"`
	WindowStr string        `json:"time_window,omitempty"`
}

var defaultSettings = []RuleSettings{
	{Name: RuleBruteForce, Enabled: true, Severity: "high", Threshold: 3, Window: 5 * time.Minute},
	{Name: RuleExcessiveFailures, Enabled: true, Severity: "medium", Threshold: 5, Window: 10 * time.Minute},
	{Name: RulePrivilegeEsc, Enabled: true, Severity: "medium", Window: 10 * time.Minute},
	{Name: RuleSuspiciousCommand, Enabled: true, Severity: "high", Window: 10 * time.Minute},
	{Name: RuleInjection, Enabled: true, Severity: "critical", Window: 10 * time.Minute},
	{Name: RuleTimeAnomaly, Enabled: true, Severity: "low", Window: time.Hour},
	{Name: RuleLateralMovement, Enabled: true, Severity: "critical", Window: 30 * time.Minute},
}

// Finding is what a rule reports for one entry; the engine turns findings into
// alerts, aggregating repeats and grouping alerts into incidents.
type Finding struct {
	AggKey      string // repeats of the same rule+AggKey within the rule window update one alert
	CorrKey     string // alerts with the same CorrKey close in time share an incident
	Severity    string // optional override of the configured severity
	Description string
	Details     map[string]interface{}
	Count       int // count for a new alert (default 1)
	Increment   int // added to Count when aggregated (default 1)

	Evidence  []string  // entry IDs that contributed (threshold rules), cited on the alert
	FirstSeen time.Time // earliest contributing event, when before the triggering one
	LinkTo    string    // alert this one continues: shares its incident, cross-linked
}

// DetectionRule interface for all detection rules
type DetectionRule interface {
	Name() string
	Analyze(ev *Event) *Finding
}

// Event is a log entry plus engine-derived context shared by all rules.
type Event struct {
	Entry *models.LogEntry
	Host  string
	Key   string // correlation key: host, plus remote IP when known

	AuthResult string // "failure", "success", or ""
	Attempts   int    // distinct authentication attempts this line represents (after de-duplication)

	fired map[string]bool // rules that produced a finding for this entry
}

// Engine coordinates detection rule execution
type Engine struct {
	storage  storage.Storage
	config   *models.Config
	rules    []DetectionRule
	settings map[string]RuleSettings
	warnings []string

	incidentGap time.Duration
	hoursLoc    *time.Location

	// Phase 2.1: adaptive thresholds
	baseline *BaselineTracker

	mu     sync.Mutex
	state  *State
	alerts map[string]*models.Alert // open alerts by ID (pointer cache over storage)
}

// NewEngine creates a new detection engine
func NewEngine(store storage.Storage, config *models.Config) *Engine {
	if config == nil {
		config = &models.Config{}
	}
	e := &Engine{
		storage:     store,
		config:      config,
		incidentGap: 30 * time.Minute,
		hoursLoc:    time.UTC,
		state:       newState(),
		alerts:      make(map[string]*models.Alert),
	}
	// Phase 2.1: adaptive thresholds — uses the excessive-failures window as
	// the observation window, so the baseline tracks the same time scale.
	e.baseline = NewBaselineTracker(DefaultBaselineConfig(10 * time.Minute))
	if config.IncidentGap != "" {
		if d, err := time.ParseDuration(config.IncidentGap); err == nil && d > 0 {
			e.incidentGap = d
		} else {
			e.warnings = append(e.warnings, fmt.Sprintf("invalid incident_gap %q, using %s", config.IncidentGap, e.incidentGap))
		}
	}
	if tz := config.NormalHours.Timezone; tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			e.hoursLoc = loc
		} else {
			e.warnings = append(e.warnings, fmt.Sprintf("unknown normal_hours.timezone %q, using UTC", tz))
		}
	}
	e.loadSettings()
	e.initializeRules()
	// Phase 2.1: update baseline window to match the effective excessive-failures config.
	if s, ok := e.settings[RuleExcessiveFailures]; ok && s.Window > 0 {
		e.baseline = NewBaselineTracker(DefaultBaselineConfig(s.Window))
	}
	return e
}

func (e *Engine) loadSettings() {
	e.settings = make(map[string]RuleSettings, len(defaultSettings))
	for _, s := range defaultSettings {
		s.WindowStr = s.Window.String()
		e.settings[s.Name] = s
	}
	for _, r := range e.config.Rules {
		s, ok := e.settings[r.Name]
		if !ok {
			e.warnings = append(e.warnings, fmt.Sprintf("config rule %q does not match any built-in rule; ignored", r.Name))
			continue
		}
		s.Enabled = r.Enabled
		if r.Severity != "" {
			s.Severity = r.Severity
		}
		if r.Threshold > 0 {
			s.Threshold = r.Threshold
		}
		if r.TimeWindow != "" {
			if d, err := time.ParseDuration(r.TimeWindow); err == nil && d > 0 {
				s.Window = d
				s.WindowStr = d.String()
			} else {
				e.warnings = append(e.warnings, fmt.Sprintf("rule %q: invalid time_window %q, using %s", r.Name, r.TimeWindow, s.Window))
			}
		}
		e.settings[r.Name] = s
	}
}

// initializeRules sets up the core detection rules
func (e *Engine) initializeRules() {
	e.rules = []DetectionRule{
		&BruteForceDetector{engine: e},
		&ExcessiveFailuresDetector{engine: e},
		&PrivilegeEscalationDetector{},
		&SuspiciousCommandDetector{},
		&InjectionPatternDetector{},
		&TimeAnomalyDetector{engine: e},
		&LateralMovementDetector{engine: e},
	}
}

// Settings returns the effective rule configuration, in evaluation order.
func (e *Engine) Settings() []RuleSettings {
	out := make([]RuleSettings, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, e.settings[r.Name()])
	}
	return out
}

// Warnings returns configuration problems found while building the engine.
func (e *Engine) Warnings() []string {
	return append([]string(nil), e.warnings...)
}

// IncidentGap returns the effective incident grouping gap.
func (e *Engine) IncidentGap() time.Duration {
	return e.incidentGap
}

func (e *Engine) setting(name string) RuleSettings {
	return e.settings[name]
}

// AnalyzeLog analyzes a single log entry against all detection rules and returns
// the alerts it created. Repeats that were aggregated into an existing alert are
// not returned (their Count/LastSeen are updated in storage).
func (e *Engine) AnalyzeLog(entry *models.LogEntry) []*models.Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	ev := e.prepare(entry)
	created := make([]*models.Alert, 0)

	// Phase 2.1: feed auth failures to the baseline tracker.
	if ev.AuthResult == "failure" && ev.Attempts > 0 {
		e.baseline.RecordFailures(ev.Key, entry.Timestamp, ev.Attempts)
	}

	for _, rule := range e.rules {
		s := e.settings[rule.Name()]
		if !s.Enabled {
			continue
		}
		f := rule.Analyze(ev)
		if f == nil {
			continue
		}
		ev.fired[rule.Name()] = true
		if alert := e.emit(rule.Name(), s, f, entry); alert != nil {
			created = append(created, alert)
		}
	}

	e.state.Processed++
	if e.state.Processed%sweepEvery == 0 {
		e.sweep()
		e.baseline.Sweep(e.state.Latest, e.maxAuthWindow()*10)
	}
	return created
}

// prepare derives the shared Event: host/correlation key and de-duplicated auth attempts.
func (e *Engine) prepare(entry *models.LogEntry) *Event {
	ev := &Event{Entry: entry, fired: make(map[string]bool)}
	ev.Host = entry.Source
	if ev.Host == "" {
		ev.Host = "unknown"
	}
	ev.Key = "host=" + ev.Host
	if ip := fieldString(entry, "src_ip"); ip != "" {
		ev.Key += "|ip=" + ip
	}

	if entry.Timestamp.After(e.state.Latest) {
		e.state.Latest = entry.Timestamp
	}

	result, weight := classifyAuth(entry)
	ev.AuthResult = result
	if result == "" {
		return ev
	}
	ev.Attempts = e.dedupeAttempt(entry, ev, weight)
	if result == "failure" && ev.Attempts > 0 {
		e.recordFailure(ev.Key, entry.Timestamp, ev.Attempts, entry.ID)
	}
	return ev
}

// attemptWindow bounds how far apart lines of a single sshd attempt can be
// ("Invalid user" is logged at connect, "Failed password" after the password prompt).
const attemptWindow = 5 * time.Second

// dedupeAttempt collapses the several lines one login attempt produces (pam_unix
// failure + "Failed password" + "Invalid user", same PID, same second) into one.
// A repeat of the same line kind from the same PID is a new attempt.
func (e *Engine) dedupeAttempt(entry *models.LogEntry, ev *Event, weight int) int {
	pid := fieldString(entry, "pid")
	kind := fieldString(entry, "auth_event")
	if pid == "" || kind == "" {
		return weight
	}
	gk := ev.Host + "|" + pid + "|" + ev.AuthResult
	g, ok := e.state.AttemptGroups[gk]
	if ok && absDur(entry.Timestamp.Sub(g.Start)) <= attemptWindow && !g.Kinds[kind] {
		g.Kinds[kind] = true
		return 0
	}
	e.state.AttemptGroups[gk] = &attemptGroup{Start: entry.Timestamp, Kinds: map[string]bool{kind: true}}
	return weight
}

func (e *Engine) recordFailure(key string, ts time.Time, n int, id string) {
	list := append(e.state.Failures[key], failureMark{At: ts, N: n, ID: id})
	// Keep only what the longest auth window can still use.
	horizon := ts.Add(-e.maxAuthWindow())
	i := 0
	for i < len(list) && list[i].At.Before(horizon) {
		i++
	}
	e.state.Failures[key] = list[i:]
}

func (e *Engine) maxAuthWindow() time.Duration {
	w := e.settings[RuleBruteForce].Window
	if x := e.settings[RuleExcessiveFailures].Window; x > w {
		w = x
	}
	return w
}

// failureWindow is the set of failed attempts that make a threshold decision.
type failureWindow struct {
	Attempts int
	First    time.Time
	IDs      []string // entry IDs of the contributing lines (evidence)
}

// failuresWithin sums attempts for key with at ∈ [t-window, t] (both ends inclusive).
func (e *Engine) failuresWithin(key string, t time.Time, window time.Duration) failureWindow {
	var w failureWindow
	from := t.Add(-window)
	for _, f := range e.state.Failures[key] {
		if !f.At.Before(from) && !f.At.After(t) {
			w.Attempts += f.N
			if w.First.IsZero() || f.At.Before(w.First) {
				w.First = f.At
			}
			w.IDs = append(w.IDs, f.ID)
		}
	}
	return w
}

// emit turns a finding into a new alert or aggregates it into an open one.
func (e *Engine) emit(rule string, s RuleSettings, f *Finding, entry *models.LogEntry) *models.Alert {
	if f.Count <= 0 {
		f.Count = 1
	}
	if f.Increment <= 0 {
		f.Increment = 1
	}
	openKey := rule + "\x00" + f.AggKey

	if o, ok := e.state.Open[openKey]; ok && absDur(entry.Timestamp.Sub(o.LastSeen)) <= s.Window {
		if alert := e.alerts[o.AlertID]; alert != nil {
			alert.Count += f.Increment
			if entry.Timestamp.After(alert.LastSeen) {
				alert.LastSeen = entry.Timestamp
				o.LastSeen = entry.Timestamp
			}
			if len(alert.RelatedLogs) < maxRelatedLogs {
				alert.RelatedLogs = append(alert.RelatedLogs, entry.ID)
			} else {
				alert.Details["related_logs_truncated"] = true
			}
			for k, v := range f.Details {
				alert.Details[k] = v
			}
			e.touchIncident(f.CorrKey, entry.Timestamp)
			e.storage.UpdateAlert(alert)
			return nil
		}
	}

	severity := s.Severity
	if f.Severity != "" {
		severity = f.Severity
	}
	if f.Details == nil {
		f.Details = map[string]interface{}{}
	}
	e.state.AlertSeq++
	alert := &models.Alert{
		ID:             fmt.Sprintf("ALERT-%06d", e.state.AlertSeq),
		IncidentID:     e.incidentFor(f.CorrKey, entry.Timestamp),
		CorrelationKey: f.CorrKey,
		Timestamp:      entry.Timestamp,
		LastSeen:       entry.Timestamp,
		RuleName:       rule,
		Severity:       severity,
		Description:    f.Description,
		RelatedLogs:    evidence(f.Evidence, entry.ID),
		Details:        f.Details,
		Count:          f.Count,
	}
	tech := ATTACKForRule(rule)
	alert.MITRETechniqueID, alert.MITRETechniqueName, alert.MITRETactic = tech.ID, tech.Name, tech.Tactic
	if !f.FirstSeen.IsZero() && f.FirstSeen.Before(alert.Timestamp) {
		alert.Timestamp = f.FirstSeen
	}
	if len(f.Evidence)+1 > maxRelatedLogs {
		alert.Details["related_logs_truncated"] = true
	}
	e.state.Open[openKey] = &openAlert{AlertID: alert.ID, LastSeen: entry.Timestamp}
	e.alerts[alert.ID] = alert
	e.storage.AddAlert(alert)

	if rule == RuleBruteForce {
		e.linkSuperseded(alert, RuleExcessiveFailures, f.AggKey)
	}
	if origin := e.alerts[f.LinkTo]; origin != nil {
		e.link(origin, alert)
	}
	return alert
}

// linkSuperseded links a higher-fidelity alert with the open lower-fidelity alert
// describing the same activity (same aggregation key), instead of leaving two
// unrelated alerts. The lower one is kept as supporting evidence and marked.
func (e *Engine) linkSuperseded(high *models.Alert, lowerRule, aggKey string) {
	o, ok := e.state.Open[lowerRule+"\x00"+aggKey]
	if !ok {
		return
	}
	low := e.alerts[o.AlertID]
	if low == nil || absDur(high.Timestamp.Sub(o.LastSeen)) > e.settings[lowerRule].Window {
		return
	}
	low.Details["superseded_by"] = high.ID
	e.link(low, high)
}

// link cross-references two alerts and moves the later one into the earlier one's incident.
func (e *Engine) link(earlier, later *models.Alert) {
	earlier.RelatedAlerts = appendUnique(earlier.RelatedAlerts, later.ID)
	later.RelatedAlerts = appendUnique(later.RelatedAlerts, earlier.ID)
	later.IncidentID = earlier.IncidentID
	e.storage.UpdateAlert(earlier)
	e.storage.UpdateAlert(later)
}

func (e *Engine) incidentFor(corrKey string, t time.Time) string {
	if inc, ok := e.state.Incidents[corrKey]; ok && absDur(t.Sub(inc.LastSeen)) <= e.incidentGap {
		if t.After(inc.LastSeen) {
			inc.LastSeen = t
		}
		return inc.ID
	}
	e.state.IncidentSeq++
	id := fmt.Sprintf("INC-%05d", e.state.IncidentSeq)
	e.state.Incidents[corrKey] = &incidentState{ID: id, LastSeen: t}
	return id
}

func (e *Engine) touchIncident(corrKey string, t time.Time) {
	if inc, ok := e.state.Incidents[corrKey]; ok && t.After(inc.LastSeen) {
		inc.LastSeen = t
	}
}

// sweep drops tracking state that can no longer influence any rule, bounding
// memory on long tail sessions with many distinct source IPs.
func (e *Engine) sweep() {
	now := e.state.Latest
	authHorizon := now.Add(-e.maxAuthWindow())
	for k, list := range e.state.Failures {
		if len(list) == 0 || list[len(list)-1].At.Before(authHorizon) {
			delete(e.state.Failures, k)
		}
	}
	for k, g := range e.state.AttemptGroups {
		if now.Sub(g.Start) > attemptWindow {
			delete(e.state.AttemptGroups, k)
		}
	}
	var longest time.Duration
	for _, s := range e.settings {
		if s.Window > longest {
			longest = s.Window
		}
	}
	for k, o := range e.state.Open {
		if now.Sub(o.LastSeen) > longest {
			delete(e.state.Open, k)
			delete(e.alerts, o.AlertID)
		}
	}
	for k, inc := range e.state.Incidents {
		if now.Sub(inc.LastSeen) > e.incidentGap {
			delete(e.state.Incidents, k)
		}
	}
	for user, c := range e.state.Compromised {
		if now.Sub(c.At) > e.settings[RuleLateralMovement].Window {
			delete(e.state.Compromised, user)
		}
	}
}

const sweepEvery = 10000

// classifyAuth returns "failure"/"success"/"" and the attempt weight of an entry.
// Structured fields from the parser are authoritative; free-text keywords are
// only a fallback for formats without an extractor.
func classifyAuth(entry *models.LogEntry) (string, int) {
	if r := fieldString(entry, "auth_result"); r != "" {
		if r != "failure" && r != "success" {
			return "", 0
		}
		n := 1
		if c, ok := entry.Fields["auth_count"].(int); ok && c > 0 {
			n = c
		}
		return r, n
	}
	if isAuthFailure(entry) {
		return "failure", 1
	}
	if isAuthSuccess(entry) {
		return "success", 1
	}
	return "", 0
}

// isAuthFailure checks if a log entry indicates authentication failure
func isAuthFailure(entry *models.LogEntry) bool {
	msg := strings.ToLower(entry.Message)
	keywords := []string{
		"failed", "failure", "invalid", "incorrect",
		"authentication failed", "login failed", "access denied",
		"bad password", "invalid user", "failed login",
	}

	for _, keyword := range keywords {
		if strings.Contains(msg, keyword) {
			// Check for auth context too
			if strings.Contains(msg, "auth") || strings.Contains(msg, "login") ||
				strings.Contains(msg, "password") || strings.Contains(msg, "user") {
				return true
			}
		}
	}

	return false
}

// isAuthSuccess checks if a log entry indicates authentication success
func isAuthSuccess(entry *models.LogEntry) bool {
	msg := strings.ToLower(entry.Message)
	keywords := []string{
		"accepted", "successful login", "logged in",
		"authentication successful",
	}

	for _, keyword := range keywords {
		if strings.Contains(msg, keyword) {
			return true
		}
	}

	return false
}

// isOutsideNormalHours checks if timestamp is outside configured normal hours
func (e *Engine) isOutsideNormalHours(t time.Time) bool {
	start := e.config.NormalHours.Start
	end := e.config.NormalHours.End
	if start == end {
		// Not configured (or a 24h window), skip check
		return false
	}
	hour := t.In(e.hoursLoc).Hour()
	if start < end {
		// Normal case: e.g., 9-17
		return hour < start || hour >= end
	}
	// Wrap around: e.g., 22-6
	return hour >= end && hour < start
}

func fieldString(entry *models.LogEntry, key string) string {
	if entry.Fields == nil {
		return ""
	}
	if s, ok := entry.Fields[key].(string); ok {
		return s
	}
	return ""
}

// evidence returns the unique contributing entry IDs plus the triggering one, capped.
func evidence(ids []string, trigger string) []string {
	out := make([]string, 0, len(ids)+1)
	seen := make(map[string]bool, len(ids)+1)
	for _, id := range append(ids, trigger) {
		if id == "" || seen[id] || len(out) >= maxRelatedLogs {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// sortedKeys is used for deterministic iteration in snapshots and tests.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
