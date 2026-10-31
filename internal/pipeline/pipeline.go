// Package pipeline runs the full ingest path shared by every command:
// hash evidence → open read-only → assemble/parse lines → detect → audit.
package pipeline

import (
	"container/heap"
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/detection"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/parser"
	"drishti-nexus/internal/storage"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Options configure a pipeline run.
type Options struct {
	Config     *models.Config
	ConfigPath string         // recorded (and hashed) in the audit trail; "" = built-in defaults
	Location   *time.Location // zone assumed for timestamps without an offset (default UTC)

	// Store receives entries and alerts. Default: in-memory.
	Store       storage.Storage
	StorageDesc string // e.g. "sqlite:case.db"; default "memory"

	// KeepLogs=false skips storing entries (benchmarks on large corpora); alerts are always stored.
	KeepLogs bool

	// OnEntry is called for every parsed entry with the alerts it created.
	OnEntry func(entry *models.LogEntry, alerts []*models.Alert)

	// Audit trail. Empty AuditLogPath disables the on-disk audit log (tests,
	// benchmarks); the Session is still built and returned.
	Command      string
	Args         []string
	AuditLogPath string
	ToolVersion  string
}

// Stats summarise a run.
type Stats struct {
	Lines        int            `json:"lines"`
	Entries      int            `json:"entries"`
	ParseQuality map[string]int `json:"parse_quality"`
	ByParser     map[string]int `json:"by_parser"`
	Repairs      map[string]int `json:"repairs"` // truncated, encoding_repaired, dst, timestamp_inherited, ...
	AlertsByRule map[string]int `json:"alerts_by_rule"`
	Alerts       int            `json:"alerts"`
	Incidents    int            `json:"incidents"`
	Duration     time.Duration  `json:"-"`
	DurationMs   int64          `json:"duration_ms"`
}

func newStats() *Stats {
	return &Stats{
		ParseQuality: map[string]int{},
		ByParser:     map[string]int{},
		Repairs:      map[string]int{},
		AlertsByRule: map[string]int{},
	}
}

// Result of a run.
type Result struct {
	Session *audit.Session
	Engine  *detection.Engine
	Store   storage.Storage
	Stats   *Stats
}

// Alerts returns stored alerts in creation order.
func (r *Result) Alerts() []*models.Alert {
	return r.Store.GetAlerts()
}

// Prepare builds the session (evidence hashed, config recorded), engine and store
// and writes the session_start audit record. Callers that drive their own loop
// (tail) use this; batch commands use Run.
func Prepare(paths []string, opts *Options) (*Result, error) {
	if opts.Config == nil {
		opts.Config = &models.Config{}
	}
	if opts.Location == nil {
		opts.Location = time.UTC
	}
	if opts.Store == nil {
		max := opts.Config.MaxLogEntries
		if max <= 0 {
			max = 100000
		}
		opts.Store = storage.NewMemoryStorage(max)
	}
	if opts.StorageDesc == "" {
		opts.StorageDesc = "memory"
	}

	session := audit.NewSession(opts.Command, opts.Args, opts.ToolVersion)
	for _, p := range paths {
		if _, err := session.AddEvidence(p); err != nil {
			return nil, err
		}
	}
	if err := session.HashConfig(opts.ConfigPath); err != nil {
		return nil, fmt.Errorf("hash config: %w", err)
	}

	engine := detection.NewEngine(opts.Store, opts.Config)
	session.Config.Rules = RuleConfigs(engine)
	session.Config.NormalHours = describeHours(opts.Config.NormalHours)
	session.Config.IncidentGap = engine.IncidentGap().String()
	session.Config.AssumedTimezone = opts.Location.String()
	session.Config.Storage = opts.StorageDesc
	session.Config.Warnings = append(session.Config.Warnings, engine.Warnings()...)

	if opts.AuditLogPath != "" {
		if err := audit.Append(opts.AuditLogPath, "session_start", session); err != nil {
			return nil, err
		}
	}
	return &Result{Session: session, Engine: engine, Store: opts.Store, Stats: newStats()}, nil
}

// Run expands directories, then processes every file through one engine in
// event-time order across files, so activity spanning hosts or rotated files
// correlates. It then re-verifies evidence hashes and writes session_end.
// Outputs added afterwards via Finish.
func Run(paths []string, opts Options) (*Result, error) {
	paths, err := ExpandPaths(paths)
	if err != nil {
		return nil, err
	}
	res, err := Prepare(paths, &opts)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	err = res.processMerged(&opts)
	res.finishStats(start)
	if err != nil {
		_ = res.Finish(&opts, "error: "+err.Error())
		return res, err
	}
	return res, nil
}

// ExpandPaths replaces each directory with the regular files beneath it, in
// lexical order. Hidden files and directories (".cache", ".git") are skipped.
func ExpandPaths(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		n := len(out)
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path != p && strings.HasPrefix(d.Name(), ".") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if len(out) == n {
			return nil, fmt.Errorf("%s: no log files found", p)
		}
	}
	return out, nil
}

// fileStream yields the parsed entries of one evidence file, in file order.
type fileStream struct {
	idx  int
	path string
	lr   *LineReader
	reg  *parser.ParserRegistry
	next *models.LogEntry
	done bool
}

// advance sets next to the file's next entry, or nil at the end.
func (s *fileStream) advance(stats *Stats) error {
	s.next = nil
	for !s.done {
		line, _, err := s.lr.Next()
		if errors.Is(err, io.EOF) {
			s.done = true
			s.next, _ = s.reg.Flush()
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", s.path, err)
		}
		stats.Lines++
		if entry, _ := s.reg.Parse(line); entry != nil {
			s.next = entry
			return nil
		}
	}
	return nil
}

// streamHeap orders files by their next entry's timestamp (ties: argument order).
type streamHeap []*fileStream

func (h streamHeap) Len() int { return len(h) }
func (h streamHeap) Less(i, j int) bool {
	a, b := h[i].next.Timestamp, h[j].next.Timestamp
	if !a.Equal(b) {
		return a.Before(b)
	}
	return h[i].idx < h[j].idx
}
func (h streamHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *streamHeap) Push(x any)   { *h = append(*h, x.(*fileStream)) }
func (h *streamHeap) Pop() any {
	old := *h
	s := old[len(old)-1]
	*h = old[:len(old)-1]
	return s
}

// processMerged k-way merges all evidence files by event time. Each file keeps
// its own order, so a single file is processed exactly as it is written.
// shortcut: keeps every evidence file open at once; batch the merge if a case
// ever exceeds the OS open-file limit.
func (r *Result) processMerged(opts *Options) error {
	var h streamHeap
	for i, ev := range r.Session.Evidence {
		f, err := audit.OpenEvidence(ev.Path)
		if err != nil {
			return err
		}
		defer f.Close()
		s := &fileStream{
			idx:  i,
			path: ev.Path,
			lr:   NewLineReader(f),
			reg: parser.NewParserRegistryWithOptions(parser.Options{
				SourceLabel: ev.Label,
				Location:    opts.Location,
				Reference:   ev.ModTime,
			}),
		}
		if err := s.advance(r.Stats); err != nil {
			return err
		}
		if s.next != nil {
			h = append(h, s)
		}
	}
	heap.Init(&h)
	for h.Len() > 0 {
		s := h[0]
		r.Handle(s.next, opts)
		if err := s.advance(r.Stats); err != nil {
			return err
		}
		if s.next == nil {
			heap.Pop(&h)
		} else {
			heap.Fix(&h, 0)
		}
	}
	return nil
}

// Handle stores, analyzes and counts one parsed entry.
func (r *Result) Handle(entry *models.LogEntry, opts *Options) []*models.Alert {
	s := r.Stats
	s.Entries++
	s.ParseQuality[entry.ParseQuality]++
	s.ByParser[entry.Parser]++
	for _, k := range []string{"truncated", "encoding_repaired", "dst", "timestamp_inherited", "timestamp_missing", "json_incomplete"} {
		if _, ok := entry.Fields[k]; ok {
			s.Repairs[k]++
		}
	}
	if opts.KeepLogs {
		r.Store.AddLog(entry)
	}
	alerts := r.Engine.AnalyzeLog(entry)
	if opts.OnEntry != nil {
		opts.OnEntry(entry, alerts)
	}
	return alerts
}

func (r *Result) finishStats(start time.Time) {
	r.Stats.Duration = time.Since(start)
	r.Stats.DurationMs = r.Stats.Duration.Milliseconds()
	r.RecountAlerts()
}

// RecountAlerts refreshes alert/incident totals from the store.
func (r *Result) RecountAlerts() {
	s := r.Stats
	s.AlertsByRule = map[string]int{}
	incidents := map[string]bool{}
	alerts := r.Store.GetAlerts()
	for _, a := range alerts {
		s.AlertsByRule[a.RuleName]++
		incidents[a.IncidentID] = true
	}
	s.Alerts = len(alerts)
	s.Incidents = len(incidents)
}

// Finish records results, re-verifies evidence and appends session_end.
// Call after writing outputs (Session.AddOutput) so they are covered.
func (r *Result) Finish(opts *Options, status string) error {
	r.Session.Results = &audit.Results{
		Lines:        r.Stats.Lines,
		Entries:      r.Stats.Entries,
		ParseQuality: r.Stats.ParseQuality,
		Alerts:       r.Stats.Alerts,
		Incidents:    r.Stats.Incidents,
		AlertsByRule: r.Stats.AlertsByRule,
	}
	r.Session.Finish(status)
	if opts.AuditLogPath != "" {
		if err := audit.Append(opts.AuditLogPath, "session_end", r.Session); err != nil {
			return err
		}
	}
	if t := r.Session.Tampered(); len(t) > 0 {
		return fmt.Errorf("evidence changed during analysis (hash mismatch): %s", strings.Join(t, ", "))
	}
	return nil
}

// RuleConfigs converts the engine's effective settings for the audit trail.
func RuleConfigs(engine *detection.Engine) []audit.RuleConfig {
	var out []audit.RuleConfig
	for _, s := range engine.Settings() {
		out = append(out, audit.RuleConfig{
			Name:      s.Name,
			Enabled:   s.Enabled,
			Severity:  s.Severity,
			Threshold: s.Threshold,
			Window:    s.WindowStr,
		})
	}
	return out
}

func describeHours(h models.NormalHours) string {
	tz := h.Timezone
	if tz == "" {
		tz = "UTC"
	}
	if h.Start == h.End {
		return "disabled"
	}
	return fmt.Sprintf("%02d:00-%02d:00 %s", h.Start, h.End, tz)
}

// SortedKeys returns map keys in order, for stable report output.
func SortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
