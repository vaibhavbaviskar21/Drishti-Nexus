// Package report renders a scan as an analyst-facing incident report (HTML and
// PDF): summary, parse quality, incidents as timelines with ATT&CK tags and cited
// evidence lines, chain of custody and the audit session. See docs/REPORTING.md.
package report

import (
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/pipeline"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Evidence lines shown per alert, and runes shown per line. The JSON report
// keeps the full list; the report stays readable on alerts with 200+ matches.
const (
	maxEvidenceLines = 10
	maxEvidenceRunes = 400
)

// AISummary is an optional AI-generated narrative for one incident. It is never
// evidence: it is rendered separately, labelled, only when present.
type AISummary struct {
	IncidentID, Model, Text string
	Verified                bool     // every claim checked against the incident's alerts and evidence
	Unsupported             []string // claims the check could not tie to the data
}

// Data is everything a report shows. Build fills it from a pipeline result.
type Data struct {
	GeneratedAt time.Time
	Session     *audit.Session
	Stats       *pipeline.Stats
	Quality     []Count // parse quality, Clean/Partial/BestEffort order
	Parsers     []Count
	Repairs     []Count
	Rules       []Count // alerts by rule
	Techniques  []Technique
	Incidents   []Incident
	AISummaries []AISummary
}

// Count is one row of a breakdown table.
type Count struct {
	Name string
	N    int
	Pct  float64
}

// Technique is an ATT&CK technique observed in the scan.
type Technique struct {
	ID, Name, Tactic string
	Alerts           int
}

// Incident is a group of alerts sharing an IncidentID, in time order.
type Incident struct {
	ID         string
	Severity   string // highest of its alerts
	Start, End time.Time
	Keys       []string // correlation keys (host / source IP)
	Techniques []string
	Alerts     []Alert
}

// Alert is an alert with its cited evidence resolved to log lines.
type Alert struct {
	*models.Alert
	Details  []KV
	Evidence []Line
	Omitted  int // cited lines not shown (see maxEvidenceLines)
}

// KV is one alert detail.
type KV struct{ Key, Value string }

// Line is one cited evidence entry. Found is false when the entry was not
// retained in the store (-alerts-only, or the memory store cap was reached).
type Line struct {
	ID     string
	Time   time.Time
	Source string
	Text   string
	Found  bool
}

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// Build assembles report data from a finished pipeline run. It re-hashes the
// evidence (read-only) so the report carries before/after hashes; Finish
// re-verifies again for the session_end audit record.
func Build(res *pipeline.Result) Data {
	for _, ev := range res.Session.Evidence {
		if ev.BytesAnalyzed == 0 {
			if err := ev.Reverify(); err != nil {
				res.Session.Config.Warnings = append(res.Session.Config.Warnings, fmt.Sprintf("re-hash %s: %v", ev.Path, err))
			}
		}
	}

	st := res.Stats
	d := Data{
		GeneratedAt: time.Now().UTC(),
		Session:     res.Session,
		Stats:       st,
		Parsers:     counts(st.ByParser, st.Entries),
		Repairs:     counts(st.Repairs, st.Entries),
		Rules:       counts(st.AlertsByRule, st.Alerts),
	}
	for _, q := range []string{models.QualityClean, models.QualityPartial, models.QualityBestEffort} {
		d.Quality = append(d.Quality, Count{q, st.ParseQuality[q], pct(st.ParseQuality[q], st.Entries)})
	}

	logs := map[string]*models.LogEntry{}
	for _, e := range res.Store.GetLogs() {
		logs[e.ID] = e
	}
	d.Incidents, d.Techniques = group(res.Alerts(), logs)
	return d
}

func group(alerts []*models.Alert, logs map[string]*models.LogEntry) ([]Incident, []Technique) {
	byID := map[string]*Incident{}
	var order []string
	techs := map[string]*Technique{}
	for _, a := range alerts {
		id := a.IncidentID
		if id == "" {
			id = a.ID
		}
		inc := byID[id]
		if inc == nil {
			inc = &Incident{ID: id, Start: a.Timestamp, End: a.LastSeen}
			byID[id] = inc
			order = append(order, id)
		}
		if severityRank[a.Severity] > severityRank[inc.Severity] {
			inc.Severity = a.Severity
		}
		if a.Timestamp.Before(inc.Start) {
			inc.Start = a.Timestamp
		}
		if a.LastSeen.After(inc.End) {
			inc.End = a.LastSeen
		}
		inc.Keys = addUnique(inc.Keys, a.CorrelationKey)
		if a.MITRETechniqueID != "" {
			inc.Techniques = addUnique(inc.Techniques, a.MITRETechniqueID)
			t := techs[a.MITRETechniqueID]
			if t == nil {
				t = &Technique{ID: a.MITRETechniqueID, Name: a.MITRETechniqueName, Tactic: a.MITRETactic}
				techs[a.MITRETechniqueID] = t
			}
			t.Alerts++
		}
		inc.Alerts = append(inc.Alerts, resolve(a, logs))
	}

	incidents := make([]Incident, 0, len(order))
	for _, id := range order {
		inc := byID[id]
		sort.SliceStable(inc.Alerts, func(i, j int) bool {
			return inc.Alerts[i].Timestamp.Before(inc.Alerts[j].Timestamp)
		})
		incidents = append(incidents, *inc)
	}
	sort.SliceStable(incidents, func(i, j int) bool {
		if !incidents[i].Start.Equal(incidents[j].Start) {
			return incidents[i].Start.Before(incidents[j].Start)
		}
		return incidents[i].ID < incidents[j].ID
	})

	techniques := make([]Technique, 0, len(techs))
	for _, t := range techs {
		techniques = append(techniques, *t)
	}
	sort.Slice(techniques, func(i, j int) bool { return techniques[i].ID < techniques[j].ID })
	return incidents, techniques
}

func resolve(a *models.Alert, logs map[string]*models.LogEntry) Alert {
	out := Alert{Alert: a}
	keys := make([]string, 0, len(a.Details))
	for k := range a.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Details = append(out.Details, KV{k, excerpt(fmt.Sprint(a.Details[k]))})
	}

	cited := a.RelatedLogs
	if len(cited) > maxEvidenceLines {
		out.Omitted = len(cited) - maxEvidenceLines
		cited = cited[:maxEvidenceLines]
	}
	for _, id := range cited {
		l := Line{ID: id}
		if e, ok := logs[id]; ok {
			l.Found, l.Time, l.Source, l.Text = true, e.Timestamp, e.Source, excerpt(e.Message)
		}
		out.Evidence = append(out.Evidence, l)
	}
	return out
}

// excerpt collapses whitespace (multi-line Windows messages) and truncates.
func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if n := utf8.RuneCountInString(s); n > maxEvidenceRunes {
		s = string([]rune(s)[:maxEvidenceRunes]) + fmt.Sprintf(" … [+%d chars]", n-maxEvidenceRunes)
	}
	return s
}

func counts(m map[string]int, total int) []Count {
	out := make([]Count, 0, len(m))
	for _, k := range pipeline.SortedKeys(m) {
		out = append(out, Count{k, m[k], pct(m[k], total)})
	}
	return out
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}

func addUnique(list []string, s string) []string {
	if s == "" {
		return list
	}
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

// unchanged renders the post-analysis hash check.
func unchanged(ev *audit.EvidenceFile) string {
	switch {
	case ev.Unchanged == nil:
		return "not verified"
	case *ev.Unchanged:
		return "unchanged"
	default:
		return "CHANGED"
	}
}
