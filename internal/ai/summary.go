package ai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"drishti-nexus/internal/models"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// Label is attached to every summary so it is never mistaken for detection output.
const Label = "AI-generated narrative — not evidence"

const (
	maxEvidenceLines = 40
	maxLineBytes     = 512
)

const systemPrompt = `You write the narrative paragraph of a security incident report.
Use ONLY the facts in the JSON the user sends. They were produced by a deterministic detection engine.
Rules:
- Do not speculate about intent, attribution, impact, or anything the facts do not state.
- Cite the alert ID (for example ALERT-000001) for every statement.
- Copy IP addresses, host names, user names, ATT&CK technique IDs, counts and times exactly as they appear in the facts. All times are UTC.
- If something is not in the facts, do not mention it.
Write 3 to 6 plain-English sentences, no headings or lists.`

// AlertFact is the part of an alert the model is shown.
type AlertFact struct {
	ID            string                 `json:"id"`
	Rule          string                 `json:"rule"`
	Severity      string                 `json:"severity"`
	TechniqueID   string                 `json:"attack_technique_id,omitempty"`
	TechniqueName string                 `json:"attack_technique_name,omitempty"`
	Tactic        string                 `json:"attack_tactic,omitempty"`
	FirstSeen     time.Time              `json:"first_seen"`
	LastSeen      time.Time              `json:"last_seen"`
	Count         int                    `json:"count"`
	Description   string                 `json:"description"`
	Details       map[string]interface{} `json:"details,omitempty"`
	RelatedAlerts []string               `json:"related_alerts,omitempty"`
}

// Facts is everything the model receives for one incident, and everything a
// summary is checked against.
type Facts struct {
	IncidentID      string      `json:"incident_id"`
	FirstSeen       time.Time   `json:"first_seen"`
	LastSeen        time.Time   `json:"last_seen"`
	Alerts          []AlertFact `json:"alerts"`
	Evidence        []string    `json:"evidence_lines,omitempty"` // raw log lines the alerts cite
	EvidenceOmitted int         `json:"evidence_lines_omitted,omitempty"`
}

// Incidents groups alerts by incident (in first-seen order) and attaches the raw
// evidence lines they cite. logs may be empty (an -alerts-only report).
func Incidents(alerts []*models.Alert, logs []*models.LogEntry) []Facts {
	byID := make(map[string]*models.LogEntry, len(logs))
	for _, l := range logs {
		byID[l.ID] = l
	}
	var order []string
	groups := map[string][]*models.Alert{}
	for _, a := range alerts {
		key := a.IncidentID
		if key == "" {
			key = a.ID
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], a)
	}

	out := make([]Facts, 0, len(order))
	for _, id := range order {
		f := Facts{IncidentID: id}
		seen := map[string]bool{}
		for _, a := range groups[id] {
			first, last := a.Timestamp.UTC(), a.LastSeen.UTC()
			if last.Before(first) {
				last = first
			}
			if f.FirstSeen.IsZero() || first.Before(f.FirstSeen) {
				f.FirstSeen = first
			}
			if last.After(f.LastSeen) {
				f.LastSeen = last
			}
			f.Alerts = append(f.Alerts, AlertFact{
				ID: a.ID, Rule: a.RuleName, Severity: a.Severity,
				TechniqueID: a.MITRETechniqueID, TechniqueName: a.MITRETechniqueName, Tactic: a.MITRETactic,
				FirstSeen: first, LastSeen: last, Count: a.Count,
				Description: a.Description, Details: a.Details, RelatedAlerts: a.RelatedAlerts,
			})
			for _, ref := range a.RelatedLogs {
				l, ok := byID[ref]
				if !ok || seen[ref] {
					continue
				}
				seen[ref] = true
				if len(f.Evidence) == maxEvidenceLines {
					f.EvidenceOmitted++
					continue
				}
				line := l.RawLog
				if len(line) > maxLineBytes {
					line = line[:maxLineBytes]
				}
				f.Evidence = append(f.Evidence, line)
			}
		}
		sort.SliceStable(f.Alerts, func(i, j int) bool { return f.Alerts[i].FirstSeen.Before(f.Alerts[j].FirstSeen) })
		out = append(out, f)
	}
	return out
}

// factsJSON is both the prompt payload and the grounding corpus, so the checker
// sees exactly what the model saw.
func factsJSON(f Facts) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(f) // only strings, numbers, times and maps from decoded JSON: cannot fail
	return buf.String()
}

// Prompt returns the system and user messages for one incident.
func Prompt(f Facts) (system, user string) {
	return systemPrompt, "Incident facts (JSON):\n" + factsJSON(f)
}

// Summary is one AI narrative plus its grounding result.
type Summary struct {
	IncidentID   string    `json:"incident_id"`
	Label        string    `json:"label"`
	Model        string    `json:"model"`
	Endpoint     string    `json:"endpoint"`
	GeneratedAt  time.Time `json:"generated_at"`
	PromptSHA256 string    `json:"prompt_sha256"` // of system + "\n" + user message
	Text         string    `json:"text"`
	Verified     bool      `json:"verified"` // every concrete claim was found in the facts
	Unsupported  []string  `json:"unsupported_claims,omitempty"`
}

// Summarize asks the model for a narrative of f and grounds it against f.
func Summarize(ctx context.Context, c *Client, f Facts) (*Summary, error) {
	system, user := Prompt(f)
	text, err := c.Complete(ctx, system, user)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(system + "\n" + user))
	unsupported := Check(text, f)
	return &Summary{
		IncidentID:   f.IncidentID,
		Label:        Label,
		Model:        c.Model,
		Endpoint:     c.Endpoint,
		GeneratedAt:  time.Now().UTC(),
		PromptSHA256: hex.EncodeToString(sum[:]),
		Text:         text,
		Verified:     len(unsupported) == 0,
		Unsupported:  unsupported,
	}, nil
}
