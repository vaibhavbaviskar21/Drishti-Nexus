package pipeline

import (
	"drishti-nexus/internal/models"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// alertSignature is the rule and count of every alert, sorted, so two runs can be compared.
func alertSignature(res *Result) []string {
	var sig []string
	for _, a := range res.Alerts() {
		sig = append(sig, fmt.Sprintf("%s x%d", a.RuleName, a.Count))
	}
	sort.Strings(sig)
	return sig
}

// LogHub publishes the same 2,000 OpenSSH events as raw syslog and as structured
// CSV. Detection must not depend on the container format.
func TestIntegration_CSVMatchesRawSyslog(t *testing.T) {
	fixtures := filepath.Join(repoRoot, "testdata", "fixtures")
	raw := runFiles(t, filepath.Join(fixtures, "loghub_openssh_2k.log"))
	csv := runFiles(t, filepath.Join(fixtures, "loghub_openssh_2k_structured.csv"))

	if csv.Stats.Entries != 2000 || csv.Stats.ByParser["csv"] != 2000 || csv.Stats.ParseQuality[models.QualityClean] != 2000 {
		t.Errorf("csv: entries=%d parsers=%v quality=%v", csv.Stats.Entries, csv.Stats.ByParser, csv.Stats.ParseQuality)
	}
	r, c := alertSignature(raw), alertSignature(csv)
	if fmt.Sprint(r) != fmt.Sprint(c) || len(r) == 0 {
		t.Errorf("same events, different alerts:\n raw %v\n csv %v", r, c)
	}
}

func TestIntegration_WindowsCSVFixture(t *testing.T) {
	res := runFiles(t, filepath.Join(repoRoot, "testdata", "fixtures", "loghub_windows_200_structured.csv"))
	if res.Stats.Entries != 200 || res.Stats.ParseQuality[models.QualityClean] != 200 || res.Stats.Alerts != 0 {
		t.Errorf("entries=%d quality=%v alerts=%v", res.Stats.Entries, res.Stats.ParseQuality, res.Stats.AlertsByRule)
	}
}

// Microsoft's documented 4625 event, pretty-printed and single-line, inside an <Events> wrapper.
func TestIntegration_WindowsXMLFixture(t *testing.T) {
	var entries []*models.LogEntry
	res, err := Run([]string{filepath.Join(repoRoot, "testdata", "fixtures", "windows_events.xml")}, Options{
		Config:  testConfig(t),
		OnEntry: func(e *models.LogEntry, _ []*models.Alert) { entries = append(entries, e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Entries != 2 || res.Stats.ByParser["xml"] != 2 || res.Stats.ParseQuality[models.QualityClean] != 2 {
		t.Fatalf("entries=%d parsers=%v quality=%v", res.Stats.Entries, res.Stats.ByParser, res.Stats.ParseQuality)
	}
	want := time.Date(2015, 9, 8, 22, 54, 54, 962511700, time.UTC)
	for _, e := range entries {
		if e.Fields["auth_result"] != "failure" || e.Fields["user"] != "Auditor" || e.Source != "DC01.contoso.local" || !e.Timestamp.Equal(want) {
			t.Errorf("%s: source=%q ts=%s fields=%v", e.ID, e.Source, e.Timestamp, e.Fields)
		}
	}
}
