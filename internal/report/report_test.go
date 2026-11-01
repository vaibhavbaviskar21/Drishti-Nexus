package report

import (
	"bytes"
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/pipeline"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2025, 3, 10, 10, 0, 0, 0, time.UTC)

func alert(id, inc, sev, tech string, at time.Duration, logs ...string) *models.Alert {
	return &models.Alert{ID: id, IncidentID: inc, Severity: sev, RuleName: "rule " + id, MITRETechniqueID: tech,
		Timestamp: t0.Add(at), LastSeen: t0.Add(at), CorrelationKey: "host=" + inc, RelatedLogs: logs}
}

func testData(alerts []*models.Alert, logs ...*models.LogEntry) Data {
	idx := map[string]*models.LogEntry{}
	for _, e := range logs {
		idx[e.ID] = e
	}
	d := Data{Session: audit.NewSession("scan", nil, "test"), Stats: &pipeline.Stats{}}
	d.Incidents, d.Techniques = group(alerts, idx)
	return d
}

func TestGroupOrdersIncidentsAndAlerts(t *testing.T) {
	cited := make([]string, maxEvidenceLines+3)
	for i := range cited {
		cited[i] = fmt.Sprintf("a.log:%d", i+1)
	}
	d := testData([]*models.Alert{
		alert("A1", "INC-2", "low", "T1110", 10*time.Minute),
		alert("A2", "INC-1", "medium", "T1059", 5*time.Minute, "a.log:1", "gone.log:9"),
		alert("A3", "INC-2", "critical", "T1110", 2*time.Minute, cited...),
		alert("A4", "", "high", "", time.Minute),
	}, &models.LogEntry{ID: "a.log:1", Message: "line\r\n  one", Source: "web01", Timestamp: t0})

	var got []string
	for _, inc := range d.Incidents {
		got = append(got, inc.ID)
	}
	// Chronological by first alert; an alert without an incident stands alone.
	if strings.Join(got, ",") != "A4,INC-2,INC-1" {
		t.Fatalf("incident order %v", got)
	}
	inc2 := d.Incidents[1]
	if inc2.Severity != "critical" || inc2.Alerts[0].ID != "A3" || inc2.Alerts[1].ID != "A1" {
		t.Errorf("INC-2: severity %s, alerts %s,%s", inc2.Severity, inc2.Alerts[0].ID, inc2.Alerts[1].ID)
	}
	if len(inc2.Techniques) != 1 || !inc2.Start.Equal(t0.Add(2*time.Minute)) || !inc2.End.Equal(t0.Add(10*time.Minute)) {
		t.Errorf("INC-2: techniques %v, window %v-%v", inc2.Techniques, inc2.Start, inc2.End)
	}
	if a3 := inc2.Alerts[0]; len(a3.Evidence) != maxEvidenceLines || a3.Omitted != 3 {
		t.Errorf("A3: %d evidence lines shown, %d omitted", len(a3.Evidence), a3.Omitted)
	}
	ev := d.Incidents[2].Alerts[0].Evidence
	if !ev[0].Found || ev[0].Text != "line one" || ev[1].Found {
		t.Errorf("evidence resolution: %+v", ev)
	}
	if len(d.Techniques) != 2 || d.Techniques[1].ID != "T1110" || d.Techniques[1].Alerts != 2 {
		t.Errorf("techniques %+v", d.Techniques)
	}
}

func TestHTMLEscapesLogContent(t *testing.T) {
	evil := `<script>alert(1)</script>`
	a := alert("A1", "INC-1", "high", "T1059", 0, "a.log:1")
	a.Description = "cmd " + evil
	a.Details = map[string]interface{}{"cmd": evil}
	d := testData([]*models.Alert{a}, &models.LogEntry{ID: "a.log:1", Message: evil, Timestamp: t0})
	d.Session.Evidence = []*audit.EvidenceFile{{Path: `x"><script>.log`}}

	var b bytes.Buffer
	if err := WriteHTML(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(strings.ToLower(out), "<script") {
		t.Fatal("unescaped <script> in HTML report")
	}
	if strings.Count(out, "&lt;script&gt;alert(1)&lt;/script&gt;") < 3 {
		t.Error("log content not rendered escaped")
	}
}

func TestAISectionOnlyWhenPresent(t *testing.T) {
	d := testData([]*models.Alert{alert("A1", "INC-1", "high", "", 0)})
	var b bytes.Buffer
	if err := WriteHTML(&b, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "AI-generated") {
		t.Error("AI section rendered without summaries")
	}
	d.AISummaries = []AISummary{{IncidentID: "INC-1", Model: "m", Text: "summary", Unsupported: []string{"claim"}}}
	b.Reset()
	if err := WriteHTML(&b, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AI-generated summaries (not evidence)", "NOT verified", "claim"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("AI section missing %q", want)
		}
	}
}

func TestPDFStructure(t *testing.T) {
	a := alert("A1", "INC-1", "critical", "T1021", 0, "a.log:1")
	a.Description = `close ) paren \ and (Tj) injection ünï 漢`
	d := testData([]*models.Alert{a}, &models.LogEntry{ID: "a.log:1", Message: strings.Repeat("x", 3000), Timestamp: t0})
	var b bytes.Buffer
	if err := WritePDF(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-")) || !bytes.HasSuffix(out, []byte("%%EOF\n")) {
		t.Fatal("not framed as a PDF")
	}
	if !bytes.Contains(out, []byte(`close \) paren \\ and \(Tj\) injection `+"\xfc"+`n`+"\xef"+` ?`)) {
		t.Error("PDF text not escaped / WinAnsi-encoded")
	}

	// Every xref offset must point at its object, or readers fall back to repair.
	m := regexp.MustCompile(`(?s)startxref\n(\d+)\n`).FindSubmatch(out)
	xref, _ := strconv.Atoi(string(m[1]))
	lines := strings.Split(string(out[xref:]), "\n")
	n, _ := strconv.Atoi(strings.Fields(lines[1])[1])
	for i := 1; i < n; i++ {
		off, _ := strconv.Atoi(lines[2+i][:10])
		if want := fmt.Sprintf("%d 0 obj", i); !bytes.HasPrefix(out[off:], []byte(want)) {
			t.Fatalf("xref entry %d points at %q", i, out[off:off+12])
		}
	}
}

func TestIntegration_MultiHostReport(t *testing.T) {
	res, err := pipeline.Run([]string{filepath.Join("..", "..", "testdata", "fixtures", "multihost")},
		pipeline.Options{KeepLogs: true, Command: "scan", ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	d := Build(res)
	if len(d.Incidents) != 1 || len(d.Incidents[0].Alerts) != 3 {
		t.Fatalf("want 1 incident with 3 alerts, got %+v", d.Incidents)
	}

	var html, pdf bytes.Buffer
	if err := WriteHTML(&html, d); err != nil {
		t.Fatal(err)
	}
	if err := WritePDF(&pdf, d); err != nil {
		t.Fatal(err)
	}
	want := []string{"INC-00001", "Lateral Movement Candidate", "T1021", "Accepted password for deploy from 10.0.0.11"}
	for _, ev := range res.Session.Evidence {
		if ev.Unchanged == nil || !*ev.Unchanged {
			t.Errorf("%s not re-verified by Build", ev.Path)
		}
		want = append(want, ev.SHA256Before)
	}
	for _, w := range want {
		if !strings.Contains(html.String(), w) {
			t.Errorf("HTML report missing %q", w)
		}
		if !strings.Contains(pdf.String(), w) {
			t.Errorf("PDF report missing %q", w)
		}
	}
}
