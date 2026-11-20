package cli

import (
	"drishti-nexus/internal/ai"
	"drishti-nexus/internal/config"
	"drishti-nexus/internal/pipeline"
	"drishti-nexus/internal/storage"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Full path: pipeline → scan report → summarize (stand-in local model) → labeled file.
func TestSummarizeCommand(t *testing.T) {
	root := filepath.Join("..", "..")
	cfg, _, err := config.Load(filepath.Join(root, "configs", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := pipeline.Run([]string{filepath.Join(root, "testdata", "fixtures", "multihost")},
		pipeline.Options{Config: cfg, KeepLogs: true, Command: "test", ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Finish(&pipeline.Options{}, "ok"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	report, out := filepath.Join(dir, "scan.json"), filepath.Join(dir, "summaries.json")
	if err := storage.ExportJSON(res.Store.GetLogs(), res.Alerts(), res.Session, "", report); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ALERT-000003: deploy was brute-forced on web01 and then logged in on db01 from 10.0.0.11."}}]}`))
	}))
	defer srv.Close()

	if err := SummarizeCommand([]string{"-in", report, "-out", out, "-endpoint", srv.URL, "-model", "test"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got summaryFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Label != ai.Label || len(got.SourceReportSHA256) != 64 || len(got.Summaries) != 1 {
		t.Fatalf("output %+v", got)
	}
	s := got.Summaries[0]
	if s.IncidentID != "INC-00001" || !s.Verified || s.Label != ai.Label || s.Model != "test" {
		t.Errorf("summary %+v", s)
	}

	if err := SummarizeCommand([]string{"-in", report, "-out", out, "-endpoint", "http://192.0.2.10:8080/v1"}); err == nil ||
		!strings.Contains(err.Error(), "not a loopback") {
		t.Errorf("non-loopback endpoint: %v", err)
	}
	if err := SummarizeCommand([]string{"-in", report, "-out", report, "-endpoint", srv.URL}); err == nil {
		t.Error("overwriting the scan report must be refused")
	}
}
