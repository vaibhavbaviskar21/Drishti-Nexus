package cli

import (
	"context"
	"crypto/sha256"
	"drishti-nexus/internal/ai"
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/storage"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// summaryFile is the summarize output. It names the exact scan report it was built
// from, and is never merged into that report: AI text stays out of the evidence record.
type summaryFile struct {
	Label              string        `json:"label"`
	SourceReport       string        `json:"source_report"`
	SourceReportSHA256 string        `json:"source_report_sha256"`
	Summaries          []*ai.Summary `json:"summaries"`
}

// SummarizeCommand writes an optional AI narrative for each incident in a scan report.
func SummarizeCommand(args []string) error {
	fs := flag.NewFlagSet("summarize", flag.ContinueOnError)
	in := fs.String("in", "", "JSON report written by 'drishti scan' (required)")
	out := fs.String("out", "summaries.json", "output file for the AI summaries")
	endpoint := fs.String("endpoint", ai.DefaultEndpoint, "local OpenAI-compatible endpoint (loopback only), e.g. http://127.0.0.1:11434/v1 for Ollama")
	model := fs.String("model", "local", "model name sent to the endpoint")
	timeout := fs.Duration("timeout", 5*time.Minute, "per-incident model timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || fs.NArg() > 0 {
		return fmt.Errorf("usage: drishti summarize -in scan-report.json [-out summaries.json] [-endpoint URL] [-model NAME]")
	}
	client, err := ai.NewClient(*endpoint, *model, *timeout)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(filepath.Clean(*in))
	if err != nil {
		return err
	}
	var report storage.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("%s is not a drishti scan report: %w", *in, err)
	}
	if filepath.Clean(*out) == filepath.Clean(*in) {
		return fmt.Errorf("-out must not overwrite the scan report")
	}
	if report.Audit != nil {
		if err := audit.CheckOutputPath(*out, report.Audit.Evidence); err != nil {
			return err
		}
	}

	incidents := ai.Incidents(report.Alerts, report.Logs)
	if len(incidents) == 0 {
		fmt.Println("No alerts in the report; nothing to summarize.")
		return nil
	}
	if len(report.Logs) == 0 {
		fmt.Println("Note: report has no log entries (-alerts-only); summaries use alert facts only.")
	}

	fmt.Printf("Summarizing %d incident(s) with %s at %s\n", len(incidents), client.Model, client.Endpoint)
	sum := sha256.Sum256(data)
	result := summaryFile{Label: ai.Label, SourceReport: *in, SourceReportSHA256: hex.EncodeToString(sum[:])}
	unverified := 0
	for _, f := range incidents {
		s, err := ai.Summarize(context.Background(), client, f)
		if err != nil {
			return fmt.Errorf("%s: %w", f.IncidentID, err)
		}
		status := "VERIFIED"
		if !s.Verified {
			status = fmt.Sprintf("UNVERIFIED (%d unsupported claim(s): %v)", len(s.Unsupported), s.Unsupported)
			unverified++
		}
		fmt.Printf("  %s: %s\n", f.IncidentID, status)
		result.Summaries = append(result.Summaries, s)
	}

	file, err := storage.CreateOutput(*out)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Printf("\n%s: %s (%d of %d unverified)\n", ai.Label, *out, unverified, len(incidents))
	return nil
}
