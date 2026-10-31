package cli

import (
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/pipeline"
	"drishti-nexus/internal/storage"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ScanCommand scans log files and exports findings to JSON and CSV.
func ScanCommand(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var common Common
	common.Register(fs)
	output := fs.String("output", "", "JSON report path (default: drishti-scan-<time>.json); alerts CSV is written alongside")
	db := fs.String("db", "", "optional SQLite database for persistent storage")
	noLogs := fs.Bool("alerts-only", false, "omit parsed log entries from the JSON report")
	files, err := ParseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("usage: drishti scan [flags] <logfile|dir> [...]")
	}
	if err := common.Load(); err != nil {
		return err
	}

	opts := common.PipelineOptions("scan", args)
	opts.KeepLogs = !*noLogs || *db != ""
	if *db != "" {
		store, err := storage.OpenSQLite(*db)
		if err != nil {
			return err
		}
		defer closeStore(store)
		opts.Store, opts.StorageDesc = store, "sqlite:"+*db
	}

	outputFile := *output
	if outputFile == "" {
		outputFile = fmt.Sprintf("drishti-scan-%s.json", time.Now().Format("20060102-150405"))
	}
	if filepath.Ext(outputFile) != ".json" {
		outputFile += ".json"
	}
	alertsCSV := strings.TrimSuffix(outputFile, ".json") + "-alerts.csv"

	fmt.Println("Scanning...")
	res, err := pipeline.Run(files, opts)
	if err != nil {
		return err
	}
	printEvidence(res.Session)
	for _, out := range []string{outputFile, alertsCSV} {
		if err := audit.CheckOutputPath(out, res.Session.Evidence); err != nil {
			_ = res.Finish(&opts, "error: "+err.Error())
			return err
		}
	}

	st := res.Stats
	fmt.Printf("\nProcessing complete in %v\n", st.Duration.Round(time.Millisecond))
	fmt.Printf("Lines: %d | Entries: %d | Alerts: %d | Incidents: %d\n", st.Lines, st.Entries, st.Alerts, st.Incidents)
	fmt.Printf("Parse quality: %s\n\n", formatCounts(st.ParseQuality))

	var logs = res.Store.GetLogs()
	if *noLogs {
		logs = nil
	}
	alerts := res.Alerts()

	fmt.Printf("Exporting results to: %s\n", outputFile)
	if err := storage.ExportJSON(logs, alerts, res.Session, opts.AuditLogPath, outputFile); err != nil {
		_ = res.Finish(&opts, "error: "+err.Error())
		return fmt.Errorf("failed to export results: %w", err)
	}
	res.Session.AddOutput(outputFile)

	if err := storage.ExportAlertsCSV(alerts, res.Session, alertsCSV); err != nil {
		fmt.Printf("Warning: failed to export alerts CSV: %v\n", err)
	} else {
		res.Session.AddOutput(alertsCSV)
		fmt.Printf("Alert summary: %s\n", alertsCSV)
	}

	ferr := res.Finish(&opts, "ok")
	printCustody(res.Session, opts.AuditLogPath)
	if ferr != nil {
		return ferr
	}
	fmt.Println("\n✓ Scan complete")
	return nil
}

func formatCounts(m map[string]int) string {
	parts := make([]string, 0, len(m))
	for _, k := range pipeline.SortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}
