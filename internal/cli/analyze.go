package cli

import (
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/pipeline"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"
)

// AnalyzeCommand performs historical analysis on log files and prints a summary.
func AnalyzeCommand(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	var common Common
	common.Register(fs)
	files, err := ParseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("usage: drishti analyze [flags] <logfile|dir> [...]")
	}
	if err := common.Load(); err != nil {
		return err
	}

	fmt.Println("╔════════════════════════════════════════════════════╗")
	fmt.Println("║   Drishti Nexus - Portable Log Analysis Tool       ║")
	fmt.Println("╚════════════════════════════════════════════════════╝")
	fmt.Printf("\nAnalysis Time: %s\n\n", time.Now().UTC().Format(time.RFC3339))

	severityCounts := make(map[models.Severity]int)
	sourceCounts := make(map[string]int)
	opts := common.PipelineOptions("analyze", args)
	opts.OnEntry = func(entry *models.LogEntry, _ []*models.Alert) {
		severityCounts[entry.Severity]++
		sourceCounts[entry.Source]++
	}

	fmt.Println("Processing logs...")
	res, err := pipeline.Run(files, opts)
	if err != nil {
		return err
	}
	printEvidence(res.Session)
	st := res.Stats
	alerts := res.Alerts()

	fmt.Println("\n═════════════════════════════════════════")
	fmt.Println("         SUMMARY STATISTICS")
	fmt.Println("═════════════════════════════════════════")
	fmt.Printf("Total lines processed:     %d\n", st.Lines)
	fmt.Printf("Log entries:               %d\n", st.Entries)
	fmt.Printf("Parse quality:             %s\n", formatCounts(st.ParseQuality))
	if len(st.Repairs) > 0 {
		fmt.Printf("Repairs / assumptions:     %s\n", formatCounts(st.Repairs))
	}
	fmt.Printf("Processing time:           %v\n", st.Duration.Round(time.Millisecond))
	if secs := st.Duration.Seconds(); secs > 0 {
		fmt.Printf("Processing rate:           %.0f lines/sec\n\n", float64(st.Lines)/secs)
	}

	fmt.Println("─────────────────────────────────────────")
	fmt.Println("SEVERITY BREAKDOWN")
	fmt.Println("─────────────────────────────────────────")
	for sev := models.SeverityDebug; sev <= models.SeverityEmergency; sev++ {
		if count := severityCounts[sev]; count > 0 && st.Entries > 0 {
			fmt.Printf("%-12s: %7d (%.1f%%)\n", sev.String(), count, float64(count)/float64(st.Entries)*100)
		}
	}

	fmt.Println("\n─────────────────────────────────────────")
	fmt.Println("TOP SOURCES")
	fmt.Println("─────────────────────────────────────────")
	for i, item := range getTopN(sourceCounts, 10) {
		fmt.Printf("%2d. %-24s: %7d logs\n", i+1, item.Key, item.Value)
	}

	fmt.Println("\n═════════════════════════════════════════")
	fmt.Printf("   SECURITY ALERTS (%d in %d incidents)\n", st.Alerts, st.Incidents)
	fmt.Println("═════════════════════════════════════════")

	if len(alerts) == 0 {
		fmt.Println("✓ No security alerts detected")
	} else {
		alertsBySeverity := make(map[string]int)
		for _, alert := range alerts {
			alertsBySeverity[alert.Severity]++
		}

		fmt.Println("\nBy Severity:")
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if count, ok := alertsBySeverity[sev]; ok {
				indicator := "⚠"
				if sev == "critical" || sev == "high" {
					indicator = "🚨"
				}
				fmt.Printf("  %s %-10s: %d\n", indicator, strings.ToUpper(sev), count)
			}
		}

		fmt.Println("\nBy Detection Rule:")
		for _, rule := range pipeline.SortedKeys(st.AlertsByRule) {
			fmt.Printf("  • %-35s: %d\n", rule, st.AlertsByRule[rule])
		}

		fmt.Println("\n─────────────────────────────────────────")
		fmt.Println("CRITICAL/HIGH SEVERITY ALERTS (Recent)")
		fmt.Println("─────────────────────────────────────────")

		shown := 0
		for i := len(alerts) - 1; i >= 0 && shown < 10; i-- {
			alert := alerts[i]
			if alert.Severity == "critical" || alert.Severity == "high" {
				mitre := ""
				if alert.MITRETechniqueID != "" {
					mitre = fmt.Sprintf(" [%s: %s]", alert.MITRETechniqueID, alert.MITRETactic)
				}
				fmt.Printf("\n[%s] %s  (%s, %s, x%d)%s\n",
					alert.Timestamp.Format("2006-01-02 15:04:05Z"), alert.RuleName, alert.ID, alert.IncidentID, alert.Count, mitre)
				fmt.Printf("  Severity: %s\n", strings.ToUpper(alert.Severity))
				fmt.Printf("  Details: %s\n", alert.Description)
				fmt.Printf("  Evidence: %s\n", strings.Join(alert.RelatedLogs[:min(3, len(alert.RelatedLogs))], ", "))
				shown++
			}
		}
		if shown == 0 {
			fmt.Println("No critical/high severity alerts")
		}
	}

	ferr := res.Finish(&opts, "ok")
	fmt.Println("\n═════════════════════════════════════════")
	printCustody(res.Session, opts.AuditLogPath)
	fmt.Println("═════════════════════════════════════════")
	return ferr
}

type countItem struct {
	Key   string
	Value int
}

func getTopN(m map[string]int, n int) []countItem {
	items := make([]countItem, 0, len(m))
	for k, v := range m {
		items = append(items, countItem{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Value != items[j].Value {
			return items[i].Value > items[j].Value
		}
		return items[i].Key < items[j].Key
	})
	if n > len(items) {
		n = len(items)
	}
	return items[:n]
}
