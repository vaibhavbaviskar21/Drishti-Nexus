package cli

import (
	"bufio"
	"drishti-nexus/internal/detection"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/parser"
	"drishti-nexus/internal/storage"
	"fmt"
	"os"
	"strings"
	"time"
)

// AnalyzeCommand performs historical analysis on log files
func AnalyzeCommand(filename string, config *models.Config) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// Initialize components
	parserRegistry := parser.NewParserRegistry()
	store := storage.NewMemoryStorage(config.MaxLogEntries)
	detectionEngine := detection.NewEngine(store, config)

	fmt.Println("╔════════════════════════════════════════════════════╗")
	fmt.Println("║   Drishti Nexus - Portable Log Analysis Tool       ║")
	fmt.Println("╚════════════════════════════════════════════════════╝")
	fmt.Printf("\nFile: %s\n", filename)
	fmt.Printf("Analysis Time: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	// Process all logs
	fmt.Println("Processing logs...")
	scanner := bufio.NewScanner(file)
	lineCount := 0
	parsedCount := 0

	severityCounts := make(map[models.Severity]int)
	sourceCounts := make(map[string]int)

	startTime := time.Now()

	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		entry, err := parserRegistry.Parse(line)
		if err != nil || entry == nil {
			continue
		}

		parsedCount++
		store.AddLog(entry)
		detectionEngine.AnalyzeLog(entry)

		severityCounts[entry.Severity]++
		sourceCounts[entry.Source]++
	}

	processingTime := time.Since(startTime)

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Get alerts
	alerts := store.GetAlerts()

	// Display summary
	fmt.Println("\n═════════════════════════════════════════")
	fmt.Println("         SUMMARY STATISTICS")
	fmt.Println("═════════════════════════════════════════")
	fmt.Printf("Total lines processed:     %d\n", lineCount)
	fmt.Printf("Successfully parsed:       %d\n", parsedCount)
	fmt.Printf("Processing time:           %v\n", processingTime)
	fmt.Printf("Processing rate:           %.0f logs/sec\n\n", float64(parsedCount)/processingTime.Seconds())

	// Severity breakdown
	fmt.Println("─────────────────────────────────────────")
	fmt.Println("SEVERITY BREAKDOWN")
	fmt.Println("─────────────────────────────────────────")
	for sev := models.SeverityDebug; sev <= models.SeverityEmergency; sev++ {
		if count, ok := severityCounts[sev]; ok && count > 0 {
			fmt.Printf("%-12s: %5d (%.1f%%)\n",
				sev.String(),
				count,
				float64(count)/float64(parsedCount)*100,
			)
		}
	}

	// Top sources
	fmt.Println("\n─────────────────────────────────────────")
	fmt.Println("TOP SOURCES")
	fmt.Println("─────────────────────────────────────────")
	topSources := getTopN(sourceCounts, 10)
	for i, item := range topSources {
		fmt.Printf("%2d. %-20s: %5d logs\n", i+1, item.Key, item.Value)
	}

	// Security alerts
	fmt.Println("\n═════════════════════════════════════════")
	fmt.Printf("         SECURITY ALERTS (%d)\n", len(alerts))
	fmt.Println("═════════════════════════════════════════")

	if len(alerts) == 0 {
		fmt.Println("✓ No security alerts detected")
	} else {
		alertsBySeverity := make(map[string]int)
		alertsByRule := make(map[string]int)

		for _, alert := range alerts {
			alertsBySeverity[alert.Severity]++
			alertsByRule[alert.RuleName]++
		}

		// Alert severity summary
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

		// Alert rule summary
		fmt.Println("\nBy Detection Rule:")
		for rule, count := range alertsByRule {
			fmt.Printf("  • %-35s: %d\n", rule, count)
		}

		// Recent critical/high alerts
		fmt.Println("\n─────────────────────────────────────────")
		fmt.Println("CRITICAL/HIGH SEVERITY ALERTS (Recent)")
		fmt.Println("─────────────────────────────────────────")

		criticalCount := 0
		for i := len(alerts) - 1; i >= 0 && criticalCount < 10; i-- {
			alert := alerts[i]
			if alert.Severity == "critical" || alert.Severity == "high" {
				fmt.Printf("\n[%s] %s\n",
					alert.Timestamp.Format("2006-01-02 15:04:05"),
					alert.RuleName,
				)
				fmt.Printf("  Severity: %s\n", strings.ToUpper(alert.Severity))
				fmt.Printf("  Details: %s\n", alert.Description)
				criticalCount++
			}
		}

		if criticalCount == 0 {
			fmt.Println("No critical/high severity alerts")
		}
	}

	fmt.Println("\n═════════════════════════════════════════")
	fmt.Println("           END OF REPORT")
	fmt.Println("═════════════════════════════════════════\n")

	return nil
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

	// Simple bubble sort for top N
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].Value > items[i].Value {
				items[i], items[j] = items[j], items[i]
			}
		}
	}

	if n > len(items) {
		n = len(items)
	}

	return items[:n]
}
