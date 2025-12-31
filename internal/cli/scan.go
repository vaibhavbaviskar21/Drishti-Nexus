package cli

import (
	"bufio"
	"drishti-nexus/internal/detection"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/parser"
	"drishti-nexus/internal/storage"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ScanCommand scans log files and generates a report
func ScanCommand(filename, outputFile string, config *models.Config) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// Initialize components
	parserRegistry := parser.NewParserRegistry()
	store := storage.NewMemoryStorage(config.MaxLogEntries)
	detectionEngine := detection.NewEngine(store, config)

	fmt.Printf("Scanning: %s\n", filename)
	fmt.Println("Processing...")

	scanner := bufio.NewScanner(file)
	lineCount := 0
	lastProgress := 0

	startTime := time.Now()

	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		// Progress indicator every 10k lines
		if lineCount%10000 == 0 {
			fmt.Printf("\rProcessed %d lines...", lineCount)
			lastProgress = lineCount
		}

		entry, err := parserRegistry.Parse(line)
		if err != nil || entry == nil {
			continue
		}

		store.AddLog(entry)
		detectionEngine.AnalyzeLog(entry)
	}

	if lineCount > lastProgress {
		fmt.Printf("\rProcessed %d lines...\n", lineCount)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	processingTime := time.Since(startTime)

	// Generate report
	logs := store.GetLogs()
	alerts := store.GetAlerts()

	fmt.Printf("\nProcessing complete in %v\n", processingTime)
	fmt.Printf("Logs: %d | Alerts: %d\n\n", len(logs), len(alerts))

	// Export results
	if outputFile == "" {
		outputFile = fmt.Sprintf("drishti-scan-%s.json", time.Now().Format("20060102-150405"))
	}

	// Ensure .json extension
	if filepath.Ext(outputFile) != ".json" {
		outputFile += ".json"
	}

	fmt.Printf("Exporting results to: %s\n", outputFile)
	if err := storage.ExportJSON(logs, alerts, outputFile); err != nil {
		return fmt.Errorf("failed to export results: %w", err)
	}

	// Also export alerts to CSV for easy review
	alertsCSV := outputFile[:len(outputFile)-5] + "-alerts.csv"
	if err := storage.ExportAlertsCSV(alerts, alertsCSV); err != nil {
		fmt.Printf("Warning: failed to export alerts CSV: %v\n", err)
	} else {
		fmt.Printf("Alert summary: %s\n", alertsCSV)
	}

	fmt.Println("\n✓ Scan complete")

	return nil
}
