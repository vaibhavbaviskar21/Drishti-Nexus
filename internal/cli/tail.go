package cli

import (
	"bufio"
	"drishti-nexus/internal/detection"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/parser"
	"drishti-nexus/internal/storage"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
)

// TailCommand follows a log file and displays entries in real-time
func TailCommand(filename string, config *models.Config) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// Initialize components
	parserRegistry := parser.NewParserRegistry()
	store := storage.NewMemoryStorage(config.MaxLogEntries)
	detectionEngine := detection.NewEngine(store, config)

	// Color setup
	debugColor := color.New(color.FgCyan)
	infoColor := color.New(color.FgWhite)
	warnColor := color.New(color.FgYellow)
	errorColor := color.New(color.FgRed)
	criticalColor := color.New(color.FgRed, color.Bold)
	alertColor := color.New(color.FgMagenta, color.Bold)

	fmt.Println("===================================")
	fmt.Println("Drishti Nexus - Live Log Monitor")
	fmt.Println("===================================")
	fmt.Printf("Monitoring: %s\n", filename)
	fmt.Printf("Time: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	scanner := bufio.NewScanner(file)
	lineCount := 0
	alertCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		// Parse log entry
		entry, err := parserRegistry.Parse(line)
		if err != nil || entry == nil {
			continue
		}

		// Store and analyze
		store.AddLog(entry)
		alerts := detectionEngine.AnalyzeLog(entry)

		// Colorize based on severity
		var outputColor *color.Color
		switch entry.Severity {
		case models.SeverityDebug:
			outputColor = debugColor
		case models.SeverityInfo, models.SeverityNotice:
			outputColor = infoColor
		case models.SeverityWarning:
			outputColor = warnColor
		case models.SeverityError:
			outputColor = errorColor
		case models.SeverityCritical, models.SeverityAlert, models.SeverityEmergency:
			outputColor = criticalColor
		default:
			outputColor = infoColor
		}

		// Display log entry
		timestamp := entry.Timestamp.Format("15:04:05")
		outputColor.Printf("[%s] [%s] %s: %s\n",
			timestamp,
			entry.Severity.String(),
			entry.Source,
			entry.Message,
		)

		// Display alerts
		for _, alert := range alerts {
			alertCount++
			alertColor.Printf("  🚨 ALERT [%s]: %s\n", alert.Severity, alert.Description)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Summary
	fmt.Println("\n===================================")
	fmt.Printf("Total logs processed: %d\n", lineCount)
	fmt.Printf("Total alerts: %d\n", alertCount)
	fmt.Println("===================================")

	return nil
}
