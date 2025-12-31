package storage

import (
	"drishti-nexus/internal/models"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ExportJSON exports logs and alerts to a JSON file
func ExportJSON(logs []*models.LogEntry, alerts []*models.Alert, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create export file: %w", err)
	}
	defer file.Close()

	export := struct {
		ExportTime time.Time          `json:"export_time"`
		LogCount   int                `json:"log_count"`
		AlertCount int                `json:"alert_count"`
		Logs       []*models.LogEntry `json:"logs"`
		Alerts     []*models.Alert    `json:"alerts"`
	}{
		ExportTime: time.Now(),
		LogCount:   len(logs),
		AlertCount: len(alerts),
		Logs:       logs,
		Alerts:     alerts,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(export)
}

// ExportAlertsCSV exports alerts to a CSV file for easy review
func ExportAlertsCSV(alerts []*models.Alert, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"Timestamp", "Rule", "Severity", "Description", "Count"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write alerts
	for _, alert := range alerts {
		record := []string{
			alert.Timestamp.Format(time.RFC3339),
			alert.RuleName,
			alert.Severity,
			alert.Description,
			fmt.Sprintf("%d", alert.Count),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}
