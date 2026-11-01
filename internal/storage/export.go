package storage

import (
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/models"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Report is the JSON export. The audit section binds the findings to the exact
// evidence bytes (SHA-256), the configuration used, and the audit-log record.
type Report struct {
	ExportTime     time.Time          `json:"export_time"`
	Audit          *audit.Session     `json:"audit"`
	AuditLog       string             `json:"audit_log,omitempty"`
	AuditStartHash string             `json:"audit_record_hash,omitempty"` // record_hash of this session's session_start line
	LogCount       int                `json:"log_count"`
	AlertCount     int                `json:"alert_count"`
	IncidentCount  int                `json:"incident_count"`
	Alerts         []*models.Alert    `json:"alerts"`
	Logs           []*models.LogEntry `json:"logs,omitempty"`
}

// ExportJSON exports logs and alerts with the full chain-of-custody record.
func ExportJSON(logs []*models.LogEntry, alerts []*models.Alert, session *audit.Session, auditLog, filename string) error {
	incidents := map[string]bool{}
	for _, a := range alerts {
		incidents[a.IncidentID] = true
	}
	report := Report{
		ExportTime:    time.Now().UTC(),
		Audit:         session,
		AuditLog:      auditLog,
		LogCount:      len(logs),
		AlertCount:    len(alerts),
		IncidentCount: len(incidents),
		Alerts:        alerts,
		Logs:          logs,
	}
	if session != nil {
		report.AuditStartHash = session.RecordHash
	}

	file, err := CreateOutput(filename)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// ExportAlertsCSV exports alerts to CSV. Every row carries the session ID and the
// SHA-256 of the evidence it was derived from, so a row can be cited on its own.
func ExportAlertsCSV(alerts []*models.Alert, session *audit.Session, filename string) error {
	file, err := CreateOutput(filename)
	if err != nil {
		return err
	}

	writer := csv.NewWriter(file)
	header := []string{
		"AlertID", "IncidentID", "Timestamp", "LastSeen", "Rule", "Severity", "Description", "Count",
		"MITRETechniqueID", "MITRETechniqueName", "MITRETactic",
		"CorrelationKey", "RelatedAlerts", "EvidenceLines", "EvidenceFile", "EvidenceSHA256",
		"AuditSessionID", "AuditRecordHash", "ToolVersion",
	}
	if err := writer.Write(header); err != nil {
		_ = file.Close()
		return err
	}

	evidenceByLabel := map[string]*audit.EvidenceFile{}
	sessionID, recordHash, version := "", "", ""
	if session != nil {
		sessionID, recordHash, version = session.SessionID, session.RecordHash, session.ToolVersion
		for _, ev := range session.Evidence {
			evidenceByLabel[ev.Label] = ev
		}
	}

	for _, alert := range alerts {
		evFile, evHash := evidenceFor(alert, evidenceByLabel)
		record := []string{
			alert.ID,
			alert.IncidentID,
			alert.Timestamp.UTC().Format(time.RFC3339),
			alert.LastSeen.UTC().Format(time.RFC3339),
			alert.RuleName,
			alert.Severity,
			alert.Description,
			fmt.Sprintf("%d", alert.Count),
			alert.MITRETechniqueID,
			alert.MITRETechniqueName,
			alert.MITRETactic,
			alert.CorrelationKey,
			strings.Join(alert.RelatedAlerts, ";"),
			strings.Join(alert.RelatedLogs, ";"),
			evFile,
			evHash,
			sessionID,
			recordHash,
			version,
		}
		if err := writer.Write(record); err != nil {
			_ = file.Close()
			return err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// evidenceFor maps an alert's first related log ID ("<file>:<line>") to its evidence file.
func evidenceFor(alert *models.Alert, byLabel map[string]*audit.EvidenceFile) (string, string) {
	if len(alert.RelatedLogs) == 0 {
		return "", ""
	}
	id := alert.RelatedLogs[0]
	if i := strings.LastIndexByte(id, ':'); i > 0 {
		if ev, ok := byLabel[id[:i]]; ok {
			return ev.Path, ev.SHA256Before
		}
	}
	if len(byLabel) == 1 {
		for _, ev := range byLabel {
			return ev.Path, ev.SHA256Before
		}
	}
	return "", ""
}

// CreateOutput creates a report file. Reports are new files written next to, never
// over, evidence (callers check audit.CheckOutputPath first).
func CreateOutput(filename string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Clean(filename), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to create export file: %w", err)
	}
	return f, nil
}
