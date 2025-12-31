package parser

import (
	"drishti-nexus/internal/models"
	"strings"
	"time"
)

// Parser defines the interface for log parsers
type Parser interface {
	Parse(line string) (*models.LogEntry, error)
	CanParse(line string) bool
	Name() string
}

// ParserRegistry manages available parsers
type ParserRegistry struct {
	parsers []Parser
}

// NewParserRegistry creates a new parser registry with all available parsers
func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: []Parser{
			NewSyslogParser(),
			NewJSONParser(),
			NewApacheParser(),
			NewGenericParser(),
		},
	}
}

// Parse attempts to parse a log line using the most appropriate parser
func (r *ParserRegistry) Parse(line string) (*models.LogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	// Try each parser in order
	for _, parser := range r.parsers {
		if parser.CanParse(line) {
			return parser.Parse(line)
		}
	}

	// Fallback to generic parser
	genericParser := NewGenericParser()
	return genericParser.Parse(line)
}

// generateID creates a unique ID for a log entry
func generateID() string {
	return time.Now().Format("20060102150405.000000")
}

// parseSeverityKeyword extracts severity from common keywords in log messages
func parseSeverityKeyword(message string) models.Severity {
	lower := strings.ToLower(message)

	if strings.Contains(lower, "emerg") || strings.Contains(lower, "panic") {
		return models.SeverityEmergency
	}
	if strings.Contains(lower, "alert") {
		return models.SeverityAlert
	}
	if strings.Contains(lower, "crit") || strings.Contains(lower, "fatal") {
		return models.SeverityCritical
	}
	if strings.Contains(lower, "error") || strings.Contains(lower, "err") ||
		strings.Contains(lower, "fail") {
		return models.SeverityError
	}
	if strings.Contains(lower, "warn") {
		return models.SeverityWarning
	}
	if strings.Contains(lower, "notice") {
		return models.SeverityNotice
	}
	if strings.Contains(lower, "debug") {
		return models.SeverityDebug
	}

	return models.SeverityInfo
}
