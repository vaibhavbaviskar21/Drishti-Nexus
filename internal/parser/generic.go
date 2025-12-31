package parser

import (
	"drishti-nexus/internal/models"
	"strings"
	"time"
)

// GenericParser is a fallback parser for unrecognized log formats
type GenericParser struct{}

func NewGenericParser() *GenericParser {
	return &GenericParser{}
}

func (p *GenericParser) Name() string {
	return "generic"
}

func (p *GenericParser) CanParse(line string) bool {
	// Generic parser accepts anything
	return true
}

func (p *GenericParser) Parse(line string) (*models.LogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	entry := &models.LogEntry{
		ID:        generateID(),
		Timestamp: time.Now(),
		Source:    "unknown",
		Facility:  "unknown",
		Severity:  parseSeverityKeyword(line),
		Message:   line,
		RawLog:    line,
		Fields:    map[string]interface{}{},
		Tags:      []string{"generic"},
	}

	return entry, nil
}
