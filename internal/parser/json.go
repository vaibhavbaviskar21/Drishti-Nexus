package parser

import (
	"drishti-nexus/internal/models"
	"encoding/json"
	"strings"
	"time"
)

// JSONParser handles JSON-formatted logs
type JSONParser struct{}

func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

func (p *JSONParser) Name() string {
	return "json"
}

func (p *JSONParser) CanParse(line string) bool {
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}")
}

func (p *JSONParser) Parse(line string) (*models.LogEntry, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		return nil, err
	}

	entry := &models.LogEntry{
		ID:     generateID(),
		RawLog: line,
		Fields: data,
		Tags:   []string{},
	}

	// Extract common fields with various field name conventions
	entry.Timestamp = p.extractTimestamp(data)
	entry.Message = p.extractString(data, "message", "msg", "text", "log")
	entry.Source = p.extractString(data, "hostname", "host", "source", "server")
	entry.Severity = p.extractSeverity(data)
	entry.Facility = p.extractString(data, "facility", "logger", "category", "service")

	return entry, nil
}

func (p *JSONParser) extractTimestamp(data map[string]interface{}) time.Time {
	fields := []string{"timestamp", "time", "@timestamp", "datetime", "date"}

	for _, field := range fields {
		if val, ok := data[field]; ok {
			switch v := val.(type) {
			case string:
				// Try multiple timestamp formats
				formats := []string{
					time.RFC3339,
					time.RFC3339Nano,
					"2006-01-02T15:04:05",
					"2006-01-02 15:04:05",
					time.RFC1123,
				}
				for _, format := range formats {
					if t, err := time.Parse(format, v); err == nil {
						return t
					}
				}
			case float64:
				// Unix timestamp
				return time.Unix(int64(v), 0)
			}
		}
	}

	return time.Now()
}

func (p *JSONParser) extractString(data map[string]interface{}, fields ...string) string {
	for _, field := range fields {
		if val, ok := data[field]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}

func (p *JSONParser) extractSeverity(data map[string]interface{}) models.Severity {
	fields := []string{"severity", "level", "loglevel", "priority"}

	for _, field := range fields {
		if val, ok := data[field]; ok {
			if str, ok := val.(string); ok {
				return p.severityFromString(str)
			}
			if num, ok := val.(float64); ok {
				return models.Severity(int(num))
			}
		}
	}

	// Fallback to keyword detection in message
	if msg := p.extractString(data, "message", "msg"); msg != "" {
		return parseSeverityKeyword(msg)
	}

	return models.SeverityInfo
}

func (p *JSONParser) severityFromString(s string) models.Severity {
	s = strings.ToLower(strings.TrimSpace(s))

	severityMap := map[string]models.Severity{
		"debug":     models.SeverityDebug,
		"info":      models.SeverityInfo,
		"notice":    models.SeverityNotice,
		"warn":      models.SeverityWarning,
		"warning":   models.SeverityWarning,
		"error":     models.SeverityError,
		"err":       models.SeverityError,
		"critical":  models.SeverityCritical,
		"crit":      models.SeverityCritical,
		"alert":     models.SeverityAlert,
		"emergency": models.SeverityEmergency,
		"emerg":     models.SeverityEmergency,
		"panic":     models.SeverityEmergency,
	}

	if sev, ok := severityMap[s]; ok {
		return sev
	}

	return models.SeverityInfo
}
