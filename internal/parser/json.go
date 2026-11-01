package parser

import (
	"drishti-nexus/internal/models"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JSONParser handles JSON-formatted logs (one object per record; pretty-printed
// objects are reassembled by the registry before they reach this parser).
type JSONParser struct {
	ctx *Context
}

func NewJSONParser(ctx *Context) *JSONParser {
	if ctx == nil {
		ctx = &Context{}
	}
	return &JSONParser{ctx: ctx}
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
	return p.fromMap(data, line), nil
}

// fromMap builds an entry from decoded key/value data: JSON objects, and CSV rows
// and Windows XML events once mapped to the same shape.
func (p *JSONParser) fromMap(data map[string]interface{}, raw string) *models.LogEntry {
	entry := &models.LogEntry{
		RawLog: raw,
		Fields: data,
		Tags:   []string{},
	}

	entry.Timestamp = p.extractTimestamp(data)
	entry.Message = p.extractString(data, messageKeys...)
	entry.Source = p.extractSource(data)
	entry.Severity = p.extractSeverity(data)
	entry.Facility = p.extractString(data, "facility", "logger", "category", "service", "channel")

	return entry
}

// messageKeys are the fields that hold the event text, in preference order.
var messageKeys = []string{"message", "msg", "text", "log", "content"}

// lookup finds a key case-insensitively ("Hostname", "hostname", "HostName").
func lookup(data map[string]interface{}, key string) (interface{}, bool) {
	if v, ok := data[key]; ok {
		return v, true
	}
	for k, v := range data {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func (p *JSONParser) extractTimestamp(data map[string]interface{}) time.Time {
	// Prefer fields that carry an explicit zone (ECS @timestamp) over local-time fields.
	fields := []string{"@timestamp", "timestamp", "time", "UtcTime", "datetime", "EventTime", "date"}

	for _, field := range fields {
		val, ok := lookup(data, field)
		if !ok {
			continue
		}
		switch v := val.(type) {
		case string:
			if ts, ok := parseWithZoneFallback(p.ctx, v, data); ok {
				return ts
			}
		case float64:
			// Unix epoch in seconds, or milliseconds when implausibly large for seconds.
			var t time.Time
			if v > 1e12 {
				t = time.UnixMilli(int64(v))
			} else {
				sec := int64(v)
				t = time.Unix(sec, int64((v-float64(sec))*1e9))
			}
			data["timestamp_raw"] = fmt.Sprintf("%v", v)
			data["tz_offset"] = "+00:00"
			return t.UTC()
		}
	}

	return time.Time{}
}

func (p *JSONParser) extractString(data map[string]interface{}, fields ...string) string {
	for _, field := range fields {
		if val, ok := lookup(data, field); ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}

func (p *JSONParser) extractSource(data map[string]interface{}) string {
	for _, field := range []string{"hostname", "host", "computer_name", "computer", "source", "server"} {
		val, ok := lookup(data, field)
		if !ok {
			continue
		}
		switch v := val.(type) {
		case string:
			if v != "" {
				return v
			}
		case map[string]interface{}: // ECS: "host": {"name": "..."}
			if name := p.extractString(v, "name", "hostname"); name != "" {
				return name
			}
		}
	}
	return ""
}

func (p *JSONParser) extractSeverity(data map[string]interface{}) models.Severity {
	fields := []string{"severity", "level", "loglevel", "priority"}

	for _, field := range fields {
		if val, ok := lookup(data, field); ok {
			if str, ok := val.(string); ok {
				return p.severityFromString(str)
			}
			if num, ok := val.(float64); ok && num >= 0 && num <= float64(models.SeverityEmergency) {
				return fromSyslogSeverity(int(num))
			}
		}
	}

	// Fallback to keyword detection in message
	if msg := p.extractString(data, messageKeys...); msg != "" {
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
