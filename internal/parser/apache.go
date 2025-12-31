package parser

import (
	"drishti-nexus/internal/models"
	"regexp"
	"time"
)

// ApacheParser handles Apache/Nginx common and combined log formats
type ApacheParser struct {
	combinedPattern *regexp.Regexp
	commonPattern   *regexp.Regexp
}

func NewApacheParser() *ApacheParser {
	return &ApacheParser{
		// Combined: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
		combinedPattern: regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"`),
		// Common: IP - - [timestamp] "METHOD /path HTTP/1.1" status size
		commonPattern: regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\S+)`),
	}
}

func (p *ApacheParser) Name() string {
	return "apache"
}

func (p *ApacheParser) CanParse(line string) bool {
	return p.combinedPattern.MatchString(line) || p.commonPattern.MatchString(line)
}

func (p *ApacheParser) Parse(line string) (*models.LogEntry, error) {
	// Try combined format first
	if matches := p.combinedPattern.FindStringSubmatch(line); matches != nil {
		return p.parseCombined(line, matches)
	}

	// Try common format
	if matches := p.commonPattern.FindStringSubmatch(line); matches != nil {
		return p.parseCommon(line, matches)
	}

	return nil, nil
}

func (p *ApacheParser) parseCombined(rawLog string, matches []string) (*models.LogEntry, error) {
	ip := matches[1]
	timestamp := p.parseApacheTime(matches[2])
	method := matches[3]
	path := matches[4]
	protocol := matches[5]
	status := matches[6]
	size := matches[7]
	referer := matches[8]
	userAgent := matches[9]

	entry := &models.LogEntry{
		ID:        generateID(),
		Timestamp: timestamp,
		Source:    ip,
		Facility:  "web",
		Severity:  p.severityFromStatus(status),
		Message:   method + " " + path + " " + status,
		RawLog:    rawLog,
		Fields: map[string]interface{}{
			"method":     method,
			"path":       path,
			"protocol":   protocol,
			"status":     status,
			"size":       size,
			"referer":    referer,
			"user_agent": userAgent,
		},
		Tags: []string{"web", "http"},
	}

	return entry, nil
}

func (p *ApacheParser) parseCommon(rawLog string, matches []string) (*models.LogEntry, error) {
	ip := matches[1]
	timestamp := p.parseApacheTime(matches[2])
	method := matches[3]
	path := matches[4]
	protocol := matches[5]
	status := matches[6]
	size := matches[7]

	entry := &models.LogEntry{
		ID:        generateID(),
		Timestamp: timestamp,
		Source:    ip,
		Facility:  "web",
		Severity:  p.severityFromStatus(status),
		Message:   method + " " + path + " " + status,
		RawLog:    rawLog,
		Fields: map[string]interface{}{
			"method":   method,
			"path":     path,
			"protocol": protocol,
			"status":   status,
			"size":     size,
		},
		Tags: []string{"web", "http"},
	}

	return entry, nil
}

func (p *ApacheParser) parseApacheTime(timeStr string) time.Time {
	// Format: "02/Jan/2006:15:04:05 -0700"
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timeStr)
	if err != nil {
		return time.Now()
	}
	return t
}

func (p *ApacheParser) severityFromStatus(status string) models.Severity {
	if len(status) == 0 {
		return models.SeverityInfo
	}

	switch status[0] {
	case '2', '3': // 2xx, 3xx - success
		return models.SeverityInfo
	case '4': // 4xx - client error
		return models.SeverityWarning
	case '5': // 5xx - server error
		return models.SeverityError
	default:
		return models.SeverityInfo
	}
}
