package parser

import (
	"drishti-nexus/internal/models"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SyslogParser handles RFC 3164 and RFC 5424 syslog formats
type SyslogParser struct {
	rfc3164Pattern *regexp.Regexp
	rfc5424Pattern *regexp.Regexp
}

func NewSyslogParser() *SyslogParser {
	return &SyslogParser{
		// RFC 3164: <PRI>Mon DD HH:MM:SS hostname tag: message
		rfc3164Pattern: regexp.MustCompile(`^<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s*(.*)$`),
		// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MESSAGE
		rfc5424Pattern: regexp.MustCompile(`^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\]\s+)?(.*)$`),
	}
}

func (p *SyslogParser) Name() string {
	return "syslog"
}

func (p *SyslogParser) CanParse(line string) bool {
	return strings.HasPrefix(line, "<") && p.rfc3164Pattern.MatchString(line) ||
		p.rfc5424Pattern.MatchString(line)
}

func (p *SyslogParser) Parse(line string) (*models.LogEntry, error) {
	// Try RFC 5424 first (more structured)
	if matches := p.rfc5424Pattern.FindStringSubmatch(line); matches != nil {
		return p.parseRFC5424(line, matches)
	}

	// Try RFC 3164
	if matches := p.rfc3164Pattern.FindStringSubmatch(line); matches != nil {
		return p.parseRFC3164(line, matches)
	}

	return nil, fmt.Errorf("invalid syslog format")
}

func (p *SyslogParser) parseRFC3164(rawLog string, matches []string) (*models.LogEntry, error) {
	pri, _ := strconv.Atoi(matches[1])
	severity := pri % 8
	facility := pri / 8

	timestamp := p.parseRFC3164Time(matches[2])
	hostname := matches[3]
	tag := matches[4]
	message := matches[5]

	entry := &models.LogEntry{
		ID:        generateID(),
		Timestamp: timestamp,
		Source:    hostname,
		Facility:  fmt.Sprintf("facility-%d", facility),
		Severity:  models.Severity(severity),
		Message:   message,
		RawLog:    rawLog,
		Fields: map[string]interface{}{
			"tag":      tag,
			"priority": pri,
		},
		Tags: []string{},
	}

	return entry, nil
}

func (p *SyslogParser) parseRFC5424(rawLog string, matches []string) (*models.LogEntry, error) {
	pri, _ := strconv.Atoi(matches[1])
	severity := pri % 8
	facility := pri / 8

	timestamp, _ := time.Parse(time.RFC3339, matches[3])
	hostname := matches[4]
	appName := matches[5]
	message := matches[8]

	entry := &models.LogEntry{
		ID:        generateID(),
		Timestamp: timestamp,
		Source:    hostname,
		Facility:  fmt.Sprintf("facility-%d", facility),
		Severity:  models.Severity(severity),
		Message:   message,
		RawLog:    rawLog,
		Fields: map[string]interface{}{
			"app_name": appName,
			"priority": pri,
		},
		Tags: []string{},
	}

	return entry, nil
}

func (p *SyslogParser) parseRFC3164Time(timeStr string) time.Time {
	// Format: "Jan 2 15:04:05"
	now := time.Now()
	t, err := time.Parse("Jan 2 15:04:05", timeStr)
	if err != nil {
		return now
	}
	// Add current year since RFC 3164 doesn't include it
	t = t.AddDate(now.Year(), 0, 0)
	return t
}
