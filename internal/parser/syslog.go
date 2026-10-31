package parser

import (
	"drishti-nexus/internal/models"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SyslogParser handles RFC 5424, RFC 3164 (with <PRI>), the PRI-less BSD format
// written to auth.log / messages files, and RFC 3339-prefixed rsyslog files.
type SyslogParser struct {
	ctx *Context

	rfc5424Pattern *regexp.Regexp
	rfc3164Pattern *regexp.Regexp
	isoPattern     *regexp.Regexp
}

func NewSyslogParser(ctx *Context) *SyslogParser {
	return &SyslogParser{
		ctx: ctx,
		// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]
		rfc5424Pattern: regexp.MustCompile(`^<(\d{1,3})>(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?$`),
		// <PRI>Mmm dd hh:mm:ss HOST REST
		rfc3164Pattern: regexp.MustCompile(`^<(\d{1,3})>([A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) (.*)$`),
		// 2006-01-02T15:04:05[.frac](Z|±hh:mm) HOST REST
		isoPattern: regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) (\S+) (.*)$`),
	}
}

func (p *SyslogParser) Name() string {
	return "syslog"
}

// CanParse is a cheap shape check; Parse does the full match (and fails cleanly).
func (p *SyslogParser) CanParse(line string) bool {
	if len(line) < 16 {
		return false
	}
	switch c := line[0]; {
	case c == '<':
		return true
	case c >= 'A' && c <= 'Z': // "Jan  2 15:04:05"
		return line[1] >= 'a' && line[1] <= 'z' && line[3] == ' '
	case c >= '0' && c <= '9': // "2006-01-02T15:04:05"
		return line[4] == '-' && line[10] == 'T'
	}
	return false
}

func (p *SyslogParser) Parse(line string) (*models.LogEntry, error) {
	if m := p.rfc5424Pattern.FindStringSubmatch(line); m != nil {
		return p.parseRFC5424(line, m)
	}
	if m := p.rfc3164Pattern.FindStringSubmatch(line); m != nil {
		pri, _ := strconv.Atoi(m[1])
		return p.parseBSD(line, m[2], m[3], m[4], pri)
	}
	if ts, host, rest, ok := splitBSDHeader(line); ok {
		return p.parseBSD(line, ts, host, rest, -1)
	}
	if m := p.isoPattern.FindStringSubmatch(line); m != nil {
		return p.parseISO(line, m)
	}
	return nil, fmt.Errorf("invalid syslog format")
}

func (p *SyslogParser) parseRFC5424(rawLog string, m []string) (*models.LogEntry, error) {
	pri, _ := strconv.Atoi(m[1])
	fields := map[string]interface{}{
		"app_name": m[5],
		"proc_id":  m[6],
		"msg_id":   m[7],
		"priority": pri,
	}
	if m[8] != "-" {
		fields["structured_data"] = m[8]
	}

	ts, ok := parseWithZoneFallback(p.ctx, m[3], fields)
	if !ok {
		return nil, fmt.Errorf("invalid RFC 5424 timestamp %q", m[3])
	}

	return &models.LogEntry{
		Timestamp: ts,
		Source:    m[4],
		Facility:  fmt.Sprintf("facility-%d", pri/8),
		Severity:  fromSyslogSeverity(pri % 8),
		Message:   strings.TrimPrefix(m[9], bom),
		RawLog:    rawLog,
		Fields:    fields,
		Tags:      []string{},
	}, nil
}

// parseBSD handles RFC 3164 with or without <PRI> (pri < 0 means absent).
func (p *SyslogParser) parseBSD(rawLog, tsRaw, host, rest string, pri int) (*models.LogEntry, error) {
	fields := map[string]interface{}{}
	ts, err := p.parseBSDTime(tsRaw, fields)
	if err != nil {
		return nil, err
	}

	tag, pid, message := p.splitTag(rest)
	if tag != "" {
		fields["tag"] = tag
		fields["program"] = programName(tag)
	}
	if pid != "" {
		fields["pid"] = pid
	}

	entry := &models.LogEntry{
		Timestamp: ts,
		Source:    host,
		Message:   message,
		RawLog:    rawLog,
		Fields:    fields,
		Tags:      []string{},
	}
	if pri >= 0 {
		fields["priority"] = pri
		entry.Facility = fmt.Sprintf("facility-%d", pri/8)
		entry.Severity = fromSyslogSeverity(pri % 8)
	} else {
		entry.Facility = programName(tag)
		entry.Severity = parseSeverityKeyword(message)
	}
	return entry, nil
}

func (p *SyslogParser) parseISO(rawLog string, m []string) (*models.LogEntry, error) {
	fields := map[string]interface{}{}
	ts, ok := parseWithZoneFallback(p.ctx, m[1], fields)
	if !ok {
		return nil, fmt.Errorf("invalid timestamp %q", m[1])
	}
	tag, pid, message := p.splitTag(m[3])
	if tag != "" {
		fields["tag"] = tag
		fields["program"] = programName(tag)
	}
	if pid != "" {
		fields["pid"] = pid
	}
	return &models.LogEntry{
		Timestamp: ts,
		Source:    m[2],
		Facility:  programName(tag),
		Severity:  parseSeverityKeyword(message),
		Message:   message,
		RawLog:    rawLog,
		Fields:    fields,
		Tags:      []string{},
	}, nil
}

// splitTag splits "TAG[PID]: MSG". The tag may contain spaces ("syslogd 1.4.1")
// or parens ("sshd(pam_unix)") but no ':' '[' ']', and is at most 64 bytes.
// Hand-written: this runs on every syslog line and a regex was 10% of CPU.
func (p *SyslogParser) splitTag(rest string) (tag, pid, message string) {
	limit := len(rest)
	if limit > 80 {
		limit = 80
	}
	colon := strings.IndexByte(rest[:limit], ':')
	if colon <= 0 {
		return "", "", rest
	}
	head := rest[:colon]
	if open := strings.IndexByte(head, '['); open >= 0 {
		if !strings.HasSuffix(head, "]") || open == 0 {
			return "", "", rest
		}
		pid = head[open+1 : len(head)-1]
		head = head[:open]
		for i := 0; i < len(pid); i++ {
			if pid[i] < '0' || pid[i] > '9' {
				return "", "", rest
			}
		}
	}
	if len(head) > 64 || strings.ContainsAny(head, "[]") {
		return "", "", rest
	}
	message = strings.TrimPrefix(rest[colon+1:], " ")
	return strings.TrimSpace(head), pid, message
}

// parseBSDTime parses "Jan  2 15:04:05[.frac]", inferring the year from the
// context reference time and the zone from the context location.
func (p *SyslogParser) parseBSDTime(raw string, fields map[string]interface{}) (time.Time, error) {
	normalized := strings.Replace(raw, "  ", " ", 1) // "Jan  2" → "Jan 2"
	layout := "Jan 2 15:04:05"
	if strings.Contains(normalized, ".") {
		layout = "Jan 2 15:04:05.999999999"
	}
	t, err := time.ParseInLocation(layout, normalized, time.UTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid BSD timestamp %q: %w", raw, err)
	}
	year := inferYear(t.Month(), t.Day(), p.ctx.ref())
	local, flag := resolveLocal(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), p.ctx.loc(), p.ctx.last)
	fields["year_inferred"] = year
	if flag != "" {
		fields["dst"] = flag
	}
	return stampTime(fields, raw, local, true), nil
}

// splitBSDHeader splits "Mmm dd hh:mm:ss[.frac] HOST REST" without a regex (it is
// the hottest path for auth.log-style files). The day may be space-padded ("Jan  2").
func splitBSDHeader(line string) (ts, host, rest string, ok bool) {
	// "Jan  2 15:04:05" or "Jan 12 15:04:05": 15 bytes, or 14 with a 1-digit unpadded day.
	if len(line) < 17 || line[3] != ' ' || !isUpper(line[0]) || !isLower(line[1]) || !isLower(line[2]) {
		return "", "", "", false
	}
	i := 4
	if line[i] == ' ' {
		i++
	}
	dayStart := i
	for i < len(line) && isDigit(line[i]) {
		i++
	}
	if i-dayStart < 1 || i-dayStart > 2 || i+9 > len(line) || line[i] != ' ' {
		return "", "", "", false
	}
	clock := line[i+1 : i+9] // hh:mm:ss
	if !isDigit(clock[0]) || !isDigit(clock[1]) || clock[2] != ':' || !isDigit(clock[3]) || !isDigit(clock[4]) ||
		clock[5] != ':' || !isDigit(clock[6]) || !isDigit(clock[7]) {
		return "", "", "", false
	}
	i += 9
	if i < len(line) && line[i] == '.' {
		j := i + 1
		for j < len(line) && isDigit(line[j]) {
			j++
		}
		if j == i+1 || j-i-1 > 9 {
			return "", "", "", false
		}
		i = j
	}
	if i >= len(line) || line[i] != ' ' {
		return "", "", "", false
	}
	ts = line[:i]
	sp := strings.IndexByte(line[i+1:], ' ')
	if sp <= 0 {
		return "", "", "", false
	}
	host = line[i+1 : i+1+sp]
	return ts, host, line[i+2+sp:], true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }

// programName strips annotations like "sshd(pam_unix)" or "postfix/smtpd" down to the binary name.
func programName(tag string) string {
	name := tag
	if i := strings.IndexAny(name, "( "); i > 0 {
		name = name[:i]
	}
	return name
}

// fromSyslogSeverity converts RFC 5424 severity (0=emergency … 7=debug) to
// models.Severity, whose order is reversed (Debug=0 … Emergency=7).
func fromSyslogSeverity(s int) models.Severity {
	if s < 0 || s > 7 {
		return models.SeverityInfo
	}
	return models.Severity(7 - s)
}
