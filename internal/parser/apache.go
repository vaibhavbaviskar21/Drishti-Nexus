package parser

import (
	"drishti-nexus/internal/models"
	"regexp"
	"strings"
	"time"
)

// ApacheParser handles Apache/Nginx common and combined log formats.
//
// The request line is captured as a whole quoted string and split afterwards,
// because attack traffic often contains raw spaces or quotes in the URL
// ("GET /x?id=1' OR '1'='1 HTTP/1.1") that a token-per-field regex rejects.
type ApacheParser struct {
	ctx     *Context
	pattern *regexp.Regexp
}

func NewApacheParser(ctx *Context) *ApacheParser {
	if ctx == nil {
		ctx = &Context{}
	}
	return &ApacheParser{
		ctx: ctx,
		// IP IDENT USER [TIME] "REQUEST" STATUS SIZE ["REFERER" "USER-AGENT"]
		pattern: regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\S+)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?`),
	}
}

func (p *ApacheParser) Name() string {
	return "apache"
}

func (p *ApacheParser) CanParse(line string) bool {
	return strings.Contains(line, " [") && strings.Contains(line, `] "`)
}

func (p *ApacheParser) Parse(line string) (*models.LogEntry, error) {
	m := p.pattern.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	fields := map[string]interface{}{}
	timestamp := p.parseApacheTime(m[4], fields)
	if timestamp.IsZero() {
		return nil, nil
	}

	ip, status := m[1], m[6]
	method, path, protocol := splitRequest(m[5])
	fields["src_ip"] = ip
	if m[3] != "-" {
		fields["user"] = m[3]
	}
	fields["request"] = m[5]
	fields["method"], fields["path"], fields["protocol"] = method, path, protocol
	fields["status"], fields["size"] = status, m[7]
	if m[9] != "" || m[8] != "" {
		fields["referer"], fields["user_agent"] = m[8], m[9]
	}

	return &models.LogEntry{
		Timestamp: timestamp,
		Source:    ip,
		Facility:  "web",
		Severity:  p.severityFromStatus(status),
		Message:   strings.TrimSpace(m[5] + " " + status),
		RawLog:    line,
		Fields:    fields,
		Tags:      []string{"web", "http"},
	}, nil
}

// splitRequest splits "METHOD PATH PROTOCOL", where PATH may contain spaces.
func splitRequest(req string) (method, path, protocol string) {
	parts := strings.Fields(req)
	switch {
	case len(parts) == 0:
		return "", "", ""
	case len(parts) == 1:
		return parts[0], "", ""
	}
	method = parts[0]
	rest := strings.TrimSpace(req[len(method):])
	if last := parts[len(parts)-1]; len(parts) > 2 && strings.HasPrefix(last, "HTTP/") {
		protocol = last
		rest = strings.TrimSpace(strings.TrimSuffix(rest, last))
	}
	return method, rest, protocol
}

func (p *ApacheParser) parseApacheTime(timeStr string, fields map[string]interface{}) time.Time {
	// Format: "02/Jan/2006:15:04:05 -0700"
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timeStr)
	if err != nil {
		return time.Time{}
	}
	return stampTime(fields, timeStr, t, false)
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
