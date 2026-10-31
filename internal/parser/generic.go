package parser

import (
	"drishti-nexus/internal/models"
	"regexp"
	"strings"
	"time"
)

// GenericParser is the fallback for unrecognized formats. It keeps the raw text and
// recovers a leading timestamp when one is present; it never invents one.
type GenericParser struct {
	ctx            *Context
	leadingISO     *regexp.Regexp
	leadingSyslog  *regexp.Regexp
	leadingSlashes *regexp.Regexp
}

func NewGenericParser(ctx *Context) *GenericParser {
	if ctx == nil {
		ctx = &Context{}
	}
	return &GenericParser{
		ctx:            ctx,
		leadingISO:     regexp.MustCompile(`^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)\]?`),
		leadingSyslog:  regexp.MustCompile(`^([A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2})`),
		leadingSlashes: regexp.MustCompile(`^\[?(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\]?`),
	}
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

	fields := map[string]interface{}{}
	entry := &models.LogEntry{
		Source:   "unknown",
		Facility: "unknown",
		Severity: parseSeverityKeyword(line),
		Message:  line,
		RawLog:   line,
		Fields:   fields,
		Tags:     []string{"generic"},
	}
	entry.Timestamp = p.leadingTimestamp(line, fields)
	return entry, nil
}

func (p *GenericParser) leadingTimestamp(line string, fields map[string]interface{}) time.Time {
	if m := p.leadingISO.FindStringSubmatch(line); m != nil {
		raw := strings.Replace(m[1], ",", ".", 1)
		if ts, ok := parseWithZoneFallback(p.ctx, raw, fields); ok {
			return ts
		}
		// "+0530" offsets without a colon
		if t, err := time.Parse("2006-01-02T15:04:05.999999999-0700", strings.Replace(raw, " ", "T", 1)); err == nil {
			return stampTime(fields, m[1], t, false)
		}
	}
	if m := p.leadingSlashes.FindStringSubmatch(line); m != nil {
		if ts, ok := parseWithZoneFallback(p.ctx, m[1], fields); ok {
			return ts
		}
	}
	if m := p.leadingSyslog.FindStringSubmatch(line); m != nil {
		sp := &SyslogParser{ctx: p.ctx}
		if ts, err := sp.parseBSDTime(m[1], fields); err == nil {
			return ts
		}
	}
	return time.Time{}
}
