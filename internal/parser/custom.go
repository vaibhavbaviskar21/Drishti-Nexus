package parser

import (
	"bytes"
	"crypto/sha256"
	"drishti-nexus/internal/models"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CustomFormat is a log format defined in a YAML file, so a new source needs no
// Go code (docs/CUSTOM_PARSERS.md). A line is parsed by one regular expression;
// its named groups become fields. These groups have a meaning:
//
//	timestamp  parsed with time_layout (Go layout) or, if empty, the built-in layouts
//	host       entry source        message   entry text (default: the whole line)
//	severity   level keyword       program, pid, user, src_ip   detection fields
type CustomFormat struct {
	Name       string            `yaml:"name"`
	Match      string            `yaml:"match"`       // optional literal every line contains (cheap prefilter)
	Pattern    string            `yaml:"pattern"`     // regular expression with named groups
	TimeLayout string            `yaml:"time_layout"` // Go reference-time layout for the timestamp group
	Rename     map[string]string `yaml:"rename"`      // group name → field name (e.g. srcip: src_ip)
	Facility   string            `yaml:"facility"`

	File   string `yaml:"-"`
	SHA256 string `yaml:"-"`
	re     *regexp.Regexp
}

// LoadCustomFormats reads every *.yaml / *.yml in dir, in name order. Any invalid
// definition fails the whole load: a half-applied parser set would silently
// change results.
func LoadCustomFormats(dir string) ([]*CustomFormat, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.y*ml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []*CustomFormat
	seen := map[string]string{}
	for _, p := range paths {
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			return nil, err
		}
		f, err := parseCustomFormat(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if prev, dup := seen[f.Name]; dup {
			return nil, fmt.Errorf("%s: parser name %q already defined in %s", p, f.Name, prev)
		}
		seen[f.Name] = p
		sum := sha256.Sum256(data)
		f.File, f.SHA256 = p, hex.EncodeToString(sum[:])
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no parser definitions (*.yaml)", dir)
	}
	return out, nil
}

var builtinNames = map[string]bool{"cef": true, "leef": true, "csv": true, "xml": true, "syslog": true, "json": true, "apache": true, "generic": true}

func parseCustomFormat(data []byte) (*CustomFormat, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a misspelt key must fail, not be ignored
	var f CustomFormat
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	switch {
	case f.Name == "":
		return nil, errors.New("name is required")
	case builtinNames[f.Name]:
		return nil, fmt.Errorf("name %q is a built-in parser", f.Name)
	case f.Pattern == "":
		return nil, errors.New("pattern is required")
	}
	if strings.Contains(f.TimeLayout, "MST") {
		return nil, errors.New("time_layout: zone abbreviations (MST) are ambiguous; use a numeric offset (-0700) or none")
	}
	re, err := regexp.Compile(f.Pattern)
	if err != nil {
		return nil, fmt.Errorf("pattern: %w", err)
	}
	named := 0
	for _, n := range re.SubexpNames() {
		if n != "" {
			named++
		}
	}
	if named == 0 {
		return nil, errors.New("pattern has no named groups (?P<name>...)")
	}
	f.re = re
	return &f, nil
}

// customParser binds a CustomFormat to one registry's time context.
type customParser struct {
	f    *CustomFormat
	ctx  *Context
	json *JSONParser
}

func (p *customParser) Name() string { return p.f.Name }

func (p *customParser) CanParse(line string) bool {
	return p.f.Match == "" || strings.Contains(line, p.f.Match)
}

func (p *customParser) Parse(line string) (*models.LogEntry, error) {
	m := p.f.re.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("%s: no match", p.f.Name)
	}
	fields := map[string]interface{}{}
	entry := &models.LogEntry{RawLog: line, Message: line, Facility: p.f.Facility, Severity: models.SeverityInfo, Fields: fields, Tags: []string{}}
	for i, name := range p.f.re.SubexpNames() {
		if name == "" || m[i] == "" {
			continue
		}
		v := m[i]
		switch name {
		case "timestamp":
			ts, ok := p.parseTime(v, fields)
			if !ok {
				fields["timestamp_unparsed"] = v
				entry.ParseQuality = models.QualityPartial
			}
			entry.Timestamp = ts
		case "host":
			entry.Source = v
		case "message":
			entry.Message = v
		case "severity":
			entry.Severity = p.json.severityFromString(v)
			fields["severity"] = v
		default:
			if to := p.f.Rename[name]; to != "" {
				name = to
			}
			fields[name] = v
		}
	}
	return entry, nil
}

func (p *customParser) parseTime(v string, fields map[string]interface{}) (time.Time, bool) {
	layout := p.f.TimeLayout
	if layout == "" {
		return parseWithZoneFallback(p.ctx, v, fields)
	}
	t, err := time.Parse(layout, v)
	if err != nil {
		return time.Time{}, false
	}
	if strings.Contains(layout, "07") { // every numeric zone token (-0700, Z07:00, ...) contains "07"
		return stampTime(fields, v, t, false), true
	}
	// Zone-less (and possibly year-less) wall time: read in the -tz location, like syslog.
	year := t.Year()
	if year == 0 {
		year = inferYear(t.Month(), t.Day(), p.ctx.ref())
		fields["year_inferred"] = year
	}
	local, flag := resolveLocal(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), p.ctx.loc(), p.ctx.last)
	if flag != "" {
		fields["dst"] = flag
	}
	return stampTime(fields, v, local, true), true
}
