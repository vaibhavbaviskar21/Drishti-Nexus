package parser

import (
	"drishti-nexus/internal/models"
	"encoding/csv"
	"errors"
	"regexp"
	"strings"
	"time"
)

// CSVParser parses header-row CSV logs (Event Viewer / audit-log exports, LogHub
// structured CSV). A file is CSV only when its first line is a header with a time
// column (csvHeader); every later record is a row keyed by that header and goes
// through the JSON field extraction (time, host, message, severity, Windows logons).
type CSVParser struct {
	json   *JSONParser
	syslog *SyslogParser
	header []string // nil: this file is not CSV
}

func NewCSVParser(ctx *Context) *CSVParser {
	return &CSVParser{json: NewJSONParser(ctx), syslog: NewSyslogParser(ctx)}
}

func (p *CSVParser) Name() string         { return "csv" }
func (p *CSVParser) CanParse(string) bool { return p.header != nil }

var errCSVWidth = errors.New("CSV row width does not match header")

func (p *CSVParser) Parse(record string) (*models.LogEntry, error) {
	row, err := readCSVRow(record)
	if err != nil {
		return nil, err
	}
	if len(row) != len(p.header) {
		return nil, errCSVWidth
	}
	data := make(map[string]interface{}, len(row))
	for i, name := range p.header {
		data[name] = row[i]
	}
	// Detection keys on exact internal names; accept "Pid", "User", ... columns for them.
	for _, k := range []string{"pid", "user", "src_ip", "program"} {
		if v, ok := lookup(data, k); ok && data[k] == nil && v != "" {
			data[k] = v
		}
	}
	entry := p.json.fromMap(data, record)
	if entry.Timestamp.IsZero() {
		entry.Timestamp = p.splitTime(data)
	}
	return entry, nil
}

// splitTime joins a timestamp spread over columns: Date+Time ("2016-09-28" "04:30:30")
// or month/day/time without a year ("Dec" "10" "06:55:46", year inferred like syslog).
func (p *CSVParser) splitTime(data map[string]interface{}) (t time.Time) {
	get := func(k string) string { v, _ := lookup(data, k); s, _ := v.(string); return s }
	date, tm := get("date"), get("time")
	if tm == "" {
		return t
	}
	if ts, ok := parseWithZoneFallback(p.json.ctx, date+" "+tm, data); ok {
		return ts
	}
	for _, md := range [][2]string{{"date", "day"}, {"month", "date"}, {"month", "day"}} {
		if m, d := get(md[0]), get(md[1]); m != "" && d != "" {
			if ts, err := p.syslog.parseBSDTime(m+" "+d+" "+tm, data); err == nil {
				return ts
			}
		}
	}
	return t
}

func readCSVRow(record string) ([]string, error) {
	r := csv.NewReader(strings.NewReader(record))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true // exports often contain stray quotes inside unquoted fields
	return r.Read()
}

var csvColumn = regexp.MustCompile(`^[A-Za-z@_][\w .()/@-]{0,63}$`)

// csvTimeColumns are header names that mark a CSV file as a log (lower case).
var csvTimeColumns = map[string]bool{
	"@timestamp": true, "timestamp": true, "time": true, "datetime": true, "date": true,
	"date and time": true, "eventtime": true, "creationdate": true, "timegenerated": true, "utctime": true,
}

// csvHeader returns the column names when line is a CSV log header, else nil.
func csvHeader(line string) []string {
	if !strings.Contains(line, ",") {
		return nil
	}
	cols, err := readCSVRow(line)
	if err != nil || len(cols) < 3 {
		return nil
	}
	hasTime := false
	for i, c := range cols {
		c = strings.TrimSpace(c)
		if !csvColumn.MatchString(c) {
			return nil
		}
		cols[i] = c
		hasTime = hasTime || csvTimeColumns[strings.ToLower(c)]
	}
	if !hasTime {
		return nil
	}
	return cols
}

// csvQuoteOpen reports whether a CSV record is still inside a quoted field after
// line, given whether it was before. "" escapes keep the parity.
func csvQuoteOpen(open bool, line string) bool {
	return open != (strings.Count(line, `"`)%2 == 1)
}
