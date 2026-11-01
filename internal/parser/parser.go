package parser

import (
	"drishti-nexus/internal/models"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	bom = "\xef\xbb\xbf"

	// MaxLineBytes caps a single physical line; longer lines are truncated and flagged.
	MaxLineBytes = 1024 * 1024
	// maxEntryBytes caps a multi-line entry (stack trace / pretty-printed JSON).
	maxEntryBytes = 4 * 1024 * 1024
	// maxEntryLines caps the number of physical lines folded into one entry.
	maxEntryLines = 5000

	truncatedMarker = "...[TRUNCATED]"
)

// Parser defines the interface for log parsers
type Parser interface {
	Parse(line string) (*models.LogEntry, error)
	CanParse(line string) bool
	Name() string
}

// Options configure a ParserRegistry for one evidence source.
type Options struct {
	// SourceLabel prefixes entry IDs ("<label>:<line>") so alerts cite exact evidence lines.
	SourceLabel string
	// Location is the zone assumed for timestamps without an offset (default UTC).
	Location *time.Location
	// Reference anchors year inference for year-less syslog timestamps (default now;
	// callers should pass the file's modification time).
	Reference time.Time
}

// ParserRegistry turns a stream of physical lines into normalized entries.
//
// It assembles multi-line records before parsing:
//   - pretty-printed JSON objects are buffered until the braces balance,
//   - indented lines and stack-trace frames ("at ...", "Caused by:", "... 3 more")
//     are folded into the preceding entry,
//   - every other line starts a new entry, recognised or not.
//
// Because a record is only known to be complete when the next one starts, Parse
// returns the *previous* entry; call Flush at end of input.
type ParserRegistry struct {
	parsers []Parser
	generic *GenericParser
	csv     *CSVParser // header set when the file's first line is a CSV log header
	ctx     *Context
	label   string

	lineNo int // physical lines seen

	pending      []string // physical lines of the entry being assembled
	pendingStart int      // line number of pending[0]
	pendingBytes int
	pendingJSON  bool // pending is an unfinished JSON object
	pendingXML   bool // pending is an unfinished <Event> element
	csvOpen      bool // pending CSV record is inside a quoted field
	sawRecord    bool // a non-blank line has been seen (only the first can be a CSV header)
	pendingNotes map[string]interface{}
	pendingDirty bool // encoding repaired or truncated on some physical line

	js       jsonScan        // brace/string state of a pending JSON object
	jsonText strings.Builder // normalized text of a pending multi-line JSON object
}

// NewParserRegistry creates a registry with default options (UTC, reference = now).
func NewParserRegistry() *ParserRegistry {
	return NewParserRegistryWithOptions(Options{})
}

// NewParserRegistryWithOptions creates a registry for one evidence source.
func NewParserRegistryWithOptions(opts Options) *ParserRegistry {
	ctx := &Context{Location: opts.Location, Reference: opts.Reference}
	label := opts.SourceLabel
	if label == "" {
		label = "input"
	}
	csvp := NewCSVParser(ctx)
	return &ParserRegistry{
		csv: csvp,
		parsers: []Parser{
			csvp, // only active once the file's first line was a CSV header
			NewXMLParser(ctx),
			NewCEFParser(ctx), // before syslog: CEF/LEEF usually arrive in a syslog envelope
			NewLEEFParser(ctx),
			NewSyslogParser(ctx),
			NewJSONParser(ctx),
			NewApacheParser(ctx),
		},
		generic: NewGenericParser(ctx),
		ctx:     ctx,
		label:   label,
	}
}

// LinesSeen returns the number of physical lines consumed so far.
func (r *ParserRegistry) LinesSeen() int {
	return r.lineNo
}

// SetLineOffset makes the next physical line number n+1. Used when resuming a
// tail session from a checkpoint so entry IDs stay stable across restarts.
func (r *ParserRegistry) SetLineOffset(n int) {
	r.lineNo = n
}

// PendingStartLine returns the line number where the entry still being assembled
// starts, or 0 if nothing is pending. Lines from there on have not been emitted yet,
// so a resumable checkpoint must point at or before it.
func (r *ParserRegistry) PendingStartLine() int {
	if len(r.pending) == 0 {
		return 0
	}
	return r.pendingStart
}

// Parse consumes one physical line and returns a completed entry, if any.
func (r *ParserRegistry) Parse(line string) (*models.LogEntry, error) {
	r.lineNo++

	line = strings.TrimSuffix(line, "\r")
	notes := map[string]interface{}{}
	dirty := false

	if r.lineNo == 1 && strings.HasPrefix(line, bom) {
		line = line[len(bom):]
		notes["bom_stripped"] = true
	}
	if len(line) > MaxLineBytes {
		line = truncateUTF8(line, MaxLineBytes) + truncatedMarker
		notes["truncated"] = true
		dirty = true
	}
	if decoded, repairs := decodeMixedEncoding(line); len(repairs) > 0 {
		line = decoded
		for _, rep := range repairs {
			if rep != "bom" {
				dirty = true
			}
		}
		notes["encoding_repaired"] = strings.Join(repairs, ",")
	}

	if r.pendingXML || r.csvOpen {
		r.appendPending(line, notes, dirty)
		if r.pendingXML {
			r.pendingXML = !strings.Contains(line, "</Event>")
		} else {
			r.csvOpen = csvQuoteOpen(true, line)
		}
		if !r.pendingXML && !r.csvOpen {
			return r.finish()
		}
		if r.pendingBytes > maxEntryBytes || len(r.pending) > maxEntryLines {
			r.pendingNotes["record_incomplete"] = true
			r.pendingDirty = true
			return r.finish()
		}
		return nil, nil
	}

	if r.pendingJSON {
		r.appendPending(line, notes, dirty)
		r.js.feedLine(&r.jsonText, line, false)
		if r.js.depth <= 0 {
			return r.finish()
		}
		if r.pendingBytes > maxEntryBytes || len(r.pending) > maxEntryLines {
			r.pendingNotes["json_incomplete"] = true
			r.pendingDirty = true
			return r.finish()
		}
		return nil, nil
	}

	if strings.TrimSpace(line) == "" || isXMLWrapper(line) {
		return nil, nil
	}
	// shortcut: the header is only seen from line 1, so a tail resumed mid-file loses CSV mode.
	if !r.sawRecord {
		r.sawRecord = true
		if h := csvHeader(line); h != nil {
			r.csv.header = h
			return nil, nil
		}
	}

	if len(r.pending) > 0 && r.csv.header == nil && isContinuation(line) &&
		r.pendingBytes+len(line) <= maxEntryBytes && len(r.pending) < maxEntryLines {
		r.appendPending(line, notes, dirty)
		return nil, nil
	}

	// New record: emit whatever was pending, then start buffering this line.
	prev, err := r.finish()
	r.startPending(line, notes, dirty)

	switch {
	case r.csv.header != nil:
		r.csvOpen = csvQuoteOpen(false, line)
	case isEventXMLStart(line):
		r.pendingXML = !strings.Contains(line, "</Event>")
	}
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		r.js = jsonScan{}
		r.jsonText.Reset()
		r.js.feedLine(&r.jsonText, line, true)
		r.pendingJSON = r.js.depth > 0
	}
	return prev, err
}

// jsonScan tracks object depth across physical lines, ignoring braces inside
// strings, so a JSON record ends exactly where its braces balance — even when it
// is malformed (e.g. a raw newline inside a string, which json.Valid rejects).
type jsonScan struct {
	depth       int
	inStr, esc  bool
	repairedNLs int // raw newlines found inside strings
}

// feedLine scans line and appends a normalized copy to b: a line break that falls
// inside a string is written as the escape "\n" so the record decodes.
func (s *jsonScan) feedLine(b *strings.Builder, line string, first bool) {
	if !first {
		if s.inStr {
			b.WriteString(`\n`)
			s.repairedNLs++
		} else {
			b.WriteByte('\n')
		}
	}
	b.WriteString(line)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case s.esc:
			s.esc = false
		case s.inStr && c == '\\':
			s.esc = true
		case c == '"':
			s.inStr = !s.inStr
		case !s.inStr && c == '{':
			s.depth++
		case !s.inStr && c == '}':
			s.depth--
		}
	}
}

// Flush returns the entry still being assembled, if any.
func (r *ParserRegistry) Flush() (*models.LogEntry, error) {
	if r.pendingJSON && len(r.pending) > 0 {
		r.pendingNotes["json_incomplete"] = true
		r.pendingDirty = true
	}
	if (r.pendingXML || r.csvOpen) && len(r.pending) > 0 {
		r.pendingNotes["record_incomplete"] = true
		r.pendingDirty = true
	}
	return r.finish()
}

func (r *ParserRegistry) startPending(line string, notes map[string]interface{}, dirty bool) {
	r.pending = []string{line}
	r.pendingStart = r.lineNo
	r.pendingBytes = len(line)
	r.pendingJSON, r.pendingXML, r.csvOpen = false, false, false
	r.pendingNotes = notes
	r.pendingDirty = dirty
}

func (r *ParserRegistry) appendPending(line string, notes map[string]interface{}, dirty bool) {
	if len(r.pending) == 0 {
		r.startPending(line, notes, dirty)
		return
	}
	r.pending = append(r.pending, line)
	r.pendingBytes += len(line) + 1
	for k, v := range notes {
		r.pendingNotes[k] = v
	}
	r.pendingDirty = r.pendingDirty || dirty
}

// finish parses the pending lines into an entry and resets the buffer.
func (r *ParserRegistry) finish() (*models.LogEntry, error) {
	if len(r.pending) == 0 {
		return nil, nil
	}
	lines, start, notes, dirty, wasJSON := r.pending, r.pendingStart, r.pendingNotes, r.pendingDirty, r.pendingJSON
	r.pending, r.pendingNotes, r.pendingBytes, r.pendingDirty, r.pendingJSON = nil, nil, 0, false, false

	raw := strings.Join(lines, "\n")
	jsonText := ""
	if wasJSON {
		jsonText = r.jsonText.String()
		if r.js.repairedNLs > 0 {
			notes["json_repaired"] = "raw newline inside string"
			dirty = true
		}
		r.jsonText.Reset()
	}
	entry, err := r.parseRecord(lines, raw, jsonText)
	if entry == nil {
		return nil, err
	}

	entry.ID = fmt.Sprintf("%s:%d", r.label, start)
	entry.LineNumber = start
	entry.RawLog = raw
	if entry.Fields == nil {
		entry.Fields = map[string]interface{}{}
	}
	for k, v := range notes {
		entry.Fields[k] = v
	}
	if len(lines) > 1 {
		entry.Fields["line_count"] = len(lines)
	}

	if entry.ParseQuality == "" {
		entry.ParseQuality = models.QualityClean
	}
	if entry.ParseQuality == models.QualityClean && (dirty || entry.Fields["dst"] != nil) {
		entry.ParseQuality = models.QualityPartial
	}

	if entry.Timestamp.IsZero() {
		// No usable timestamp: inherit the previous entry's so time-window rules keep
		// working on order, and say so explicitly.
		if !r.ctx.last.IsZero() {
			entry.Timestamp = r.ctx.last
			entry.Fields["timestamp_inherited"] = true
		} else {
			entry.Fields["timestamp_missing"] = true
		}
	} else {
		r.ctx.last = entry.Timestamp
	}

	extractAuthFields(entry)
	return entry, nil
}

// parseRecord runs the structured parsers on the first physical line (or the whole
// JSON object) and folds continuation lines into the message.
func (r *ParserRegistry) parseRecord(lines []string, raw, jsonText string) (*models.LogEntry, error) {
	head := lines[0]
	wholeRecord := true // the parsers see every physical line (JSON objects)
	switch {
	case jsonText != "":
		head = jsonText
	case strings.HasPrefix(strings.TrimSpace(head), "{"), r.csv.header != nil, isEventXMLStart(head):
		head = raw
	default:
		wholeRecord = false
	}
	head = strings.TrimSpace(head)

	for _, p := range r.parsers {
		if !p.CanParse(head) {
			continue
		}
		entry, err := p.Parse(head)
		if err != nil || entry == nil {
			continue
		}
		entry.Parser = p.Name()
		if !wholeRecord && len(lines) > 1 {
			entry.Message += "\n" + strings.Join(lines[1:], "\n")
		}
		return entry, nil
	}

	entry, err := r.generic.Parse(strings.TrimSpace(raw))
	if entry != nil {
		entry.Parser = r.generic.Name()
		entry.ParseQuality = models.QualityBestEffort
	}
	return entry, err
}

var stackFramePattern = regexp.MustCompile(`^(?:at |Caused by:|\.\.\. \d+ more|Traceback \(most recent call last\)|[A-Za-z_][\w.]*(?:Error|Exception)(?::|$))`)

// isContinuation reports whether a physical line belongs to the previous entry.
func isContinuation(line string) bool {
	if line == "" {
		return false
	}
	if line[0] == ' ' || line[0] == '\t' {
		return true
	}
	return stackFramePattern.MatchString(line)
}

// decodeMixedEncoding strips a UTF-8 BOM, removes NUL bytes (UTF-16 artefacts) and
// decodes invalid UTF-8 as Latin-1. It returns the repairs applied.
func decodeMixedEncoding(s string) (string, []string) {
	var repairs []string
	if strings.HasPrefix(s, bom) {
		s = s[len(bom):]
		repairs = append(repairs, "bom")
	}
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
		repairs = append(repairs, "nul")
	}
	if utf8.ValidString(s) {
		return s, repairs
	}

	// Latin-1: every byte maps to the code point of the same value. Valid UTF-8
	// sequences inside a mostly-Latin-1 line are decoded as Latin-1 too, which is
	// what a Latin-1 writer meant.
	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for i := 0; i < len(s); i++ {
		b.WriteRune(rune(s[i]))
	}
	return b.String(), append(repairs, "latin1")
}

// truncateUTF8 cuts s to at most n bytes without splitting a multi-byte rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// parseSeverityKeyword extracts severity from common keywords in log messages
func parseSeverityKeyword(message string) models.Severity {
	lower := strings.ToLower(message)

	if strings.Contains(lower, "emerg") || strings.Contains(lower, "panic") {
		return models.SeverityEmergency
	}
	if strings.Contains(lower, "alert") {
		return models.SeverityAlert
	}
	if strings.Contains(lower, "crit") || strings.Contains(lower, "fatal") {
		return models.SeverityCritical
	}
	if strings.Contains(lower, "error") || strings.Contains(lower, "err") ||
		strings.Contains(lower, "fail") {
		return models.SeverityError
	}
	if strings.Contains(lower, "warn") {
		return models.SeverityWarning
	}
	if strings.Contains(lower, "notice") {
		return models.SeverityNotice
	}
	if strings.Contains(lower, "debug") {
		return models.SeverityDebug
	}

	return models.SeverityInfo
}
