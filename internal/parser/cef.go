package parser

import (
	"drishti-nexus/internal/models"
	"errors"
	"strconv"
	"strings"
	"time"
)

// CEF (ArcSight Common Event Format) and LEEF (IBM QRadar Log Event Extended
// Format) parsers. Both usually arrive inside a syslog envelope
// ("<134>Sep 19 08:26:10 fw01 CEF:0|..."); the envelope gives the relay time and
// host, the payload gives the device's own fields. The device's event time (CEF
// rt, LEEF devTime) wins over the envelope time, as the LEEF spec requires.
//
// Every extension attribute is kept unmodified under Fields["cef"] / Fields["leef"];
// the common ones are also copied to the shared field names (src_ip, user, ...)
// that detection rules and ECS export use.

var errNotCEF = errors.New("not a CEF/LEEF record")

// CEFParser parses "CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension".
type CEFParser struct{ env *SyslogParser }

func NewCEFParser(ctx *Context) *CEFParser { return &CEFParser{env: NewSyslogParser(ctx)} }

func (p *CEFParser) Name() string              { return "cef" }
func (p *CEFParser) CanParse(line string) bool { return strings.Contains(line, "CEF:") }

func (p *CEFParser) Parse(line string) (*models.LogEntry, error) {
	i := payloadIndex(line, "CEF:")
	if i < 0 {
		return nil, errNotCEF
	}
	hdr, ext, ok := splitCEFHeader(line[i+len("CEF:"):])
	if !ok || (hdr[0] != "0" && hdr[0] != "1") {
		return nil, errNotCEF
	}
	attrs := parseCEFExtension(ext)

	entry := envelope(p.env, line, i)
	f := entry.Fields
	f["cef_version"], f["vendor"], f["product"], f["product_version"] = hdr[0], hdr[1], hdr[2], hdr[3]
	f["event_class_id"], f["vendor_severity"] = hdr[4], hdr[6]
	f["cef"] = attrs

	entry.Facility = hdr[2]
	entry.Message = hdr[5]
	if msg := attrs["msg"]; msg != "" {
		entry.Message += ": " + msg
	}
	entry.Severity = vendorSeverity(hdr[6])
	copyAttrs(f, attrs, map[string]string{"src": "src_ip", "spt": "src_port", "dst": "dst_ip", "dpt": "dst_port"})
	// duser is the account acted on (the login target); suser the acting account.
	firstAttr(f, "user", attrs, "duser", "suser")
	if entry.Source == "" {
		entry.Source = firstOf(attrs, "dvchost", "dvc")
	}
	deviceTime(entry, p.env.ctx, attrs["rt"])
	authFromVendor(f, hdr[5]+" "+hdr[4]+" "+attrs["cat"], attrs["outcome"]+" "+attrs["cat"]+" "+hdr[5])
	return entry, nil
}

// LEEFParser parses LEEF 1.0 ("LEEF:1.0|Vendor|Product|Version|EventID|" + tab-separated
// key=value) and 2.0 (an extra "|DelimiterCharacter|" field, a char or hex x5E / 0x5E).
type LEEFParser struct{ env *SyslogParser }

func NewLEEFParser(ctx *Context) *LEEFParser { return &LEEFParser{env: NewSyslogParser(ctx)} }

func (p *LEEFParser) Name() string              { return "leef" }
func (p *LEEFParser) CanParse(line string) bool { return strings.Contains(line, "LEEF:") }

func (p *LEEFParser) Parse(line string) (*models.LogEntry, error) {
	i := payloadIndex(line, "LEEF:")
	if i < 0 {
		return nil, errNotCEF
	}
	parts := strings.SplitN(line[i+len("LEEF:"):], "|", 7)
	if len(parts) < 6 {
		return nil, errNotCEF
	}
	version, delim, body := parts[0], "\t", parts[5]
	switch {
	case strings.HasPrefix(version, "1"):
		body = strings.Join(parts[5:], "|") // 1.0 has no delimiter field; a '|' here belongs to a value
	case strings.HasPrefix(version, "2") && len(parts) == 7:
		d, ok := leefDelimiter(parts[5])
		if !ok {
			return nil, errNotCEF
		}
		delim, body = d, parts[6]
	case strings.HasPrefix(version, "2"): // delimiter field omitted: default tab
	default:
		return nil, errNotCEF
	}

	attrs := map[string]string{}
	for _, kv := range strings.Split(body, delim) {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			attrs[strings.TrimSpace(k)] = v
		}
	}

	entry := envelope(p.env, line, i)
	f := entry.Fields
	f["leef_version"], f["vendor"], f["product"], f["product_version"], f["event_class_id"] = version, parts[1], parts[2], parts[3], parts[4]
	f["leef"] = attrs

	entry.Facility = parts[2]
	entry.Message = parts[4]
	if cat := attrs["cat"]; cat != "" {
		entry.Message += ": " + cat
	}
	if sev := attrs["sev"]; sev != "" {
		f["vendor_severity"] = sev
		entry.Severity = vendorSeverity(sev)
	}
	copyAttrs(f, attrs, map[string]string{"src": "src_ip", "srcPort": "src_port", "dst": "dst_ip", "dstPort": "dst_port"})
	firstAttr(f, "user", attrs, "usrName", "accountName")
	if entry.Source == "" {
		entry.Source = firstOf(attrs, "identHostName")
	}
	deviceTime(entry, p.env.ctx, attrs["devTime"])
	authFromVendor(f, parts[4]+" "+attrs["cat"], attrs["cat"]+" "+parts[4])
	return entry, nil
}

// payloadIndex finds marker at the start of the line or after a space (the end of a
// syslog envelope), so "CEF:" inside ordinary message text does not match.
func payloadIndex(line, marker string) int {
	for from := 0; ; {
		j := strings.Index(line[from:], marker)
		if j < 0 {
			return -1
		}
		at := from + j
		if at == 0 || line[at-1] == ' ' {
			return at
		}
		from = at + 1
	}
}

// envelope parses the syslog header before the payload at i, if any, for its
// host and relay time. The bogus "CEF"/"LEEF" tag it would read is dropped.
func envelope(sp *SyslogParser, line string, i int) *models.LogEntry {
	entry := &models.LogEntry{RawLog: line, Severity: models.SeverityInfo, Tags: []string{}}
	if i > 0 {
		if e, err := sp.Parse(line); err == nil && e != nil {
			entry.Timestamp, entry.Source, entry.Fields = e.Timestamp, e.Source, e.Fields
			if tag, _ := e.Fields["tag"].(string); strings.HasPrefix(tag, "CEF") || strings.HasPrefix(tag, "LEEF") {
				delete(e.Fields, "tag")
				delete(e.Fields, "program")
				delete(e.Fields, "pid")
			}
		}
	}
	if entry.Fields == nil {
		entry.Fields = map[string]interface{}{}
	}
	return entry
}

// splitCEFHeader splits the 7 header fields (escapes \| and \\) from the extension.
func splitCEFHeader(s string) (hdr [7]string, ext string, ok bool) {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '\\'):
			i++
			b.WriteByte(s[i])
		case c == '|':
			hdr[n] = b.String()
			b.Reset()
			if n++; n == len(hdr) {
				return hdr, strings.TrimSpace(s[i+1:]), true
			}
		default:
			b.WriteByte(c)
		}
	}
	return hdr, "", false
}

// parseCEFExtension parses space-separated key=value pairs whose values may contain
// spaces. An '=' starts a new pair only when the word before it is a valid key, so
// unescaped '=' inside URLs or base64 stays part of the value. Escapes: \= \\ \n \r.
func parseCEFExtension(ext string) map[string]string {
	out := map[string]string{}
	key, valStart := "", 0
	for i := 0; i < len(ext); i++ {
		switch ext[i] {
		case '\\':
			i++ // escaped character is never a separator
		case '=':
			ks := strings.LastIndexByte(ext[:i], ' ') + 1
			if ks < valStart || !isCEFKey(ext[ks:i]) {
				continue
			}
			if key != "" {
				out[key] = cefUnescape(strings.TrimRight(ext[valStart:ks], " "))
			}
			key, valStart = ext[ks:i], i+1
		}
	}
	if key != "" {
		out[key] = cefUnescape(strings.TrimRight(ext[valStart:], " "))
	}
	return out
}

func isCEFKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		if c := k[i]; !isWordChar(c) && !strings.ContainsRune(".[],-", rune(c)) {
			return false
		}
	}
	return true
}

func isWordChar(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

var cefUnescaper = strings.NewReplacer(`\=`, "=", `\\`, `\`, `\n`, "\n", `\r`, "\r", `\|`, "|")

func cefUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return cefUnescaper.Replace(s)
}

// leefDelimiter decodes the LEEF 2.0 delimiter field: one character, or hex "x5E"/"0x5E"
// (1-4 hex digits). Empty means the default tab.
func leefDelimiter(s string) (string, bool) {
	switch {
	case s == "":
		return "\t", true
	case len(s) == 1:
		return s, true
	}
	h, ok := strings.CutPrefix(strings.ToLower(s), "0x")
	if !ok {
		h, ok = strings.CutPrefix(strings.ToLower(s), "x")
	}
	if !ok || len(h) == 0 || len(h) > 4 {
		return "", false
	}
	n, err := strconv.ParseUint(h, 16, 32)
	if err != nil || n == 0 {
		return "", false
	}
	return string(rune(n)), true
}

// vendorSeverity maps CEF/LEEF severity (0-10, or CEF:1 words) onto syslog levels.
func vendorSeverity(s string) models.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low", "unknown", "":
		return models.SeverityInfo
	case "medium":
		return models.SeverityWarning
	case "high":
		return models.SeverityError
	case "very-high":
		return models.SeverityCritical
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	switch {
	case err != nil || n <= 3:
		return models.SeverityInfo
	case n <= 6:
		return models.SeverityWarning
	case n <= 8:
		return models.SeverityError
	}
	return models.SeverityCritical
}

// deviceTime replaces the envelope time with the device's event time when it parses:
// epoch seconds/milliseconds (10/13 digits) or a layout parseWithZoneFallback knows.
// shortcut: LEEF devTimeFormat (Java SimpleDateFormat) is not interpreted, only the
// common layouts are tried; add a pattern translator if a source needs another layout.
func deviceTime(entry *models.LogEntry, ctx *Context, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil && (len(raw) == 10 || len(raw) == 13) {
		t := time.Unix(n, 0)
		if len(raw) == 13 {
			t = time.UnixMilli(n)
		}
		entry.Timestamp = stampTime(entry.Fields, raw, t, false)
		return
	}
	if t, ok := parseWithZoneFallback(ctx, raw, entry.Fields); ok {
		entry.Timestamp = t
		return
	}
	entry.Fields["device_time_unparsed"] = raw
	entry.ParseQuality = models.QualityPartial
}

// authFromVendor marks authentication events (login/logon/auth in the event name,
// class or category) as failure or success from the outcome/category words, so the
// auth rules see vendor logins too. Anything else is left unclassified.
func authFromVendor(f map[string]interface{}, what, outcome string) {
	what, outcome = strings.ToLower(what), strings.ToLower(outcome)
	if !strings.Contains(what, "login") && !strings.Contains(what, "logon") && !strings.Contains(what, "auth") {
		return
	}
	switch {
	case strings.Contains(outcome, "fail") || strings.Contains(outcome, "denied"):
		f["auth_result"] = "failure"
	case strings.Contains(outcome, "success"):
		f["auth_result"] = "success"
	default:
		return
	}
	f["auth_event"], f["auth_count"] = "vendor_login", 1
}

func copyAttrs(f map[string]interface{}, attrs map[string]string, names map[string]string) {
	for from, to := range names {
		if v := attrs[from]; v != "" {
			f[to] = v
		}
	}
}

func firstAttr(f map[string]interface{}, to string, attrs map[string]string, from ...string) {
	if v := firstOf(attrs, from...); v != "" {
		f[to] = v
	}
}

func firstOf(attrs map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := attrs[k]; v != "" {
			return v
		}
	}
	return ""
}
