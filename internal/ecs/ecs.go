// Package ecs normalizes parsed log entries onto Elastic Common Schema (ECS)
// documents, the common event taxonomy for SIEM / data-lake export.
//
// Parsers keep their own field names (detection rules key on them); this is
// the single place they are translated. Every document keeps the original line
// (event.original) and points back to its evidence (event.id = "<file>:<line>",
// log.file.path, drishti.evidence_sha256), so normalization never loses or
// detaches the source record.
package ecs

import (
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/models"
	"strconv"
	"strings"
	"time"
)

// Version is the ECS version the documents follow.
const Version = "8.11.0"

// stringFields maps parser field names to ECS fields, values copied as-is.
var stringFields = map[string]string{
	// auth (internal/parser/auth.go) and syslog
	"user":       "user.name",
	"src_ip":     "source.ip",
	"program":    "process.name",
	"auth_event": "event.action",
	"dst_ip":     "destination.ip",
	// CEF / LEEF header
	"vendor":          "observer.vendor",
	"product":         "observer.product",
	"product_version": "observer.version",
	"event_class_id":  "event.code",
	// RFC 5424
	"app_name":        "log.syslog.appname",
	"proc_id":         "log.syslog.procid",
	"msg_id":          "log.syslog.msgid",
	"structured_data": "log.syslog.structured_data",
	// Apache / Nginx
	"method":     "http.request.method",
	"path":       "url.original",
	"referer":    "http.request.referrer",
	"user_agent": "user_agent.original",
	// Windows Security / Sysmon / PowerShell JSON (EVTX exports)
	"Channel":           "winlog.channel",
	"Image":             "process.executable",
	"CommandLine":       "process.command_line",
	"ParentImage":       "process.parent.executable",
	"ParentCommandLine": "process.parent.command_line",
	"ScriptBlockText":   "powershell.file.script_block_text",
}

// intFields maps parser fields holding integers (as string or JSON number) to ECS.
// A value that is not an integer ("-" size) stays in drishti.fields instead.
var intFields = map[string]string{
	"pid":             "process.pid",
	"src_port":        "source.port",
	"dst_port":        "destination.port",
	"vendor_severity": "event.severity", // CEF/LEEF 0-10; CEF:1 words stay in drishti.fields
	"status":          "http.response.status_code",
	"size":            "http.response.body.bytes",
	"priority":        "log.syslog.priority",
	"EventID":         "winlog.event_id",
	"ProcessId":       "process.pid",
}

// Event builds the ECS document for one entry. ev is the evidence file the
// entry came from (nil if unknown); session is the audit session ID.
func Event(e *models.LogEntry, ev *audit.EvidenceFile, session string) map[string]interface{} {
	doc := map[string]interface{}{}
	put(doc, "ecs.version", Version)
	if !e.Timestamp.IsZero() {
		put(doc, "@timestamp", e.Timestamp.UTC().Format(time.RFC3339Nano))
	}
	put(doc, "message", e.Message)
	put(doc, "event.kind", "event")
	put(doc, "event.id", e.ID)
	put(doc, "event.original", e.RawLog)
	put(doc, "log.level", strings.ToLower(e.Severity.String()))
	if e.Source != "" && e.Source != "unknown" {
		put(doc, "host.name", e.Source)
	}

	put(doc, "drishti.parser", e.Parser)
	put(doc, "drishti.parse_quality", e.ParseQuality)
	put(doc, "drishti.line", e.LineNumber)
	put(doc, "drishti.facility", e.Facility)
	put(doc, "drishti.session_id", session)
	if ev != nil {
		put(doc, "log.file.path", ev.Path)
		put(doc, "drishti.evidence_sha256", ev.SHA256Before)
	}

	rest := map[string]interface{}{}
	for k, v := range e.Fields {
		if mapField(doc, k, v) {
			continue
		}
		rest[k] = v
	}
	if len(rest) > 0 {
		doc["drishti"].(map[string]interface{})["fields"] = rest
	}
	return doc
}

// mapField writes one parser field into doc; false means it has no ECS home.
func mapField(doc map[string]interface{}, k string, v interface{}) bool {
	if dst, ok := stringFields[k]; ok {
		if s, ok := v.(string); ok && s != "" && s != "-" {
			put(doc, dst, s)
			return true
		}
		return false
	}
	if dst, ok := intFields[k]; ok {
		n, ok := toInt(v)
		if ok {
			put(doc, dst, n)
			if k == "EventID" {
				put(doc, "event.code", strconv.Itoa(n))
			}
		}
		return ok
	}
	switch k {
	case "protocol": // "HTTP/1.1" → http.version "1.1"
		if s, ok := v.(string); ok && strings.HasPrefix(s, "HTTP/") {
			put(doc, "http.version", strings.TrimPrefix(s, "HTTP/"))
			return true
		}
	case "auth_result":
		switch v {
		case "failure", "success":
			put(doc, "event.category", []string{"authentication"})
			put(doc, "event.outcome", v)
		}
		return true // "info" / "none" are internal markers with no ECS meaning
	}
	return false
}

func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	case string:
		if i, err := strconv.Atoi(n); err == nil {
			return i, true
		}
	}
	return 0, false
}

// put sets a dotted ECS path ("http.request.method") in a nested document.
// Empty strings are skipped: ECS documents omit absent fields.
func put(doc map[string]interface{}, path string, v interface{}) {
	if s, ok := v.(string); ok && s == "" {
		return
	}
	keys := strings.Split(path, ".")
	m := doc
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]interface{})
		if !ok {
			next = map[string]interface{}{}
			m[k] = next
		}
		m = next
	}
	m[keys[len(keys)-1]] = v
}
