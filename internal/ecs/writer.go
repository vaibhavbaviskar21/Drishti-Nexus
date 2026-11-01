package ecs

import (
	"bufio"
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/models"
	"encoding/json"
	"io"
	"strings"
)

// Writer streams entries as ECS NDJSON (one document per line), so exports
// are not bounded by the in-memory store.
type Writer struct {
	buf     *bufio.Writer
	enc     *json.Encoder
	byLabel map[string]*audit.EvidenceFile
	session string
	err     error
}

// NewWriter writes to out; session supplies the evidence files and session ID.
func NewWriter(out io.Writer, session *audit.Session) *Writer {
	buf := bufio.NewWriterSize(out, 1<<20)
	w := &Writer{buf: buf, enc: json.NewEncoder(buf), byLabel: map[string]*audit.EvidenceFile{}, session: session.SessionID}
	w.enc.SetEscapeHTML(false) // keep "<script>" in attack payloads readable
	for _, ev := range session.Evidence {
		w.byLabel[ev.Label] = ev
	}
	return w
}

// Write appends one entry. The first error is kept and returned by Flush.
func (w *Writer) Write(e *models.LogEntry) {
	if w.err != nil {
		return
	}
	var ev *audit.EvidenceFile
	if i := strings.LastIndexByte(e.ID, ':'); i > 0 {
		ev = w.byLabel[e.ID[:i]]
	}
	w.err = w.enc.Encode(Event(e, ev, w.session))
}

// Flush writes buffered documents and reports the first error.
func (w *Writer) Flush() error {
	if w.err != nil {
		return w.err
	}
	return w.buf.Flush()
}
