package parser

import (
	"drishti-nexus/internal/models"
	"strconv"
	"strings"
	"testing"
	"time"
)

// feed runs lines through a registry and returns every emitted entry (Flush included).
func feed(t *testing.T, reg *ParserRegistry, lines ...string) []*models.LogEntry {
	t.Helper()
	var out []*models.LogEntry
	for _, l := range lines {
		e, err := reg.Parse(l)
		if err != nil {
			t.Fatalf("Parse(%q): %v", l, err)
		}
		if e != nil {
			out = append(out, e)
		}
	}
	e, err := reg.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if e != nil {
		out = append(out, e)
	}
	return out
}

func newTestRegistry() *ParserRegistry {
	return NewParserRegistryWithOptions(Options{
		SourceLabel: "test.log",
		Reference:   time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	})
}

func TestDecodeMixedEncoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		repairs  string
	}{
		{"clean UTF-8", "Hello World", "Hello World", ""},
		{"UTF-8 with BOM", "\xef\xbb\xbfHello World", "Hello World", "bom"},
		{"NUL bytes (UTF-16 artefact)", "Hello\x00 World", "Hello World", "nul"},
		{"Latin-1", "Caf\xe9", "Café", "latin1"},
		{"valid multibyte UTF-8 untouched", "Zürich 東京", "Zürich 東京", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, repairs := decodeMixedEncoding(tt.input)
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
			if got := strings.Join(repairs, ","); got != tt.repairs {
				t.Errorf("repairs = %q, want %q", got, tt.repairs)
			}
		})
	}
}

// Regression: plain BSD syslog lines (no <PRI>) used to be glued together into one
// multi-line buffer until 512 KB, so 50,000 lines produced 9 entries.
func TestRegistry_EveryPlainSyslogLineIsOneEntry(t *testing.T) {
	lines := []string{
		"Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
		"Dec 10 06:55:46 LabSZ sshd[24200]: input_userauth_request: invalid user webmaster [preauth]",
		"Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2",
	}
	entries := feed(t, newTestRegistry(), lines...)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	for i, e := range entries {
		if e.Parser != "syslog" || e.ParseQuality != models.QualityClean {
			t.Errorf("entry %d: parser=%s quality=%s, want syslog/Clean", i, e.Parser, e.ParseQuality)
		}
		if e.Source != "LabSZ" {
			t.Errorf("entry %d: source=%q, want LabSZ", i, e.Source)
		}
		if e.LineNumber != i+1 || e.ID != "test.log:"+strconv.Itoa(i+1) {
			t.Errorf("entry %d: line=%d id=%s", i, e.LineNumber, e.ID)
		}
	}
}

func TestRegistry_MultilineJSON(t *testing.T) {
	entries := feed(t, newTestRegistry(),
		`{`,
		`  "timestamp": "2023-10-04T12:00:00Z",`,
		`  "message": "test message"`,
		`}`,
		`{"timestamp": "2023-10-04T12:00:01Z", "message": "second"}`,
	)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Message != "test message" || entries[0].Parser != "json" {
		t.Errorf("first entry: %+v", entries[0])
	}
	if entries[0].LineNumber != 1 || entries[1].LineNumber != 5 {
		t.Errorf("line numbers %d, %d; want 1, 5", entries[0].LineNumber, entries[1].LineNumber)
	}
	if entries[0].Fields["line_count"] != 4 {
		t.Errorf("line_count = %v, want 4", entries[0].Fields["line_count"])
	}
}

func TestRegistry_JSONWithEmbeddedNewlineInString(t *testing.T) {
	// A pretty-printer that wraps inside a string value produces a raw newline
	// inside the string, which is invalid JSON; the record must still be one entry.
	entries := feed(t, newTestRegistry(),
		`{"message": "line one`,
		`line two", "level": "error"}`,
		`Jan  5 10:00:00 host app: next record`,
	)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	if entries[0].Fields["json_incomplete"] == nil && entries[0].ParseQuality == models.QualityClean {
		t.Errorf("malformed JSON should not be Clean: %+v", entries[0])
	}
	if entries[1].Source != "host" {
		t.Errorf("record after malformed JSON lost: %+v", entries[1])
	}
}

func TestRegistry_UnterminatedJSONAtEOF(t *testing.T) {
	entries := feed(t, newTestRegistry(), `{"message": "cut off`, `  "more": 1`)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Fields["json_incomplete"] != true || entries[0].ParseQuality == models.QualityClean {
		t.Errorf("truncated JSON must be flagged: quality=%s fields=%v", entries[0].ParseQuality, entries[0].Fields)
	}
}

func TestRegistry_StackTraceFoldedIntoEntry(t *testing.T) {
	entries := feed(t, newTestRegistry(),
		`2024-03-01T10:00:00Z app01 java[42]: Unhandled exception`,
		`java.lang.IllegalStateException: boom`,
		`	at com.example.Foo.bar(Foo.java:10)`,
		`	at com.example.Main.main(Main.java:3)`,
		`Caused by: java.io.IOException: disk`,
		`	... 2 more`,
		`2024-03-01T10:00:01Z app01 java[42]: recovered`,
	)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if !strings.Contains(entries[0].Message, "Caused by: java.io.IOException") || entries[0].Fields["line_count"] != 6 {
		t.Errorf("stack trace not folded: %q (%v lines)", entries[0].Message, entries[0].Fields["line_count"])
	}
	if entries[1].Message != "recovered" || entries[1].LineNumber != 7 {
		t.Errorf("second entry: %+v", entries[1])
	}
}

func TestRegistry_UnrecognisedLinesAreSeparateEntries(t *testing.T) {
	entries := feed(t, newTestRegistry(), "garbage one", "garbage two", "", "garbage three")
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3 (unknown lines must not be glued together)", len(entries))
	}
	for _, e := range entries {
		if e.ParseQuality != models.QualityBestEffort || e.Parser != "generic" {
			t.Errorf("unknown line: quality=%s parser=%s", e.ParseQuality, e.Parser)
		}
	}
}

func TestRegistry_TruncateLargeLine(t *testing.T) {
	entries := feed(t, newTestRegistry(), "Jan  5 10:00:00 host app: "+strings.Repeat("a", 2*MaxLineBytes))
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	e := entries[0]
	if len(e.RawLog) > MaxLineBytes+len(truncatedMarker) {
		t.Errorf("not truncated: %d bytes", len(e.RawLog))
	}
	if e.Fields["truncated"] != true || e.ParseQuality != models.QualityPartial {
		t.Errorf("truncation not flagged: quality=%s", e.ParseQuality)
	}
}

func TestRegistry_CRLFAndBOM(t *testing.T) {
	entries := feed(t, newTestRegistry(),
		"\xef\xbb\xbfJan  5 10:00:00 host sshd[1]: first\r",
		"Jan  5 10:00:01 host sshd[1]: second\r",
	)
	if len(entries) != 2 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[0].Message != "first" || entries[1].Message != "second" {
		t.Errorf("CR not stripped: %q %q", entries[0].Message, entries[1].Message)
	}
	if entries[0].ParseQuality != models.QualityClean || entries[0].Fields["bom_stripped"] != true {
		t.Errorf("BOM on line 1 should be stripped without downgrading quality: %s %v", entries[0].ParseQuality, entries[0].Fields)
	}
}

func TestRegistry_Latin1LineIsPartial(t *testing.T) {
	entries := feed(t, newTestRegistry(), "Jan  5 10:00:00 host app: Caf\xe9 ouvert")
	if entries[0].Message != "Café ouvert" || entries[0].ParseQuality != models.QualityPartial {
		t.Errorf("got %q quality=%s", entries[0].Message, entries[0].ParseQuality)
	}
}

func TestRegistry_TimestampInheritedForTimelessLines(t *testing.T) {
	entries := feed(t, newTestRegistry(),
		"Jan  5 10:00:00 host app: anchor",
		"no timestamp here",
	)
	if len(entries) != 2 {
		t.Fatalf("got %d entries", len(entries))
	}
	if !entries[1].Timestamp.Equal(entries[0].Timestamp) || entries[1].Fields["timestamp_inherited"] != true {
		t.Errorf("timeless line should inherit previous timestamp and say so: %v %v", entries[1].Timestamp, entries[1].Fields)
	}

	first := feed(t, newTestRegistry(), "no timestamp at all")
	if !first[0].Timestamp.IsZero() || first[0].Fields["timestamp_missing"] != true {
		t.Errorf("first timeless line must not get a fabricated time: %v", first[0].Timestamp)
	}
}

func TestRegistry_SetLineOffsetKeepsIDsStable(t *testing.T) {
	reg := newTestRegistry()
	reg.SetLineOffset(100)
	entries := feed(t, reg, "Jan  5 10:00:00 host app: resumed")
	if entries[0].ID != "test.log:101" {
		t.Errorf("ID = %s, want test.log:101", entries[0].ID)
	}
}

func TestRegistry_PendingStartLine(t *testing.T) {
	reg := newTestRegistry()
	if reg.PendingStartLine() != 0 {
		t.Fatal("empty registry should have nothing pending")
	}
	_, _ = reg.Parse("Jan  5 10:00:00 host app: one")
	_, _ = reg.Parse("  continuation")
	if got := reg.PendingStartLine(); got != 1 {
		t.Errorf("PendingStartLine = %d, want 1", got)
	}
	_, _ = reg.Parse("Jan  5 10:00:01 host app: two")
	if got := reg.PendingStartLine(); got != 3 {
		t.Errorf("PendingStartLine = %d, want 3", got)
	}
}
