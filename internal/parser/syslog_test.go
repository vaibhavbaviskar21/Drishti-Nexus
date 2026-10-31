package parser

import (
	"drishti-nexus/internal/models"
	"testing"
	"time"
)

func parseOne(t *testing.T, opts Options, line string) *models.LogEntry {
	t.Helper()
	if opts.Reference.IsZero() {
		opts.Reference = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	}
	entries := feed(t, NewParserRegistryWithOptions(opts), line)
	if len(entries) != 1 {
		t.Fatalf("got %d entries for %q", len(entries), line)
	}
	return entries[0]
}

func TestSyslog_FormatDetection(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		parser   string
		source   string
		tag      string
		pid      string
		message  string
		severity models.Severity
	}{
		{
			name: "BSD auth.log (no PRI)", parser: "syslog",
			line:   "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
			source: "LabSZ", tag: "sshd", pid: "24200", message: "Invalid user webmaster from 173.234.31.186",
		},
		{
			name: "BSD space-padded day", parser: "syslog",
			line:   "Jun  9 06:06:20 combo syslogd 1.4.1: restart.",
			source: "combo", tag: "syslogd 1.4.1", message: "restart.",
		},
		{
			name: "BSD tag with pam annotation", parser: "syslog",
			line:   "Jun 15 02:04:59 combo sshd(pam_unix)[20882]: authentication failure; logname= uid=0",
			source: "combo", tag: "sshd(pam_unix)", pid: "20882", message: "authentication failure; logname= uid=0",
		},
		{
			name: "BSD without tag", parser: "syslog",
			line:   "Jun 15 02:04:59 combo just a message without a tag",
			source: "combo", message: "just a message without a tag",
		},
		{
			name: "RFC 3164 with PRI", parser: "syslog",
			line:   "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
			source: "mymachine", tag: "su", message: "'su root' failed for lonvick on /dev/pts/8", severity: models.SeverityCritical,
		},
		{
			name: "RFC 5424 with structured data", parser: "syslog",
			line:   `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application"] An application event`,
			source: "mymachine.example.com", message: "An application event", severity: models.SeverityNotice,
		},
		{
			name: "RFC 5424 nil structured data", parser: "syslog",
			line:   `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed`,
			source: "mymachine.example.com", message: "'su root' failed", severity: models.SeverityCritical,
		},
		{
			name: "RFC 3339 prefixed (rsyslog)", parser: "syslog",
			line:   "2024-03-01T10:00:00.123+05:30 web01 nginx[77]: started",
			source: "web01", tag: "nginx", pid: "77", message: "started",
		},
		{
			name: "looks like syslog but bad clock", parser: "generic",
			line: "Dec 10 6:55 LabSZ sshd[1]: nope", source: "unknown",
		},
		{
			name: "month-like word", parser: "generic",
			line: "Hello world this is not a log line", source: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := parseOne(t, Options{}, tt.line)
			if e.Parser != tt.parser {
				t.Fatalf("parser = %s, want %s", e.Parser, tt.parser)
			}
			if e.Source != tt.source {
				t.Errorf("source = %q, want %q", e.Source, tt.source)
			}
			if tt.parser != "syslog" {
				return
			}
			if got, _ := e.Fields["tag"].(string); got != tt.tag {
				t.Errorf("tag = %q, want %q", got, tt.tag)
			}
			if got, _ := e.Fields["pid"].(string); got != tt.pid {
				t.Errorf("pid = %q, want %q", got, tt.pid)
			}
			if e.Message != tt.message {
				t.Errorf("message = %q, want %q", e.Message, tt.message)
			}
			if tt.severity != 0 && e.Severity != tt.severity {
				t.Errorf("severity = %v, want %v", e.Severity, tt.severity)
			}
		})
	}
}

func TestSyslog_YearInference(t *testing.T) {
	tests := []struct {
		name string
		ref  time.Time
		line string
		want time.Time
	}{
		{
			name: "same year",
			ref:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			line: "Mar  3 10:00:00 h app: x", want: time.Date(2025, 3, 3, 10, 0, 0, 0, time.UTC),
		},
		{
			name: "December entry read in January belongs to last year",
			ref:  time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			line: "Dec 31 23:59:59 h app: x", want: time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			name: "entry up to 48h after reference keeps year (clock skew)",
			ref:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			line: "Jun  2 12:00:00 h app: x", want: time.Date(2025, 6, 2, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "Feb 29 resolves to the latest leap year",
			ref:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			line: "Feb 29 08:00:00 h app: x", want: time.Date(2024, 2, 29, 8, 0, 0, 0, time.UTC),
		},
		{
			name: "fractional seconds",
			ref:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			line: "Mar  3 10:00:00.250 h app: x", want: time.Date(2025, 3, 3, 10, 0, 0, 250e6, time.UTC),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := parseOne(t, Options{Reference: tt.ref}, tt.line)
			if !e.Timestamp.Equal(tt.want) {
				t.Errorf("timestamp = %v, want %v", e.Timestamp, tt.want)
			}
			if e.Fields["year_inferred"] != tt.want.Year() {
				t.Errorf("year_inferred = %v", e.Fields["year_inferred"])
			}
		})
	}
}

func TestSyslog_TimezoneNormalisedToUTCWithOriginalOffsetRetained(t *testing.T) {
	ist, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		t.Skip("tzdata unavailable:", err)
	}

	// Zone-less BSD timestamp interpreted in the assumed zone.
	e := parseOne(t, Options{Location: ist}, "Mar  3 10:00:00 h app: x")
	if want := time.Date(2025, 3, 3, 4, 30, 0, 0, time.UTC); !e.Timestamp.Equal(want) || e.Timestamp.Location() != time.UTC {
		t.Errorf("timestamp = %v, want %v in UTC", e.Timestamp, want)
	}
	if e.Fields["tz_offset"] != "+05:30" || e.Fields["tz_assumed"] != true || e.Fields["timestamp_raw"] != "Mar  3 10:00:00" {
		t.Errorf("provenance fields wrong: %v", e.Fields)
	}

	// Explicit offset in the log wins over the assumed zone, and is not "assumed".
	e = parseOne(t, Options{Location: ist}, "2024-03-01T10:00:00-08:00 web01 app: x")
	if want := time.Date(2024, 3, 1, 18, 0, 0, 0, time.UTC); !e.Timestamp.Equal(want) {
		t.Errorf("timestamp = %v, want %v", e.Timestamp, want)
	}
	if e.Fields["tz_offset"] != "-08:00" || e.Fields["tz_assumed"] != nil {
		t.Errorf("explicit offset not retained: %v", e.Fields)
	}
}

func TestSplitTag(t *testing.T) {
	p := NewSyslogParser(&Context{})
	tests := []struct{ in, tag, pid, msg string }{
		{"sshd[123]: hello", "sshd", "123", "hello"},
		{"kernel: [UFW BLOCK] IN=eth0", "kernel", "", "[UFW BLOCK] IN=eth0"},
		{"postfix/smtpd[9]: connect from x[1.2.3.4]", "postfix/smtpd", "9", "connect from x[1.2.3.4]"},
		{"no colon here", "", "", "no colon here"},
		{"app[abc]: bad pid", "", "", "app[abc]: bad pid"},
		{": empty tag", "", "", ": empty tag"},
	}
	for _, tt := range tests {
		tag, pid, msg := p.splitTag(tt.in)
		if tag != tt.tag || pid != tt.pid || msg != tt.msg {
			t.Errorf("splitTag(%q) = (%q,%q,%q), want (%q,%q,%q)", tt.in, tag, pid, msg, tt.tag, tt.pid, tt.msg)
		}
	}
}
