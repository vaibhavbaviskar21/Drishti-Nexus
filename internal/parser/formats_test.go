package parser

import (
	"drishti-nexus/internal/models"
	"testing"
	"time"
)

func TestJSON_FieldExtraction(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		source  string
		message string
		ts      time.Time
		sev     models.Severity
	}{
		{
			name:   "ECS host object and @timestamp",
			line:   `{"@timestamp":"2024-05-01T10:00:00.5Z","host":{"name":"web01"},"message":"hi","level":"warn"}`,
			source: "web01", message: "hi", ts: time.Date(2024, 5, 1, 10, 0, 0, 5e8, time.UTC), sev: models.SeverityWarning,
		},
		{
			name:   "Mordor/Windows: case-insensitive Hostname and Message",
			line:   `{"Hostname":"WORKSTATION5.theshire.local","@timestamp":"2020-08-07T14:32:25.358Z","EventTime":"2020-08-07 10:32:22","Message":"Process accessed","EventID":10}`,
			source: "WORKSTATION5.theshire.local", message: "Process accessed", ts: time.Date(2020, 8, 7, 14, 32, 25, 358e6, time.UTC),
		},
		{
			name:   "epoch seconds",
			line:   `{"time":1700000000,"host":"a","msg":"x"}`,
			source: "a", message: "x", ts: time.Unix(1700000000, 0).UTC(),
		},
		{
			name:   "epoch milliseconds",
			line:   `{"time":1700000000123,"host":"a","msg":"x"}`,
			source: "a", message: "x", ts: time.UnixMilli(1700000000123).UTC(),
		},
		{
			name:    "numeric severity outside syslog range is ignored",
			line:    `{"timestamp":"2024-05-01T10:00:00Z","severity":42,"message":"fatal error"}`,
			message: "fatal error", ts: time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC), sev: models.SeverityCritical,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := parseOne(t, Options{}, tt.line)
			if e.Parser != "json" || e.ParseQuality != models.QualityClean {
				t.Fatalf("parser=%s quality=%s", e.Parser, e.ParseQuality)
			}
			if e.Source != tt.source || e.Message != tt.message {
				t.Errorf("source=%q message=%q", e.Source, e.Message)
			}
			if !e.Timestamp.Equal(tt.ts) {
				t.Errorf("timestamp=%v want %v", e.Timestamp, tt.ts)
			}
			if tt.sev != 0 && e.Severity != tt.sev {
				t.Errorf("severity=%v want %v", e.Severity, tt.sev)
			}
		})
	}
}

func TestJSON_ZonelessTimestampUsesAssumedZone(t *testing.T) {
	ist := mustLoad(t, "Asia/Kolkata")
	e := parseOne(t, Options{Location: ist}, `{"timestamp":"2024-05-01 10:00:00","message":"x"}`)
	if want := time.Date(2024, 5, 1, 4, 30, 0, 0, time.UTC); !e.Timestamp.Equal(want) {
		t.Errorf("got %v, want %v", e.Timestamp, want)
	}
	if e.Fields["tz_assumed"] != true || e.Fields["tz_offset"] != "+05:30" {
		t.Errorf("fields: %v", e.Fields)
	}
}

func TestJSON_InvalidFallsBackToGeneric(t *testing.T) {
	e := parseOne(t, Options{}, `{"unterminated": "value}`)
	if e.ParseQuality == models.QualityClean {
		t.Errorf("invalid JSON parsed as Clean")
	}
}

func TestApache_CombinedAndCommon(t *testing.T) {
	e := parseOne(t, Options{}, `203.0.113.7 - - [10/Oct/2023:13:55:36 -0700] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 200 2326 "http://ref/" "curl/8.0"`)
	if e.Parser != "apache" || e.Source != "" || e.Fields["src_ip"] != "203.0.113.7" || e.Fields["status"] != "200" || e.Fields["user_agent"] != "curl/8.0" {
		t.Errorf("combined: parser=%s source=%s fields=%v", e.Parser, e.Source, e.Fields)
	}
	if want := time.Date(2023, 10, 10, 20, 55, 36, 0, time.UTC); !e.Timestamp.Equal(want) || e.Fields["tz_offset"] != "-07:00" {
		t.Errorf("combined time %v offset %v", e.Timestamp, e.Fields["tz_offset"])
	}

	e = parseOne(t, Options{}, `10.0.0.1 - frank [10/Oct/2023:13:55:36 +0000] "POST /login HTTP/1.0" 401 12`)
	if e.Parser != "apache" || e.Severity != models.SeverityWarning || e.Fields["src_ip"] != "10.0.0.1" {
		t.Errorf("common: parser=%s severity=%v fields=%v", e.Parser, e.Severity, e.Fields)
	}
}

func TestGeneric_LeadingTimestampFormats(t *testing.T) {
	tests := []struct {
		line string
		want time.Time
	}{
		{"2024-05-01 10:00:00,123 ERROR something broke", time.Date(2024, 5, 1, 10, 0, 0, 123e6, time.UTC)},
		{"[2024-05-01T10:00:00Z] worker started", time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)},
		{"2024/05/01 10:00:00 [error] 123#0: open() failed", time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)},
	}
	for _, tt := range tests {
		e := parseOne(t, Options{}, tt.line)
		if e.Parser != "generic" {
			t.Errorf("%q: parser=%s, want generic", tt.line, e.Parser)
		}
		if !e.Timestamp.Equal(tt.want) {
			t.Errorf("%q: timestamp=%v, want %v", tt.line, e.Timestamp, tt.want)
		}
	}
}
