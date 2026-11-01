package parser

import (
	"drishti-nexus/internal/models"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadCustomFormats_Shipped(t *testing.T) {
	formats, err := LoadCustomFormats(filepath.Join("..", "..", "parsers"))
	if err != nil {
		t.Fatal(err)
	}
	if len(formats) != 2 || formats[0].Name != "hdfs" || formats[1].Name != "zookeeper" || len(formats[0].SHA256) != 64 {
		t.Errorf("formats: %+v", formats)
	}
}

func TestLoadCustomFormats_RejectsBadDefinitions(t *testing.T) {
	for name, def := range map[string]string{
		"unknown key":     "name: x\npattern: '(?P<a>.)'\npatern: typo\n",
		"bad regex":       "name: x\npattern: '(?P<a>'\n",
		"no named groups": "name: x\npattern: '^(.*)$'\n",
		"zone abbrev":     "name: x\npattern: '(?P<timestamp>.*)'\ntime_layout: 'Jan 2 15:04:05 MST'\n",
		"builtin name":    "name: syslog\npattern: '(?P<a>.)'\n",
		"missing name":    "pattern: '(?P<a>.)'\n",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(def), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCustomFormats(dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	dir := t.TempDir()
	for _, f := range []string{"a.yaml", "b.yml"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("name: same\npattern: '(?P<a>.)'\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadCustomFormats(dir); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Errorf("duplicate names: %v", err)
	}
	if _, err := LoadCustomFormats(t.TempDir()); err == nil {
		t.Error("an empty folder must be an error: -parsers pointing at the wrong place should not pass silently")
	}
}

func shipped(t *testing.T) []*CustomFormat {
	t.Helper()
	f, err := LoadCustomFormats(filepath.Join("..", "..", "parsers"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCustomFormat_LogHubLines(t *testing.T) {
	opts := Options{Custom: shipped(t)}

	// LogHub HDFS
	e := parseOne(t, opts, "081109 204005 35 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.73.220:50010 is added to blk_7128370237687728475 size 67108864")
	if e.Parser != "hdfs" || e.ParseQuality != models.QualityClean || !e.Timestamp.Equal(time.Date(2008, 11, 9, 20, 40, 5, 0, time.UTC)) ||
		e.Fields["pid"] != "35" || e.Fields["program"] != "dfs.FSNamesystem" || !strings.HasPrefix(e.Message, "BLOCK* NameSystem") || e.Facility != "hdfs" {
		t.Errorf("hdfs: parser=%s quality=%s ts=%s msg=%q fields=%v", e.Parser, e.ParseQuality, e.Timestamp, e.Message, e.Fields)
	}

	// LogHub Zookeeper: brackets and colons inside the thread name
	e = parseOne(t, opts, "2015-07-29 19:04:29,071 - WARN  [SendWorker:188978561024:QuorumCnxManager$SendWorker@688] - Send worker leaving thread")
	if e.Parser != "zookeeper" || e.Severity != models.SeverityWarning || e.Fields["thread"] != "SendWorker:188978561024" ||
		e.Fields["program"] != "QuorumCnxManager$SendWorker" || e.Fields["source_line"] != "688" || e.Message != "Send worker leaving thread" ||
		!e.Timestamp.Equal(time.Date(2015, 7, 29, 19, 4, 29, 71e6, time.UTC)) {
		t.Errorf("zookeeper: parser=%s sev=%v ts=%s msg=%q fields=%v", e.Parser, e.Severity, e.Timestamp, e.Message, e.Fields)
	}
	e = parseOne(t, opts, "2015-07-29 17:41:44,747 - INFO  [QuorumPeer[myid=1]/0:0:0:0:0:0:0:0:2181:FastLeaderElection@774] - Notification time out: 3200")
	if e.Fields["thread"] != "QuorumPeer[myid=1]/0:0:0:0:0:0:0:0:2181" || e.Fields["program"] != "FastLeaderElection" {
		t.Errorf("nested brackets: %v", e.Fields)
	}

	// Without the definitions the same line is raw text only.
	if e := parseOne(t, Options{}, "081109 204005 35 INFO dfs.FSNamesystem: x"); e.Parser == "hdfs" {
		t.Error("custom parser active without being loaded")
	}
}

func TestCustomFormat_TimeHandling(t *testing.T) {
	dir := t.TempDir()
	def := `name: app
pattern: '^(?P<timestamp>\w{3} +\d+ \d\d:\d\d:\d\d) (?P<user>\S+) (?P<client>\S+) (?P<message>.*)$'
time_layout: 'Jan _2 15:04:05'
rename: {client: src_ip}
`
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(def), 0o600); err != nil {
		t.Fatal(err)
	}
	formats, err := LoadCustomFormats(dir)
	if err != nil {
		t.Fatal(err)
	}
	ist, _ := time.LoadLocation("Asia/Kolkata")
	e := parseOne(t, Options{Custom: formats, Location: ist}, "Mar  3 10:00:00 bob 10.0.0.9 Failed password for bob from 10.0.0.9 port 22 ssh2")
	// Year-less: inferred from the reference (2025-06-01); zone-less: read in -tz and stored as UTC.
	if !e.Timestamp.Equal(time.Date(2025, 3, 3, 4, 30, 0, 0, time.UTC)) || e.Fields["year_inferred"] != 2025 || e.Fields["tz_assumed"] != true {
		t.Errorf("ts=%s fields=%v", e.Timestamp, e.Fields)
	}
	if e.Fields["src_ip"] != "10.0.0.9" || e.Fields["user"] != "bob" || e.Fields["auth_result"] != "failure" {
		t.Errorf("rename / auth extraction: %v", e.Fields)
	}
}
