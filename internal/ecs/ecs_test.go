package ecs

import (
	"bufio"
	"bytes"
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/parser"
	"drishti-nexus/internal/pipeline"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// parse runs one line through the real parser registry.
func parse(t *testing.T, line string) *models.LogEntry {
	t.Helper()
	reg := parser.NewParserRegistryWithOptions(parser.Options{SourceLabel: "auth.log"})
	e, _ := reg.Parse(line)
	if e == nil {
		e, _ = reg.Flush()
	}
	if e == nil {
		t.Fatalf("no entry for %q", line)
	}
	return e
}

// get walks a dotted path in a nested document.
func get(doc map[string]interface{}, path string) interface{} {
	var v interface{} = doc
	for _, k := range strings.Split(path, ".") {
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func expect(t *testing.T, doc map[string]interface{}, want map[string]interface{}) {
	t.Helper()
	for path, w := range want {
		if got := get(doc, path); !reflect.DeepEqual(got, w) {
			t.Errorf("%s = %#v, want %#v", path, got, w)
		}
	}
}

func TestEvent_SSHFailure(t *testing.T) {
	line := "2025-03-10T10:14:01+00:00 web01 sshd[2101]: Failed password for deploy from 203.0.113.50 port 51120 ssh2"
	ev := &audit.EvidenceFile{Path: "/case/web01/auth.log", SHA256Before: "abc"}
	doc := Event(parse(t, line), ev, "sess1")
	expect(t, doc, map[string]interface{}{
		"@timestamp":              "2025-03-10T10:14:01Z",
		"event.original":          line,
		"event.id":                "auth.log:1",
		"event.category":          []string{"authentication"},
		"event.outcome":           "failure",
		"event.action":            "password_failed",
		"host.name":               "web01",
		"user.name":               "deploy",
		"source.ip":               "203.0.113.50",
		"source.port":             51120,
		"process.name":            "sshd",
		"process.pid":             2101,
		"log.file.path":           "/case/web01/auth.log",
		"drishti.evidence_sha256": "abc",
		"drishti.session_id":      "sess1",
		"drishti.line":            1,
		"drishti.parse_quality":   models.QualityClean,
	})
	// Internal-only markers never leak as top-level ECS; unmapped fields are kept, not dropped.
	if get(doc, "auth_result") != nil || get(doc, "drishti.fields.auth_count") == nil {
		t.Errorf("unexpected field placement: %v", doc["drishti"])
	}
}

func TestEvent_ApacheAccess(t *testing.T) {
	line := `203.0.113.7 - - [10/Mar/2025:10:00:00 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 - "-" "curl/8.0"`
	doc := Event(parse(t, line), nil, "")
	expect(t, doc, map[string]interface{}{
		"source.ip":                 "203.0.113.7",
		"http.request.method":       "GET",
		"url.original":              "/search?q=' OR '1'='1",
		"http.version":              "1.1",
		"http.response.status_code": 200,
		"user_agent.original":       "curl/8.0",
		"host.name":                 nil, // the client is not the host
		"http.response.body.bytes":  nil, // "-" is not a size
		"drishti.fields.size":       "-", // ...so it stays as parsed
	})
}

func TestEvent_WindowsJSON(t *testing.T) {
	logon := `{"EventID":4625,"Hostname":"WORKSTATION5","Channel":"Security","TargetUserName":"bob","IpAddress":"10.0.0.9","@timestamp":"2020-09-20T12:16:08.000Z","Message":"An account failed to log on."}`
	expect(t, Event(parse(t, logon), nil, ""), map[string]interface{}{
		"winlog.event_id": 4625,
		"event.code":      "4625",
		"winlog.channel":  "Security",
		"host.name":       "WORKSTATION5",
		"user.name":       "bob",
		"source.ip":       "10.0.0.9",
		"event.outcome":   "failure",
	})
	proc := `{"EventID":1,"Hostname":"WORKSTATION5","Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"cmd.exe /c whoami","ParentImage":"C:\\Windows\\explorer.exe","ProcessId":4242,"@timestamp":"2020-09-20T12:16:09.000Z"}`
	expect(t, Event(parse(t, proc), nil, ""), map[string]interface{}{
		"process.executable":        `C:\Windows\System32\cmd.exe`,
		"process.command_line":      "cmd.exe /c whoami",
		"process.parent.executable": `C:\Windows\explorer.exe`,
		"process.pid":               4242,
		"event.outcome":             nil, // not an authentication event
	})
}

// Every entry of a real run becomes exactly one NDJSON document that traces back to its evidence.
func TestWriter_FullPipeline(t *testing.T) {
	var out bytes.Buffer
	var w *Writer
	src := filepath.Join("..", "..", "testdata", "fixtures", "sample_auth.log")
	res, err := pipeline.Run([]string{src}, pipeline.Options{
		OnStart: func(r *pipeline.Result) error { w = NewWriter(&out, r.Session); return nil },
		OnEntry: func(e *models.LogEntry, _ []*models.Alert) { w.Write(e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	sha := res.Session.Evidence[0].SHA256Before
	n := 0
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		n++
		var doc map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &doc); err != nil {
			t.Fatalf("line %d is not JSON: %v", n, err)
		}
		if get(doc, "event.original") == nil || get(doc, "drishti.evidence_sha256") != sha || get(doc, "log.file.path") != src {
			t.Errorf("document %d not traceable: %s", n, sc.Bytes())
		}
	}
	if n != res.Stats.Entries {
		t.Errorf("%d documents for %d entries", n, res.Stats.Entries)
	}
}

func TestEvent_CEF(t *testing.T) {
	line := `<134>Mar 10 10:14:01 vpn01 CEF:0|Acme|VPN|2.1|4625|User login failed|5|duser=deploy src=203.0.113.50 spt=51120 dst=10.0.0.1 dpt=443 outcome=Failure`
	doc := Event(parse(t, line), nil, "")
	expect(t, doc, map[string]interface{}{
		"observer.vendor":    "Acme",
		"observer.product":   "VPN",
		"observer.version":   "2.1",
		"event.code":         "4625",
		"event.severity":     5,
		"event.outcome":      "failure",
		"host.name":          "vpn01",
		"user.name":          "deploy",
		"source.ip":          "203.0.113.50",
		"source.port":        51120,
		"destination.ip":     "10.0.0.1",
		"destination.port":   443,
		"drishti.parser":     "cef",
		"drishti.fields.cef": map[string]string{"duser": "deploy", "src": "203.0.113.50", "spt": "51120", "dst": "10.0.0.1", "dpt": "443", "outcome": "Failure"},
		"drishti.fields.tag": nil,
	})
}
