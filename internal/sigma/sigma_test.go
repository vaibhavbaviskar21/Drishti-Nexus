package sigma

import (
	"drishti-nexus/internal/models"
	"path/filepath"
	"strings"
	"testing"
)

func win(fields map[string]interface{}) *models.LogEntry {
	if _, ok := fields["EventID"]; !ok {
		fields["EventID"] = float64(1)
		fields["Channel"] = "Microsoft-Windows-Sysmon/Operational"
	}
	return &models.LogEntry{Source: "WS1", Fields: fields}
}

func linux(msg string) *models.LogEntry {
	return &models.LogEntry{Source: "srv", Message: msg, Fields: map[string]interface{}{"program": "sshd"}}
}

func mustParse(t *testing.T, doc string) *Rule {
	t.Helper()
	r, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, doc)
	}
	return r
}

const ruleHead = "title: t\nlogsource: {product: windows, category: process_creation}\n"

func TestFieldModifiers(t *testing.T) {
	cases := []struct {
		detection string
		entry     map[string]interface{}
		want      bool
	}{
		{`sel: {Image|endswith: '\cmd.exe'}`, map[string]interface{}{"Image": `C:\Windows\System32\CMD.EXE`}, true}, // case-insensitive, literal backslash
		{`sel: {Image|endswith: '\cmd.exe'}`, map[string]interface{}{"Image": `C:\x\notcmd.exe`}, false},
		{`sel: {CommandLine|contains: ' -enc '}`, map[string]interface{}{"CommandLine": "powershell -enc SQBFAFgA"}, true},
		{`sel: {CommandLine|startswith: 'powershell'}`, map[string]interface{}{"CommandLine": "cmd /c powershell"}, false},
		{`sel: {CommandLine: 'cmd*whoami'}`, map[string]interface{}{"CommandLine": "cmd /c whoami"}, true}, // * wildcard
		{`sel: {CommandLine: 'a\*b'}`, map[string]interface{}{"CommandLine": "a*b"}, true},                 // \* is a literal star
		{`sel: {CommandLine: 'a\*b'}`, map[string]interface{}{"CommandLine": "axxb"}, false},
		{`sel: {CommandLine|contains|all: [mimikatz, sekurlsa]}`, map[string]interface{}{"CommandLine": "mimikatz sekurlsa::logonpasswords"}, true},
		{`sel: {CommandLine|contains|all: [mimikatz, sekurlsa]}`, map[string]interface{}{"CommandLine": "mimikatz coffee"}, false},
		{`sel: {CommandLine|contains: [mimikatz, sekurlsa]}`, map[string]interface{}{"CommandLine": "sekurlsa"}, true}, // list = any
		{`sel: {CommandLine|re: '^[a-z]+\.exe -x$'}`, map[string]interface{}{"CommandLine": "tool.exe -x"}, true},
		{`sel: {SourceIp|cidr: '10.0.0.0/8'}`, map[string]interface{}{"SourceIp": "10.20.30.40"}, true},
		{`sel: {SourceIp|cidr: '10.0.0.0/8'}`, map[string]interface{}{"SourceIp": "192.168.1.1"}, false},
		{`sel: {ParentImage: null}`, map[string]interface{}{}, true},
		{`sel: {ParentImage: null}`, map[string]interface{}{"ParentImage": "x"}, false},
		{`sel: {ParentImage|exists: false}`, map[string]interface{}{}, true},
		{`sel: {EventID: 1, Image|endswith: '.exe'}`, map[string]interface{}{"Image": "a.exe"}, true}, // number vs JSON number; map = AND
		{`sel: {EventID: 2, Image|endswith: '.exe'}`, map[string]interface{}{"Image": "a.exe"}, false},
		{`sel: [{Image: a.exe}, {Image: b.exe}]`, map[string]interface{}{"Image": "b.exe"}, true}, // list of maps = OR
	}
	for _, c := range cases {
		r := mustParse(t, ruleHead+"detection:\n  "+c.detection+"\n  condition: sel\n")
		if got := r.Match(win(c.entry)); got != c.want {
			t.Errorf("%s on %v: %v, want %v", c.detection, c.entry, got, c.want)
		}
	}
}

func TestConditions(t *testing.T) {
	det := "detection:\n  sel_a: {CommandLine|contains: alpha}\n  sel_b: {CommandLine|contains: beta}\n  filter: {CommandLine|contains: gamma}\n  condition: %s\n"
	for _, c := range []struct {
		cond, line string
		want       bool
	}{
		{"sel_a and not filter", "alpha", true},
		{"sel_a and not filter", "alpha gamma", false},
		{"1 of sel_* and not filter", "beta", true},
		{"all of sel_*", "alpha", false},
		{"all of sel_*", "alpha beta", true},
		{"(sel_a or sel_b) and filter", "beta gamma", true},
		{"not (sel_a or sel_b)", "delta", true},
		{"1 of them", "gamma", true},
		{"all of them", "alpha beta", false},
	} {
		r := mustParse(t, ruleHead+strings.Replace(det, "%s", c.cond, 1))
		if got := r.Match(win(map[string]interface{}{"CommandLine": c.line})); got != c.want {
			t.Errorf("%q on %q: %v, want %v", c.cond, c.line, got, c.want)
		}
	}
	// A list of conditions is an OR.
	r := mustParse(t, ruleHead+"detection:\n  a: {CommandLine: x}\n  b: {CommandLine: y}\n  condition: [a, b]\n")
	if !r.Match(win(map[string]interface{}{"CommandLine": "y"})) {
		t.Error("condition list must OR")
	}
}

func TestKeywordsAndLogsource(t *testing.T) {
	r := mustParse(t, "title: k\nlogsource: {product: linux}\ndetection:\n  keywords: ['%hn', 'evil*string']\n  condition: keywords\n")
	if !r.Match(linux("gethostbyname error for %8x%hn")) || !r.Match(linux("an evil long string")) || r.Match(linux("all good")) {
		t.Error("keyword search")
	}
	if r.Match(win(map[string]interface{}{"CommandLine": "%hn"})) {
		t.Error("a linux rule must not match Windows events")
	}

	// process_creation covers Sysmon 1 and Security 4688, with Image → NewProcessName.
	pc := mustParse(t, ruleHead+"detection:\n  sel: {Image|endswith: '\\whoami.exe'}\n  condition: sel\n")
	sec := win(map[string]interface{}{"EventID": float64(4688), "Channel": "Security", "NewProcessName": `C:\Windows\System32\whoami.exe`})
	other := win(map[string]interface{}{"EventID": float64(10), "Channel": "Microsoft-Windows-Sysmon/Operational", "Image": `C:\whoami.exe`})
	if !pc.Match(sec) || pc.Match(other) {
		t.Errorf("process_creation: 4688=%v, sysmon 10=%v", pc.Match(sec), pc.Match(other))
	}
}

func TestUnsupportedRulesAreRejected(t *testing.T) {
	for name, doc := range map[string]string{
		"aggregation":       ruleHead + "detection:\n  sel: {Image: x}\n  condition: sel | count() by Computer > 5\n",
		"timeframe":         ruleHead + "detection:\n  sel: {Image: x}\n  timeframe: 5m\n  condition: sel\n",
		"modifier":          ruleHead + "detection:\n  sel: {CommandLine|base64offset|contains: x}\n  condition: sel\n",
		"category":          "title: t\nlogsource: {product: windows, category: driver_load}\ndetection:\n  sel: {Image: x}\n  condition: sel\n",
		"product":           "title: t\nlogsource: {product: macos}\ndetection:\n  sel: {Image: x}\n  condition: sel\n",
		"unknown search":    ruleHead + "detection:\n  sel: {Image: x}\n  condition: sel and other\n",
		"multi-document":    ruleHead + "detection:\n  sel: {Image: x}\n  condition: sel\n---\ntitle: second\n",
		"missing detection": "title: t\nlogsource: {product: windows}\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestShippedRules(t *testing.T) {
	rules, skipped, err := Load(filepath.Join("..", "..", "rules", "sigma"))
	if err != nil || len(skipped) != 0 || len(rules) != 3 {
		t.Fatalf("rules=%d skipped=%v err=%v", len(rules), skipped, err)
	}
	for _, r := range rules {
		id, tactic := r.ATTACK()
		if id == "" || tactic == "" || len(r.SHA256) != 64 || r.Severity() == "" {
			t.Errorf("%s: attack=%s/%s sha=%q sev=%s", r.Title, id, tactic, r.SHA256, r.Severity())
		}
	}
}
