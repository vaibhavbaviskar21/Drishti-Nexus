package ai

import (
	"context"
	"drishti-nexus/internal/config"
	"drishti-nexus/internal/pipeline"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var repoRoot = filepath.Join("..", "..")

// incidentFacts runs the real pipeline on a fixture and returns its incidents.
func incidentFacts(t *testing.T, fixture string) map[string]Facts {
	t.Helper()
	cfg, _, err := config.Load(filepath.Join(repoRoot, "configs", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := pipeline.Run([]string{filepath.Join(repoRoot, "testdata", "fixtures", fixture)},
		pipeline.Options{Config: cfg, KeepLogs: true, Command: "test", ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Finish(&pipeline.Options{}, "ok"); err != nil {
		t.Fatal(err)
	}
	out := map[string]Facts{}
	for _, f := range Incidents(res.Alerts(), res.Store.GetLogs()) {
		out[f.IncidentID] = f
	}
	return out
}

// Faithful narratives, written the way an instruction-tuned model paraphrases the
// facts. Each must verify: a checker that flags faithful text is useless.
var faithful = map[string]map[string]string{
	"multihost": {
		"INC-00001": `Between 10:14 and 10:21 UTC on 2025-03-10, incident INC-00001 shows the account "deploy" being ` +
			`brute-forced on web01 from 203.0.113.50 and then used on db01. ALERT-000001 (T1110, Credential Access) ` +
			`recorded 6 failed password attempts from 203.0.113.50 against web01 starting at 10:14:01, above the ` +
			`threshold of 5 within 10 minutes. ALERT-000002 (T1110.001) records that the 6 failures were followed by a ` +
			`successful password login for user deploy at 2025-03-10T10:14:14Z. ALERT-000003 (T1021, Lateral Movement, ` +
			`critical) shows deploy logging in to db01 from 10.0.0.11 7 minutes 26 seconds later, at 10:21:40. ` +
			`The incident contains 3 alerts.`,
	},
	"sample_auth.log": {
		"INC-00001": `ALERT-000001 (T1110.001) reports 3 failed password attempts for admin from 192.168.1.100 on server1, ` +
			`followed by a successful login at 10:15:30 UTC on 2026-01-16.`,
		"INC-00002": `Incident INC-00002 groups two alerts on server1. ALERT-000002 (T1190) flagged an SQL injection ` +
			`pattern in a request from 192.168.1.50 at 10:18:12, and ALERT-000005 (T1059) flagged user admin running ` +
			`an encoded powershell command at 10:29:30.`,
		"INC-00003": `ALERT-000003 (T1110) recorded 5 failed logins from 10.0.0.50 on server1 between 10:19:45 and ` +
			`10:21:25 UTC, for user2 through user6.`,
		"INC-00004": `ALERT-000004 (T1078) flagged 2 events outside normal hours on server1, the first at 02:30 UTC, ` +
			`including a login by admin from 203.0.113.50.`,
	},
}

// A planted hallucination of each type, derived from the incident's own facts so it
// is wrong for that incident specifically.
var plants = []struct {
	kind  string
	plant func(f Facts, g *grounding) string
}{
	{"wrong IP address", func(f Facts, g *grounding) string {
		return "The attacker also connected from " + unusedIP(g) + "."
	}},
	{"invented ATT&CK technique", func(f Facts, g *grounding) string {
		for _, id := range []string{"T1003", "T1486", "T1566.001", "T1078"} {
			if !g.claims[claim{kindTechnique, id}] {
				return "This is consistent with " + id + "."
			}
		}
		panic("no unused technique")
	}},
	{"wrong count", func(f Facts, g *grounding) string {
		n := f.Alerts[0].Count + 1
		for g.numbers[strconv.Itoa(n)] {
			n++
		}
		return fmt.Sprintf("%s fired %d times.", f.Alerts[0].ID, n)
	}},
	{"invented host", func(f Facts, g *grounding) string { return "The same account was then used on host fileserver." }},
	{"invented host (identifier)", func(f Facts, g *grounding) string { return "Activity then moved to app07." }},
	{"invented user", func(f Facts, g *grounding) string { return `The account "svc_backup" was also targeted.` }},
	{"time outside window", func(f Facts, g *grounding) string {
		return "Further activity was seen at " + f.LastSeen.Add(3*time.Hour).Format("15:04") + " UTC."
	}},
	{"timestamp outside window", func(f Facts, g *grounding) string {
		return "It began at " + f.FirstSeen.Add(-26*time.Hour).Format(time.RFC3339) + "."
	}},
	{"nonexistent alert ID", func(f Facts, g *grounding) string { return "See also ALERT-000099." }},
	{"wrong incident ID", func(f Facts, g *grounding) string { return "This continues INC-00042." }},
}

func unusedIP(g *grounding) string {
	for i := 2; ; i++ {
		ip := "198.51.100." + strconv.Itoa(i)
		if !g.claims[claim{kindIP, ip}] {
			return ip
		}
	}
}

// TestGroundingEvaluation is the Phase 5.1 hallucination evaluation recorded in
// docs/AI_SUMMARY.md: faithful narratives must verify and every planted
// hallucination must be caught. Run with -v for the per-type table.
func TestGroundingEvaluation(t *testing.T) {
	caught, total := map[string]int{}, map[string]int{}
	falsePositives, faithfulTotal := 0, 0
	for _, fixture := range []string{"multihost", "sample_auth.log"} {
		incidents := incidentFacts(t, fixture)
		if len(incidents) != len(faithful[fixture]) {
			t.Fatalf("%s: %d incidents, faithful summaries cover %d", fixture, len(incidents), len(faithful[fixture]))
		}
		for id, f := range incidents {
			text, ok := faithful[fixture][id]
			if !ok {
				t.Fatalf("%s %s: no faithful summary", fixture, id)
			}
			faithfulTotal++
			if bad := Check(text, f); len(bad) > 0 {
				falsePositives++
				t.Errorf("%s %s: faithful summary flagged: %v", fixture, id, bad)
			}
			g := newGrounding(f)
			for _, p := range plants {
				sentence := p.plant(f, g)
				total[p.kind]++
				if bad := Check(text+" "+sentence, f); len(bad) > 0 {
					caught[p.kind]++
				} else {
					t.Errorf("%s %s: %s not caught: %q", fixture, id, p.kind, sentence)
				}
			}
		}
	}

	kinds := make([]string, 0, len(total))
	for k := range total {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	t.Logf("faithful summaries verified: %d/%d", faithfulTotal-falsePositives, faithfulTotal)
	for _, k := range kinds {
		t.Logf("%-28s caught %d/%d", k, caught[k], total[k])
	}
}

// What the checker does NOT catch, pinned so the documented limits stay true.
func TestGroundingKnownBlindSpots(t *testing.T) {
	f := incidentFacts(t, "multihost")["INC-00001"]
	for _, s := range []string{
		"The attacker then exfiltrated the customer database.", // speculation with no concrete entity
		"The attacker was likely a disgruntled insider.",       // attribution
		"Eight failed attempts were recorded.",                 // number written as a word
	} {
		if bad := Check(s, f); len(bad) != 0 {
			t.Errorf("%q: now flagged %v; update the limits in docs/AI_SUMMARY.md", s, bad)
		}
	}
}

func TestCheckEdgeCases(t *testing.T) {
	f := Facts{
		IncidentID: "INC-00007",
		FirstSeen:  time.Date(2025, 3, 10, 23, 50, 0, 0, time.UTC),
		LastSeen:   time.Date(2025, 3, 11, 0, 10, 0, 0, time.UTC),
		Alerts:     []AlertFact{{ID: "ALERT-000007", Count: 4, Description: "from 10.0.0.1 and 2001:db8::1 on mail.example.com"}},
	}
	ok := []string{
		"ALERT-000007 saw 2001:DB8:0:0::1 and 10.0.0.1 on mail.example.com at 00:05 and 23:55 on 2025-03-11.",
		"4 events, 1 alert.",
		"Started 2025-03-10 23:50 UTC.",
	}
	for _, s := range ok {
		if bad := Check(s, f); len(bad) != 0 {
			t.Errorf("%q flagged %v", s, bad)
		}
	}
	bad := map[string]string{
		"From 10.0.0.11.":                "ip 10.0.0.11", // prefix of a real IP is not a match
		"From 2001:db8::2.":              "ip 2001:db8::2",
		"At 12:00.":                      "time 12:00", // outside the midnight-spanning window
		"At 2025-03-11T00:10:01Z.":       "timestamp 2025-03-11T00:10:01Z",
		"On 2025-03-12.":                 "date 2025-03-12",
		"On mail2.example.com.":          "name mail2.example.com",
		"ALERT-7 fired.":                 "alert ALERT-7",
		"From 999.1.1.1.":                "ip 999.1.1.1",
		"   ":                            "empty summary",
		"A login by user mallory.":       "name mallory",
		"In INC-00007 user root logged.": "name root",
	}
	for s, want := range bad {
		if got := Check(s, f); !contains(got, want) {
			t.Errorf("%q: got %v, want %q", s, got, want)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// End to end against a stand-in model: the prompt carries the facts and the
// planted hallucination in the reply is flagged.
func TestSummarizeLabelsUnverified(t *testing.T) {
	f := incidentFacts(t, "multihost")["INC-00001"]
	var prompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		prompt = req.Messages[1].Content
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ALERT-000002: deploy was brute-forced from 203.0.113.99."}}]}`))
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "m", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Summarize(context.Background(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	if s.Verified || !contains(s.Unsupported, "ip 203.0.113.99") || s.Label != Label || len(s.PromptSHA256) != 64 {
		t.Errorf("summary %+v", s)
	}
	for _, want := range []string{"ALERT-000003", "T1021", "203.0.113.50", "Accepted password for deploy from 10.0.0.11"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
}
