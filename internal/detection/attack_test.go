package detection

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Enterprise ATT&CK tactics (v15+). A tag outside this set is a typo.
var attackTactics = map[string]bool{
	"Reconnaissance": true, "Resource Development": true, "Initial Access": true,
	"Execution": true, "Persistence": true, "Privilege Escalation": true,
	"Defense Evasion": true, "Credential Access": true, "Discovery": true,
	"Lateral Movement": true, "Collection": true, "Command and Control": true,
	"Exfiltration": true, "Impact": true,
}

var techniqueID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func allRuleNames() []string {
	var names []string
	for _, s := range defaultSettings {
		names = append(names, s.Name)
	}
	return names
}

func TestATTACK_EveryRuleTaggedWithValidTechnique(t *testing.T) {
	for _, rule := range allRuleNames() {
		tech := ATTACKForRule(rule)
		if !techniqueID.MatchString(tech.ID) {
			t.Errorf("%s: technique ID %q is not T####[.###]", rule, tech.ID)
		}
		if tech.Name == "" {
			t.Errorf("%s: technique name missing", rule)
		}
		if !attackTactics[tech.Tactic] {
			t.Errorf("%s: tactic %q is not an Enterprise ATT&CK tactic", rule, tech.Tactic)
		}
	}
	if len(ruleATTACK) != len(allRuleNames()) {
		t.Errorf("ruleATTACK has %d entries, want %d (stale entry for a removed rule?)", len(ruleATTACK), len(allRuleNames()))
	}
}

func TestATTACK_AlertCarriesTechnique(t *testing.T) {
	e, _ := newTestEngine(nil)
	alerts := run(e,
		fail(t0, "10.0.0.9", 1), fail(t0.Add(time.Second), "10.0.0.9", 2), fail(t0.Add(2*time.Second), "10.0.0.9", 3),
		ok(t0.Add(3*time.Second), "10.0.0.9", 4),
	)
	if countRule(alerts, RuleBruteForce) != 1 {
		t.Fatalf("expected one brute-force alert, got %d", countRule(alerts, RuleBruteForce))
	}
	for _, a := range alerts {
		want := ATTACKForRule(a.RuleName)
		if a.MITRETechniqueID != want.ID || a.MITRETechniqueName != want.Name || a.MITRETactic != want.Tactic {
			t.Errorf("%s: alert tagged %s/%s/%s, want %+v", a.RuleName, a.MITRETechniqueID, a.MITRETechniqueName, a.MITRETactic, want)
		}
	}
}

// The published mapping must not drift from the code.
func TestATTACK_DocumentListsEveryRule(t *testing.T) {
	doc, err := os.ReadFile("../../docs/ATTACK_MAPPING.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range allRuleNames() {
		tech := ATTACKForRule(rule)
		row := "| " + rule + " | " + tech.ID + " | " + tech.Name + " | " + tech.Tactic + " |"
		if !strings.Contains(string(doc), row) {
			t.Errorf("docs/ATTACK_MAPPING.md missing row: %s", row)
		}
	}
}
