package detection

import (
	"drishti-nexus/internal/sigma"
	"path/filepath"
	"testing"
)

var frameworks = map[string]bool{pci: true, iso: true, hipaa: true}

func TestCompliance_EveryRuleTechniqueMapped(t *testing.T) {
	ids := map[string]string{}
	for _, rule := range allRuleNames() {
		ids[ATTACKForRule(rule).ID] = rule
	}
	rules, _, err := sigma.Load(filepath.Join("..", "..", "rules", "sigma"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if id, _ := r.ATTACK(); id != "" {
			ids[id] = "sigma " + r.Title
		}
	}
	for id, rule := range ids {
		got := ControlsForTechnique(id)
		if len(got) == 0 {
			t.Errorf("%s (%s): no compliance controls", rule, id)
		}
		seen := map[string]bool{}
		for _, c := range got {
			if !frameworks[c.Framework] || c.ID == "" || c.Title == "" {
				t.Errorf("%s: malformed control %+v", id, c)
			}
			if seen[c.Framework] {
				continue
			}
			seen[c.Framework] = true
		}
		if len(seen) != len(frameworks) {
			t.Errorf("%s (%s): covers %d of %d frameworks", rule, id, len(seen), len(frameworks))
		}
	}
}

func TestCompliance_SubTechniqueInheritsParent(t *testing.T) {
	if got, want := ControlsForTechnique("T1110.001"), ControlsForTechnique("T1110"); len(got) == 0 || &got[0] != &want[0] {
		t.Errorf("T1110.001 should use the T1110 controls")
	}
	if ControlsForTechnique("T9999") != nil || ControlsForTechnique("") != nil {
		t.Error("unmapped technique must return nil")
	}
}
