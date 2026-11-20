package detection

// ATTACKTechnique is the MITRE ATT&CK (Enterprise) technique a rule is tagged with.
type ATTACKTechnique struct {
	ID     string // technique or sub-technique ID, e.g. "T1110.001"
	Name   string // ATT&CK display name, e.g. "Brute Force: Password Guessing"
	Tactic string // the tactic the rule's evidence supports, e.g. "Credential Access"
}

// ruleATTACK tags every rule with the single technique its logic most directly
// evidences. Conservative by design: a parent technique is used when the rule
// cannot tell sub-techniques apart. Rationale per rule: docs/ATTACK_MAPPING.md.
var ruleATTACK = map[string]ATTACKTechnique{
	RuleBruteForce:        {"T1110.001", "Brute Force: Password Guessing", "Credential Access"},
	RuleExcessiveFailures: {"T1110", "Brute Force", "Credential Access"},
	RulePrivilegeEsc:      {"T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"},
	RuleSuspiciousCommand: {"T1059", "Command and Scripting Interpreter", "Execution"},
	RuleInjection:         {"T1190", "Exploit Public-Facing Application", "Initial Access"},
	RuleTimeAnomaly:       {"T1078", "Valid Accounts", "Initial Access"},
	RuleLateralMovement:   {"T1021", "Remote Services", "Lateral Movement"},
}

// ATTACKForRule returns the technique a rule is tagged with (zero value if none).
func ATTACKForRule(rule string) ATTACKTechnique {
	return ruleATTACK[rule]
}

// techniqueNames names the techniques tagged by the shipped Sigma rules; Sigma tags
// carry only the ID.
// shortcut: other IDs show without a name; embed the ATT&CK STIX names if community rule packs need them.
var techniqueNames = map[string]string{
	"T1003.001": "OS Credential Dumping: LSASS Memory",
	"T1110.003": "Brute Force: Password Spraying",
	"T1569.002": "System Services: Service Execution",
}

// techniqueName returns the ATT&CK name of a technique ID, or "" if unknown.
func techniqueName(id string) string {
	if n, ok := techniqueNames[id]; ok {
		return n
	}
	for _, t := range ruleATTACK {
		if t.ID == id {
			return t.Name
		}
	}
	return ""
}
