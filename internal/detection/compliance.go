package detection

import "strings"

// Control is a compliance control an alert can serve as supporting evidence for.
// It is a reference for auditors, never a claim of compliance or of a violation.
type Control struct {
	Framework string // "PCI DSS 4.0.1", "ISO/IEC 27001:2022", "HIPAA"
	ID        string // e.g. "8.3.4", "A.8.5", "164.308(a)(5)(ii)(C)"
	Title     string
}

const (
	pci   = "PCI DSS 4.0.1"
	iso   = "ISO/IEC 27001:2022"
	hipaa = "HIPAA"
)

// MonitoringControls are met by running detection at all, whatever fires.
var MonitoringControls = []Control{
	{pci, "10.4.1.1", "Automated mechanisms perform audit log reviews"},
	{iso, "A.8.16", "Monitoring activities"},
	{hipaa, "164.308(a)(1)(ii)(D)", "Information system activity review"},
}

// techniqueControls maps a parent ATT&CK technique to the controls its alerts
// evidence. Keyed by parent so Sigma sub-techniques inherit it. Rationale per
// row: docs/COMPLIANCE_MAPPING.md.
var techniqueControls = map[string][]Control{
	"T1110": { // Brute Force
		{pci, "8.3.4", "Invalid authentication attempts are limited"},
		{pci, "10.2.1.4", "Invalid logical access attempts are logged"},
		{iso, "A.8.5", "Secure authentication"},
		{iso, "A.5.17", "Authentication information"},
		{hipaa, "164.308(a)(5)(ii)(C)", "Log-in monitoring"},
		{hipaa, "164.312(d)", "Person or entity authentication"},
	},
	"T1078": { // Valid Accounts
		{pci, "8.2.6", "Inactive user accounts are removed or disabled"},
		{pci, "10.2.1.1", "Individual user access is logged"},
		{iso, "A.5.18", "Access rights"},
		{iso, "A.8.5", "Secure authentication"},
		{hipaa, "164.308(a)(5)(ii)(C)", "Log-in monitoring"},
	},
	"T1548": { // Abuse Elevation Control Mechanism
		{pci, "7.2.2", "Access is assigned on least privilege"},
		{pci, "10.2.1.2", "Actions by administrative accounts are logged"},
		{iso, "A.8.2", "Privileged access rights"},
		{hipaa, "164.312(a)(1)", "Access control"},
	},
	"T1059": { // Command and Scripting Interpreter
		{pci, "10.2.1.2", "Actions by administrative accounts are logged"},
		{iso, "A.8.18", "Use of privileged utility programs"},
		{iso, "A.8.7", "Protection against malware"},
		{hipaa, "164.308(a)(5)(ii)(B)", "Protection from malicious software"},
	},
	"T1190": { // Exploit Public-Facing Application
		{pci, "6.2.4", "Software engineering techniques prevent common attacks"},
		{pci, "6.4.2", "Automated solution detects and prevents web attacks"},
		{iso, "A.8.8", "Management of technical vulnerabilities"},
		{iso, "A.8.26", "Application security requirements"},
		{hipaa, "164.308(a)(1)(ii)(B)", "Risk management"},
	},
	"T1021": { // Remote Services
		{pci, "1.3.1", "Inbound traffic to the CDE is restricted"},
		{pci, "8.4.2", "MFA for all access into the CDE"},
		{iso, "A.8.20", "Networks security"},
		{iso, "A.8.22", "Segregation of networks"},
		{hipaa, "164.312(a)(1)", "Access control"},
	},
	"T1003": { // OS Credential Dumping
		{pci, "8.3.2", "Authentication factors are unreadable in storage"},
		{pci, "5.2.1", "Anti-malware solution is deployed"},
		{iso, "A.5.17", "Authentication information"},
		{iso, "A.8.7", "Protection against malware"},
		{hipaa, "164.312(d)", "Person or entity authentication"},
	},
	"T1569": { // System Services
		{pci, "2.2.4", "Only necessary services are enabled"},
		{pci, "10.2.1.2", "Actions by administrative accounts are logged"},
		{iso, "A.8.2", "Privileged access rights"},
		{iso, "A.8.18", "Use of privileged utility programs"},
		{hipaa, "164.312(a)(1)", "Access control"},
	},
}

// ControlsForTechnique returns the controls an alert tagged with this ATT&CK
// technique (or sub-technique) supports; nil when the technique is unmapped.
func ControlsForTechnique(id string) []Control {
	parent, _, _ := strings.Cut(id, ".")
	return techniqueControls[parent]
}
