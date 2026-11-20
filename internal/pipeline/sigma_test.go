package pipeline

import (
	"drishti-nexus/internal/sigma"
	"path/filepath"
	"strings"
	"testing"
)

const (
	sigmaLSASS   = "Sigma: LSASS Memory Read With Credential-Dumping Access Rights"
	sigmaService = "Sigma: Service Installed That Runs Encoded PowerShell"
	sigmaFormat  = "Sigma: Format String Exploitation Attempt in a Service Log"
)

func shippedSigma(t *testing.T) []*sigma.Rule {
	t.Helper()
	rules, _, err := sigma.Load(filepath.Join(repoRoot, "rules", "sigma"))
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func runWithSigma(t *testing.T, files ...string) *Result {
	t.Helper()
	res, err := Run(files, Options{Config: testConfig(t), Sigma: shippedSigma(t)})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Real Mordor events: Empire's psexec service install, Mimikatz reading LSASS, and a
// benign svchost LSASS access that must not match.
func TestIntegration_SigmaFixture(t *testing.T) {
	res := runWithSigma(t, filepath.Join(repoRoot, "testdata", "fixtures", "mordor_sigma_events.json"))
	st := res.Stats
	if st.AlertsByRule[sigmaService] != 1 || st.AlertsByRule[sigmaLSASS] != 1 {
		t.Errorf("alerts = %v", st.AlertsByRule)
	}
	for _, a := range res.Alerts() {
		switch a.RuleName {
		case sigmaLSASS:
			if a.MITRETechniqueID != "T1003.001" || a.MITRETactic != "Credential Access" || a.Severity != "high" ||
				!strings.HasSuffix(a.RelatedLogs[0], ":2") { // line 2: the powershell access, not svchost on line 3
				t.Errorf("lsass alert: %+v", a)
			}
		case sigmaService:
			if a.MITRETechniqueID != "T1569.002" || a.Details["sigma_id"] == nil {
				t.Errorf("service alert: %+v", a)
			}
		}
	}
	defs := res.Session.Config.Definitions
	if len(defs) != 3 || len(defs[0].SHA256) != 64 {
		t.Errorf("rule files not recorded in the audit session: %+v", defs)
	}
}

// Shipped rules on the full datasets: the attacks they target are found, and the
// benign set and the SSH brute-force corpus stay silent.
func TestIntegration_SigmaDatasets(t *testing.T) {
	for _, tt := range []struct {
		path string
		want map[string]span
	}{
		{"testdata/datasets/mordor/empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608.json", map[string]span{sigmaService: {1, 1}, sigmaLSASS: {0, 0}}},
		{"testdata/datasets/mordor/empire_mimikatz_logonpasswords_2020-08-07103224.json", map[string]span{sigmaLSASS: {1, 1}, sigmaService: {0, 0}}},
		{"testdata/datasets/loghub-linux/Linux.log", map[string]span{sigmaFormat: {7, 7}}}, // the rpc.statd exploit (a Phase 1 gap): 7 separate attempts, 20 lines, no false positives
		{"testdata/datasets/loghub-ssh/SSH.log", map[string]span{sigmaFormat: {0, 0}}},
		{"testdata/benign/auth_benign.log", map[string]span{sigmaFormat: {0, 0}, sigmaLSASS: {0, 0}, sigmaService: {0, 0}}},
	} {
		t.Run(filepath.Base(tt.path), func(t *testing.T) {
			res := runWithSigma(t, datasetOrSkip(t, tt.path))
			for rule, want := range tt.want {
				checkRange(t, rule, res.Stats.AlertsByRule[rule], want)
			}
		})
	}
}
