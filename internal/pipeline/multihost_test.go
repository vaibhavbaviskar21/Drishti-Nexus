package pipeline

import (
	"drishti-nexus/internal/models"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The multihost fixture: deploy is brute-forced on web01, then used to log in on
// db01 7 minutes later. db01 sorts first, so this only correlates if files are
// merged by event time rather than read one after another.
func TestIntegration_MultiHostLateralMovement(t *testing.T) {
	res := runFiles(t, filepath.Join(repoRoot, "testdata", "fixtures", "multihost"))
	st := res.Stats
	want := map[string]int{
		"Excessive Authentication Failures": 1,
		"Authentication Brute Force":        1,
		"Lateral Movement Candidate":        1,
	}
	for rule, n := range want {
		if st.AlertsByRule[rule] != n {
			t.Errorf("%s: %d alerts, want %d (all: %v)", rule, st.AlertsByRule[rule], n, st.AlertsByRule)
		}
	}
	if len(st.AlertsByRule) != len(want) || st.Incidents != 1 {
		t.Errorf("want 3 alerts in 1 incident, got %v in %d incidents", st.AlertsByRule, st.Incidents)
	}
	if st.Entries != 17 || st.ParseQuality[models.QualityClean] != 17 {
		t.Errorf("entries=%d quality=%v", st.Entries, st.ParseQuality)
	}

	// Same-named files get distinct path labels, so evidence IDs stay unambiguous.
	for _, a := range res.Alerts() {
		for _, id := range a.RelatedLogs {
			if !strings.Contains(id, "web01/auth.log:") && !strings.Contains(id, "db01/auth.log:") {
				t.Errorf("%s cites ambiguous evidence %q", a.RuleName, id)
			}
		}
	}
}

func TestExpandPaths(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"b/auth.log", "a/syslog", ".cache/x.tar.gz", "a/.hidden"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	single := filepath.Join(dir, "b", "auth.log")
	got, err := ExpandPaths([]string{dir, single})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "a", "syslog"), single, single}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", got, want)
	}

	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ExpandPaths([]string{filepath.Join(dir, "empty")}); err == nil {
		t.Error("an empty directory should be an error, not a silent no-op")
	}
}

// Vendor formats reach the same rules as native logs: a brute force reported
// only by a VPN appliance in CEF raises the same alert as one from sshd.
func TestIntegration_CEFLEEFFixture(t *testing.T) {
	res := runFiles(t, filepath.Join(repoRoot, "testdata", "fixtures", "cef_leef.log"))
	st := res.Stats
	if st.ByParser["cef"] != 4 || st.ByParser["leef"] != 1 || st.ParseQuality[models.QualityClean] != 5 {
		t.Errorf("parsers=%v quality=%v", st.ByParser, st.ParseQuality)
	}
	if st.AlertsByRule["Authentication Brute Force"] != 1 || st.Alerts != 1 {
		t.Errorf("alerts = %v, want exactly one brute force", st.AlertsByRule)
	}
}
