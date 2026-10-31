package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHashFileAndEvidence(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	writeFile(t, p, "hello\n")

	sum, n, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// sha256("hello\n")
	if sum != "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" || n != 6 {
		t.Errorf("sum=%s n=%d", sum, n)
	}

	ev, err := NewEvidenceFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Reverify(); err != nil || ev.Unchanged == nil || !*ev.Unchanged {
		t.Fatalf("unchanged file reported changed: %v", err)
	}

	writeFile(t, p, "tampered\n")
	if err := ev.Reverify(); err != nil || *ev.Unchanged {
		t.Error("modified evidence must be detected")
	}
}

func TestEvidenceLabelsUniqueWithinSession(t *testing.T) {
	dir := t.TempDir()
	for _, h := range []string{"web01", "db01"} {
		if err := os.Mkdir(filepath.Join(dir, h), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, h, "auth.log"), h+"\n")
	}
	writeFile(t, filepath.Join(dir, "syslog"), "x\n")

	s := NewSession("test", nil, "test")
	for _, p := range []string{filepath.Join(dir, "web01", "auth.log"), filepath.Join(dir, "syslog"), filepath.Join(dir, "db01", "auth.log")} {
		if _, err := s.AddEvidence(p); err != nil {
			t.Fatal(err)
		}
	}
	if s.Evidence[1].Label != "syslog" {
		t.Errorf("unique name should stay a bare file name, got %q", s.Evidence[1].Label)
	}
	a, b := s.Evidence[0].Label, s.Evidence[2].Label
	if a == b || !strings.HasSuffix(a, "web01/auth.log") || !strings.HasSuffix(b, "db01/auth.log") {
		t.Errorf("same-named files need distinct path labels, got %q and %q", a, b)
	}
}

func TestCheckOutputPathRefusesEvidence(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	writeFile(t, p, "x\n")
	ev, err := NewEvidenceFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckOutputPath(p, []*EvidenceFile{ev}); err == nil {
		t.Error("writing a report over the evidence file must be refused")
	}
	wd := mustWd(t)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	for _, rel := range []string{"auth.log", "./auth.log", "sub/../auth.log"} {
		if err := CheckOutputPath(rel, []*EvidenceFile{ev}); err == nil {
			t.Errorf("relative path %q to evidence must be refused too", rel)
		}
	}
	if err := CheckOutputPath(filepath.Join(dir, "report.json"), []*EvidenceFile{ev}); err != nil {
		t.Errorf("a new report path should be allowed: %v", err)
	}
}

func mustWd(t *testing.T) string {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func newTestSession(t *testing.T) *Session {
	s := NewSession("scan", []string{"x.log"}, "test")
	if s.SessionID == "" || s.OSUser == "" || s.StartedAt.IsZero() {
		t.Fatalf("session not initialised: %+v", s)
	}
	return s
}

func TestAuditLogChainAppendAndVerify(t *testing.T) {
	log := filepath.Join(t.TempDir(), "audit.log")
	s1, s2 := newTestSession(t), newTestSession(t)
	for _, step := range []struct {
		s     *Session
		event string
	}{{s1, "session_start"}, {s1, "session_end"}, {s2, "session_start"}} {
		if err := Append(log, step.event, step.s); err != nil {
			t.Fatal(err)
		}
	}
	if s2.PrevHash != s1.RecordHash {
		t.Error("records must chain: prev_hash of a record is the previous record_hash")
	}
	res, err := Verify(log)
	if err != nil {
		t.Fatalf("intact log failed verification: %v", err)
	}
	if res.Records != 3 || len(res.Sessions) != 2 {
		t.Errorf("records=%d sessions=%d", res.Records, len(res.Sessions))
	}
}

func readLines(t *testing.T, path string) []string {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func TestAuditLogTamperDetection(t *testing.T) {
	build := func(t *testing.T) (string, []string) {
		log := filepath.Join(t.TempDir(), "audit.log")
		for i := 0; i < 3; i++ {
			if err := Append(log, "session_start", newTestSession(t)); err != nil {
				t.Fatal(err)
			}
		}
		return log, readLines(t, log)
	}
	rewrite := func(t *testing.T, path string, lines []string) {
		writeFile(t, path, strings.Join(lines, "\n")+"\n")
	}

	t.Run("edited record", func(t *testing.T) {
		log, lines := build(t)
		lines[1] = strings.Replace(lines[1], `"command":"scan"`, `"command":"tail"`, 1)
		rewrite(t, log, lines)
		if _, err := Verify(log); err == nil || !strings.Contains(err.Error(), "line 2") {
			t.Errorf("edit not detected at line 2: %v", err)
		}
	})
	t.Run("deleted record", func(t *testing.T) {
		log, lines := build(t)
		rewrite(t, log, append(lines[:1], lines[2:]...))
		if _, err := Verify(log); err == nil || !strings.Contains(err.Error(), "chain broken") {
			t.Errorf("deletion not detected: %v", err)
		}
	})
	t.Run("reordered records", func(t *testing.T) {
		log, lines := build(t)
		lines[0], lines[1] = lines[1], lines[0]
		rewrite(t, log, lines)
		if _, err := Verify(log); err == nil {
			t.Error("reordering not detected")
		}
	})
	t.Run("append refuses after corrupted tail", func(t *testing.T) {
		log, lines := build(t)
		rewrite(t, log, append(lines, "not json"))
		if err := Append(log, "session_start", newTestSession(t)); err == nil {
			t.Error("appending to a corrupted log must fail instead of silently forking the chain")
		}
	})
}

func TestOpenEvidenceIsReadOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.log")
	writeFile(t, p, "data\n")
	f, err := OpenEvidence(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("x")); err == nil {
		t.Error("evidence handle must not be writable")
	}
}
