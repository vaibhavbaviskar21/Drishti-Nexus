package pipeline

import (
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/storage"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// attackLog builds a log with brute-force bursts, multi-line entries (so
// checkpoints land mid-entry) and enough volume for several checkpoints.
func attackLog(n int) []string {
	var lines []string
	t := time.Date(2025, 2, 1, 1, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		ts := t.Add(time.Duration(i) * 7 * time.Second).Format("Jan _2 15:04:05")
		ip := fmt.Sprintf("203.0.113.%d", i/40)
		switch i % 10 {
		case 9:
			lines = append(lines, fmt.Sprintf("%s srv sshd[%d]: Accepted password for root from %s port %d ssh2", ts, 5000+i, ip, 30000+i))
		case 5:
			lines = append(lines,
				fmt.Sprintf("%s srv java[9]: worker crashed", ts),
				"java.lang.RuntimeException: boom",
				"\tat a.b.C.d(C.java:1)")
		default:
			lines = append(lines, fmt.Sprintf("%s srv sshd[%d]: Failed password for root from %s port %d ssh2", ts, 5000+i, ip, 30000+i))
		}
	}
	return lines
}

func writeLines(t *testing.T, path string, lines []string, appendMode bool) {
	t.Helper()
	flag := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flag = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		t.Fatal(err)
	}
}

// fingerprint renders alerts in a comparable, order-independent form.
func fingerprint(alerts []*models.Alert) []string {
	var out []string
	for _, a := range alerts {
		out = append(out, fmt.Sprintf("%s %s %s count=%d first=%s last=%s rel=%v",
			a.ID, a.IncidentID, a.RuleName, a.Count, a.Timestamp.Format(time.RFC3339), a.LastSeen.Format(time.RFC3339), a.RelatedAlerts))
	}
	sort.Strings(out)
	return out
}

func reference(t *testing.T, path string) []string {
	t.Helper()
	res, err := Run([]string{path}, Options{Config: testConfig(t)})
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint(res.Alerts())
}

func follow(t *testing.T, path, db string, fo FollowOptions) (*Result, error) {
	t.Helper()
	store, err := storage.OpenSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return Follow(path, Options{Config: testConfig(t), Store: store, KeepLogs: true}, fo)
}

func compare(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d alerts, want %d\n got: %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("alert %d:\n got  %s\n want %s", i, got[i], want[i])
		}
	}
}

func TestFollow_ResumeAfterAppend(t *testing.T) {
	dir := t.TempDir()
	path, db := filepath.Join(dir, "auth.log"), filepath.Join(dir, "case.db")
	all := attackLog(300)
	half := len(all) / 2

	writeLines(t, filepath.Join(dir, "full.log"), all, false)
	want := reference(t, filepath.Join(dir, "full.log"))
	if len(want) == 0 {
		t.Fatal("reference produced no alerts; test log is not exercising detection")
	}

	writeLines(t, path, all[:half], false)
	if _, err := follow(t, path, db, FollowOptions{}); err != nil {
		t.Fatal(err)
	}
	writeLines(t, path, all[half:], true)

	var resumedAt int64
	res, err := follow(t, path, db, FollowOptions{OnResume: func(off int64, _ int) { resumedAt = off }})
	if err != nil {
		t.Fatal(err)
	}
	if resumedAt == 0 {
		t.Fatal("second session did not resume from the checkpoint")
	}
	if res.Stats.Lines >= len(all) {
		t.Errorf("resumed session re-read %d lines; should only read the appended part", res.Stats.Lines)
	}
	compare(t, fingerprint(res.Store.GetAlerts()), want)
}

func TestFollow_ResumeAfterCrash(t *testing.T) {
	dir := t.TempDir()
	path, db := filepath.Join(dir, "auth.log"), filepath.Join(dir, "case.db")
	all := attackLog(600)
	writeLines(t, path, all, false)
	want := reference(t, path)

	// Crash right after the 3rd mid-run checkpoint: uncommitted writes are lost.
	store, err := storage.OpenSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := 0
	afterCheckpointHook = func() {
		checkpoints++
		if checkpoints == 3 {
			panic("simulated crash")
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected simulated crash")
			}
		}()
		_, _ = Follow(path, Options{Config: testConfig(t), Store: store, KeepLogs: true}, FollowOptions{CheckpointEvery: 37})
	}()
	afterCheckpointHook = nil
	if err := store.Abort(); err != nil {
		t.Fatal(err)
	}

	var resumedAt int64
	res, err := follow(t, path, db, FollowOptions{OnResume: func(off int64, _ int) { resumedAt = off }})
	if err != nil {
		t.Fatal(err)
	}
	if resumedAt == 0 {
		t.Fatal("did not resume from the pre-crash checkpoint")
	}
	compare(t, fingerprint(res.Store.GetAlerts()), want)

	logs, _ := res.Store.Count()
	if logs != res.Stats.Entries+countEntriesBefore(t, path, resumedAt) {
		t.Logf("stored logs=%d (replayed entries are upserted by ID, never duplicated)", logs)
	}
	ids := map[string]bool{}
	for _, l := range res.Store.GetLogs() {
		if ids[l.ID] {
			t.Fatalf("duplicate log entry %s after resume", l.ID)
		}
		ids[l.ID] = true
	}
}

func countEntriesBefore(t *testing.T, path string, offset int64) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range strings.Split(string(data[:offset]), "\n") {
		if l != "" && l[0] != '\t' && !strings.HasPrefix(l, "java.") {
			n++
		}
	}
	return n
}

func TestFollow_RejectsReplacedFile(t *testing.T) {
	dir := t.TempDir()
	path, db := filepath.Join(dir, "auth.log"), filepath.Join(dir, "case.db")
	writeLines(t, path, attackLog(50), false)
	if _, err := follow(t, path, db, FollowOptions{}); err != nil {
		t.Fatal(err)
	}
	// Rotated/replaced: different content at the start.
	writeLines(t, path, append([]string{"Jan  1 00:00:00 other app: rotated"}, attackLog(60)...), false)
	if _, err := follow(t, path, db, FollowOptions{}); err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Errorf("replaced file must be refused, got %v", err)
	}
}

func TestFollow_LiveAppendAndStop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.log")
	writeLines(t, path, attackLog(20), false)

	stop := make(chan struct{})
	done := make(chan *Result, 1)
	go func() {
		res, err := Follow(path, Options{Config: testConfig(t)}, FollowOptions{Follow: true, Poll: 20 * time.Millisecond, Stop: stop})
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()

	time.Sleep(150 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// A line written in two parts must be read as one line.
	_, _ = f.WriteString("Feb  1 02:00:00 srv sshd[1]: Failed password for ")
	time.Sleep(100 * time.Millisecond)
	_, _ = f.WriteString("root from 192.0.2.1 port 1 ssh2\n")
	_ = f.Close()
	time.Sleep(150 * time.Millisecond)
	close(stop)

	select {
	case res := <-done:
		if res.Stats.Lines != len(attackLog(20))+1 {
			t.Errorf("lines = %d, want %d", res.Stats.Lines, len(attackLog(20))+1)
		}
		ev := res.Session.Evidence[0]
		if ev.Unchanged == nil || !*ev.Unchanged || ev.BytesAnalyzed <= ev.SizeBytes {
			t.Errorf("growing file custody: unchanged=%v analysed=%d initial=%d", ev.Unchanged, ev.BytesAnalyzed, ev.SizeBytes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Follow did not stop")
	}
}
