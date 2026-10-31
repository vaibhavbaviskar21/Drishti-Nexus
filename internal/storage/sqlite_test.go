package storage

import (
	"drishti-nexus/internal/models"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLite_RoundTripAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "case.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < batchSize+10; i++ { // crosses a batch commit
		s.AddLog(&models.LogEntry{
			ID: fmt.Sprintf("f:%d", i+1), Timestamp: t0.Add(time.Duration(i) * time.Second),
			Source: []string{"a", "b"}[i%2], Severity: models.Severity(i % 8), Message: "m",
			Fields: map[string]interface{}{"n": i},
		})
	}
	alert := &models.Alert{ID: "ALERT-000001", RuleName: "r", Count: 1, Details: map[string]interface{}{}}
	s.AddAlert(alert)
	alert.Count = 7
	s.UpdateAlert(alert)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: everything committed must survive.
	s, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	logs, alerts := s.Count()
	if logs != batchSize+10 || alerts != 1 {
		t.Fatalf("after reopen: %d logs, %d alerts", logs, alerts)
	}
	if a := s.GetAlerts()[0]; a.Count != 7 {
		t.Errorf("UpdateAlert not persisted: count=%d", a.Count)
	}
	if got := len(s.GetLogsBySource("a")); got != (batchSize+10)/2 {
		t.Errorf("by source: %d", got)
	}
	recent := s.GetRecentLogs(3)
	if len(recent) != 3 || recent[2].ID != fmt.Sprintf("f:%d", batchSize+10) {
		t.Errorf("recent logs wrong order: %v", recent)
	}
	if got := len(s.GetLogsSince(t0.Add(time.Duration(batchSize) * time.Second))); got != 10 {
		t.Errorf("since: %d", got)
	}
	if got := len(s.GetLogsBySeverity(models.SeverityEmergency)); got == 0 {
		t.Error("by severity returned nothing")
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLite_Checkpoint(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if cp, err := s.LoadCheckpoint("/evidence/auth.log"); err != nil || cp != nil {
		t.Fatalf("missing checkpoint: %v %v", cp, err)
	}
	want := &Checkpoint{SourcePath: "/evidence/auth.log", Offset: 4096, Lines: 77, HeadSHA256: "abc", EngineState: []byte(`{"v":1}`), UpdatedAt: time.Now()}
	if err := s.SaveCheckpoint(want); err != nil {
		t.Fatal(err)
	}
	want.Offset = 8192
	if err := s.SaveCheckpoint(want); err != nil { // upsert
		t.Fatal(err)
	}
	got, err := s.LoadCheckpoint("/evidence/auth.log")
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if got.Offset != 8192 || got.Lines != 77 || string(got.EngineState) != `{"v":1}` || got.HeadSHA256 != "abc" {
		t.Errorf("checkpoint = %+v", got)
	}
}

func TestMemoryStorage_EvictsOldest(t *testing.T) {
	s := NewMemoryStorage(10)
	for i := 0; i < 25; i++ {
		s.AddLog(&models.LogEntry{ID: fmt.Sprintf("x:%d", i), Source: "h"})
	}
	logs, _ := s.Count()
	if logs > 10 {
		t.Errorf("capacity exceeded: %d", logs)
	}
	if got := s.GetRecentLogs(1)[0].ID; got != "x:24" {
		t.Errorf("newest entry lost: %s", got)
	}
}
