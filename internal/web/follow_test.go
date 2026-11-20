package web

import (
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/pipeline"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// waitFor polls cond every 100ms for up to 10s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func getJSON(t *testing.T, url string, v interface{}) {
	t.Helper()
	resp, err := http.Get(url) // #nosec G107 -- httptest server URL
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("%s: %v (%s)", url, err, body)
	}
}

// serve -follow: lines appended to the log after start reach the dashboard API,
// open dashboards are told to refresh, and stopping closes the audit session.
func TestFollow_LiveUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, []byte("2025-03-10T10:00:00+00:00 web01 sshd[1]: Accepted publickey for alice from 10.0.0.5 port 50100 ssh2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewServer(&models.Config{MaxLogEntries: 1000})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	stop := make(chan struct{})
	errc := make(chan error, 1)
	go func() { errc <- s.Follow(path, pipeline.Options{Config: &models.Config{}, Command: "serve"}, stop) }()

	waitFor(t, "audit session", func() bool {
		var sess map[string]interface{}
		getJSON(t, ts.URL+"/api/session", &sess)
		return sess != nil
	})
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/api/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	// Append a brute force: 3 failures then a success from one source.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	for i, outcome := range []string{"Failed", "Failed", "Failed", "Accepted"} {
		fmt.Fprintf(f, "2025-03-10T10:14:0%d+00:00 web01 sshd[%d]: %s password for deploy from 203.0.113.50 port 5112%d ssh2\n", i, 100+i, outcome, i)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	var msg map[string]string
	if err := ws.ReadJSON(&msg); err != nil || msg["type"] != "update" {
		t.Fatalf("no live update over the WebSocket: %v %v", msg, err)
	}
	waitFor(t, "brute-force alert from appended lines", func() bool {
		var alerts []models.Alert
		getJSON(t, ts.URL+"/api/alerts", &alerts)
		for _, a := range alerts {
			if a.RuleName == "Authentication Brute Force" {
				return true
			}
		}
		return false
	})

	close(stop)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	var sess struct {
		Status     string     `json:"status"`
		FinishedAt *time.Time `json:"finished_at"`
	}
	getJSON(t, ts.URL+"/api/session", &sess)
	if sess.Status != "ok" || sess.FinishedAt == nil {
		t.Errorf("audit session not closed after stop: %+v", sess)
	}
}

func TestStart_FollowNeedsOneFile(t *testing.T) {
	err := NewServer(&models.Config{}).Start(Options{Follow: true, LogFiles: []string{"a.log", "b.log"}})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("err = %v", err)
	}
}
