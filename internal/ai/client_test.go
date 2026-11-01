package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientRefusesNonLoopback(t *testing.T) {
	for _, ep := range []string{
		"http://127.0.0.1:8080/v1", "http://127.9.9.9/v1", "http://[::1]:11434/v1", "http://LOCALHOST:8080/v1",
	} {
		if _, err := NewClient(ep, "m", time.Second); err != nil {
			t.Errorf("%s: %v", ep, err)
		}
	}
	for _, ep := range []string{
		"http://10.0.0.5:8080/v1", "https://api.openai.com/v1", "http://localhost.evil.com/v1",
		"http://127.0.0.1@evil.com/v1", "http://127.0.0.1.nip.io/v1", "http://[::ffff:8.8.8.8]/v1",
		"http://0.0.0.0:8080/v1", "file:///etc/passwd", "127.0.0.1:8080", "",
	} {
		if _, err := NewClient(ep, "m", time.Second); err == nil {
			t.Errorf("%s accepted; only loopback endpoints may be used", ep)
		}
	}
}

func TestLoopbackOnlyDialGuard(t *testing.T) {
	if err := loopbackOnly("tcp", "127.0.0.1:80", nil); err != nil {
		t.Error(err)
	}
	if err := loopbackOnly("tcp", "93.184.216.34:80", nil); err == nil {
		t.Error("dial to a public address must be refused even if the URL passed validation")
	}
}

func TestCompleteRequestShape(t *testing.T) {
	var got chatRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"  narrative  "}}]}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL+"/v1/", "qwen2.5-7b-instruct", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	text, err := c.Complete(context.Background(), "sys", "facts")
	if err != nil {
		t.Fatal(err)
	}
	if text != "narrative" {
		t.Errorf("text %q", text)
	}
	if got.Model != "qwen2.5-7b-instruct" || got.Temperature != 0 || got.Stream ||
		len(got.Messages) != 2 || got.Messages[0] != (chatMessage{"system", "sys"}) || got.Messages[1] != (chatMessage{"user", "facts"}) {
		t.Errorf("request %+v", got)
	}
}

func TestCompleteErrors(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"http status": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "model not loaded", http.StatusServiceUnavailable)
		},
		"not json":   func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"no choices": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"choices":[]}`)) },
		"empty text": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":" "}}]}`))
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://198.51.100.1/v1/chat/completions", http.StatusTemporaryRedirect)
		},
		"timeout": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(time.Second):
			case <-r.Context().Done():
			}
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			c, err := NewClient(srv.URL, "m", 200*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Complete(context.Background(), "s", "u"); err == nil {
				t.Error("expected an error")
			} else if name == "http status" && !strings.Contains(err.Error(), "model not loaded") {
				t.Errorf("error should carry the server's message: %v", err)
			}
		})
	}
}
