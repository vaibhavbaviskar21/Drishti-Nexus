// Package ai turns an already-detected incident into an optional, clearly labeled
// plain-English narrative using a model that runs on this machine. The model only
// sees facts the deterministic engine produced; it never queries logs or calls tools,
// and every narrative is checked against those facts (see Check).
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// DefaultEndpoint is llama.cpp's llama-server default; Ollama serves the same API at
// http://127.0.0.1:11434/v1.
const DefaultEndpoint = "http://127.0.0.1:8080/v1"

// Client calls a local OpenAI-compatible chat completions endpoint.
type Client struct {
	Endpoint string
	Model    string
	http     *http.Client
}

// NewClient refuses any endpoint that is not on this machine: logs and findings
// must never leave an air-gapped host.
func NewClient(endpoint, model string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("endpoint %q: scheme must be http or https", endpoint)
	}
	if !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("endpoint %q is not a loopback address: the model must run on this machine (127.0.0.1, ::1 or localhost)", endpoint)
	}
	// Checked again at connect time so a "localhost" that resolves elsewhere, a proxy
	// or a redirect cannot carry the request off the machine.
	dialer := &net.Dialer{Timeout: timeout, Control: loopbackOnly}
	return &Client{
		Endpoint: strings.TrimRight(endpoint, "/"),
		Model:    model,
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{Proxy: nil, DialContext: dialer.DialContext},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects are not followed")
			},
		},
	}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loopbackOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing non-loopback connection to %s", address)
	}
	return nil
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"` // 0: same facts, same narrative
	Stream      bool          `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// Complete sends one system+user exchange and returns the model's reply.
func (c *Client) Complete(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:    c.Model,
		Messages: []chatMessage{{Role: "system", Content: system}, {Role: "user", Content: user}},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("model request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("model response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("model endpoint returned %s: %.300s", resp.Status, raw)
	}
	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("model response is not a chat completion: %w", err)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", errors.New("model returned an empty completion")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}
