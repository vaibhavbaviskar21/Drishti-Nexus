// Package audit implements chain of custody: evidence hashing, read-only access,
// and a tamper-evident, append-only audit log of every analysis session.
// See docs/CHAIN_OF_CUSTODY.md for the design.
package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"
)

// DefaultLogPath is where the audit log is written unless overridden.
const DefaultLogPath = "drishti_audit.log"

// genesisHash is the prev_hash of the first record in a log.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// RuleConfig is the effective configuration of one detection rule for a session.
type RuleConfig struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Severity  string `json:"severity"`
	Threshold int    `json:"threshold,omitempty"`
	Window    string `json:"time_window,omitempty"`
}

// AnalysisConfig records every setting that influences results.
type AnalysisConfig struct {
	ConfigPath      string       `json:"config_path,omitempty"` // empty = built-in defaults
	ConfigSHA256    string       `json:"config_sha256,omitempty"`
	Rules           []RuleConfig `json:"rules"`
	NormalHours     string       `json:"normal_hours"`
	IncidentGap     string       `json:"incident_gap"`
	AssumedTimezone string       `json:"assumed_timezone"` // zone applied to timestamps without an offset
	Storage         string       `json:"storage"`          // "memory" or "sqlite:<path>"
	Warnings        []string     `json:"warnings,omitempty"`
}

// OutputFile is a report written by the session.
type OutputFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}

// Results summarises what a session produced.
type Results struct {
	Lines        int            `json:"lines"`
	Entries      int            `json:"entries"`
	ParseQuality map[string]int `json:"parse_quality"`
	Alerts       int            `json:"alerts"`
	Incidents    int            `json:"incidents"`
	AlertsByRule map[string]int `json:"alerts_by_rule"`
}

// Session is one invocation of the tool against a set of evidence files.
type Session struct {
	SessionID   string          `json:"session_id"`
	Event       string          `json:"event"` // "session_start" or "session_end"
	Command     string          `json:"command"`
	Args        []string        `json:"args"`
	StartedAt   time.Time       `json:"started_at"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	OSUser      string          `json:"os_user"`
	Hostname    string          `json:"hostname"`
	ToolVersion string          `json:"tool_version"`
	GoVersion   string          `json:"go_version"`
	Platform    string          `json:"platform"`
	Config      AnalysisConfig  `json:"config"`
	Evidence    []*EvidenceFile `json:"evidence"`
	Outputs     []OutputFile    `json:"outputs,omitempty"`
	Results     *Results        `json:"results,omitempty"`
	Status      string          `json:"status,omitempty"` // "ok", "error: ...", "interrupted"

	// Position in the audit log, filled when the session is appended.
	PrevHash   string `json:"-"`
	RecordHash string `json:"-"`
}

// NewSession starts a session record for command.
func NewSession(command string, args []string, toolVersion string) *Session {
	userName := "unknown"
	if u, err := user.Current(); err == nil {
		userName = u.Username
	}
	host, _ := os.Hostname()
	return &Session{
		SessionID:   newSessionID(),
		Command:     command,
		Args:        append([]string(nil), args...),
		StartedAt:   time.Now().UTC(),
		OSUser:      userName,
		Hostname:    host,
		ToolVersion: toolVersion,
		GoVersion:   runtime.Version(),
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func newSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("s%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// AddEvidence hashes path and attaches it to the session.
func (s *Session) AddEvidence(path string) (*EvidenceFile, error) {
	ev, err := NewEvidenceFile(path)
	if err != nil {
		return nil, err
	}
	// Label by file name; two files with the same name (host1/auth.log,
	// host2/auth.log) are both labelled by path so entry IDs stay unambiguous.
	ev.Label = filepath.Base(path)
	for _, other := range s.Evidence {
		if filepath.Base(other.Path) == ev.Label {
			other.Label = filepath.ToSlash(filepath.Clean(other.Path))
			ev.Label = filepath.ToSlash(filepath.Clean(path))
		}
	}
	s.Evidence = append(s.Evidence, ev)
	return ev, nil
}

// HashConfig records the config file used (path may be empty for defaults).
func (s *Session) HashConfig(path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	s.Config.ConfigPath = path
	s.Config.ConfigSHA256 = hex.EncodeToString(sum[:])
	return nil
}

// AddOutput records a report written by the session, with its hash.
func (s *Session) AddOutput(path string) {
	out := OutputFile{Path: path}
	if sum, _, err := HashFile(path); err == nil {
		out.SHA256 = sum
	}
	s.Outputs = append(s.Outputs, out)
}

// Finish re-verifies evidence hashes and stamps the end time.
func (s *Session) Finish(status string) {
	now := time.Now().UTC()
	s.FinishedAt = &now
	s.Status = status
	for _, ev := range s.Evidence {
		if ev.BytesAnalyzed > 0 {
			continue // growing file (tail): verified by prefix hash instead
		}
		if err := ev.Reverify(); err != nil {
			s.Config.Warnings = append(s.Config.Warnings, fmt.Sprintf("re-hash %s: %v", ev.Path, err))
		}
	}
}

// Tampered reports evidence files whose hash changed during the session.
func (s *Session) Tampered() []string {
	var out []string
	for _, ev := range s.Evidence {
		if ev.Unchanged != nil && !*ev.Unchanged {
			out = append(out, ev.Path)
		}
	}
	return out
}

// envelope is one line of the audit log. RecordHash = SHA-256(PrevHash || Record),
// computed over the exact Record bytes, so any edit, deletion or reordering of
// earlier lines breaks the chain.
type envelope struct {
	PrevHash   string          `json:"prev_hash"`
	Record     json.RawMessage `json:"record"`
	RecordHash string          `json:"record_hash"`
}

func chainHash(prev string, record []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(record)
	return hex.EncodeToString(h.Sum(nil))
}

// Append writes the session as the next record of the append-only log at path.
// event is "session_start" or "session_end".
func Append(path, event string, s *Session) error {
	s.Event = event
	record, err := json.Marshal(s)
	if err != nil {
		return err
	}

	prev, err := lastHash(path)
	if err != nil {
		return err
	}

	// O_APPEND: the OS positions every write at end-of-file; existing records are
	// never rewritten.
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	env := envelope{PrevHash: prev, Record: record, RecordHash: chainHash(prev, record)}
	line, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}
	s.PrevHash, s.RecordHash = env.PrevHash, env.RecordHash
	return nil
}

// lastHash returns the record_hash of the final line, or the genesis hash.
func lastHash(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return genesisHash, nil
	}
	if err != nil {
		return "", fmt.Errorf("read audit log: %w", err)
	}
	defer f.Close()

	// Read only the tail of the file; records are a few KB at most.
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	const tailSize = 1 << 20
	start := info.Size() - tailSize
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return "", err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	data = bytes.TrimRight(data, "\n")
	if len(data) == 0 {
		return genesisHash, nil
	}
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		data = data[i+1:]
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil || env.RecordHash == "" {
		return "", fmt.Errorf("audit log %s: last record is not a valid chained record; refusing to append (run 'drishti audit verify')", path)
	}
	return env.RecordHash, nil
}

// VerifyResult describes an audit log check.
type VerifyResult struct {
	Records  int
	Sessions map[string]bool
}

// Verify checks every record's hash chain. It returns the number of valid
// records and an error identifying the first broken line.
func Verify(path string) (*VerifyResult, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := &VerifyResult{Sessions: map[string]bool{}}
	prev := genesisHash
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var env envelope
		if err := json.Unmarshal(line, &env); err != nil {
			return res, fmt.Errorf("line %d: not a valid audit record: %w", lineNo, err)
		}
		if env.PrevHash != prev {
			return res, fmt.Errorf("line %d: chain broken (prev_hash does not match previous record) — a record was removed, reordered or inserted", lineNo)
		}
		if got := chainHash(env.PrevHash, env.Record); got != env.RecordHash {
			return res, fmt.Errorf("line %d: record_hash mismatch — record content was modified", lineNo)
		}
		var s struct {
			SessionID string `json:"session_id"`
		}
		_ = json.Unmarshal(env.Record, &s)
		res.Sessions[s.SessionID] = true
		prev = env.RecordHash
		res.Records++
	}
	return res, sc.Err()
}
