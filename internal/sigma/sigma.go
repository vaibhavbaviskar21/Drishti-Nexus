// Package sigma evaluates Sigma detection rules (https://sigmahq.io) against
// parsed log entries, offline and without a SIEM backend.
//
// Supported: field selections with the modifiers contains, startswith, endswith,
// re, cidr, all and exists; * and ? wildcards (\* \? \\ escapes); null values;
// keyword lists; conditions with and / or / not, parentheses, "1 of" / "any of" /
// "all of" over search names (with * patterns) or "them"; a list of conditions.
// Anything else (aggregations such as "| count()", near, unknown modifiers,
// unmapped log sources, multi-document collections) makes the rule unsupported:
// it is skipped with a reason, never half-applied.
//
// Field names follow Sigma's taxonomy, which for Windows is the event's own field
// names (Image, CommandLine, TargetImage, ...). They are looked up in the entry's
// parsed fields case-insensitively, with aliases where sources differ (4688
// NewProcessName for Image, ...). See docs/SIGMA.md.
package sigma

import (
	"bytes"
	"crypto/sha256"
	"drishti-nexus/internal/models"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is a compiled Sigma rule.
type Rule struct {
	Title       string
	ID          string
	Level       string
	Description string
	Tags        []string
	File        string
	SHA256      string

	// Agg is the rule's count aggregation, nil for a plain rule. Match only tests
	// the condition; counting over the timeframe is the caller's (stateful) job.
	Agg *Aggregation

	source func(*models.LogEntry) bool
	cond   func(*models.LogEntry) bool
}

// Value returns a Sigma field of an entry, as rules see it (group-by and counted fields).
func Value(e *models.LogEntry, name string) (string, bool) { return value(e, name) }

// Match reports whether the entry is in the rule's log source and satisfies its condition.
func (r *Rule) Match(e *models.LogEntry) bool { return r.source(e) && r.cond(e) }

// Severity maps the Sigma level to an alert severity.
func (r *Rule) Severity() string {
	switch r.Level {
	case "informational", "low":
		return "low"
	case "high", "critical":
		return r.Level
	}
	return "medium"
}

// ATTACK returns the first technique tag (attack.t1003.001) and tactic tag (attack.credential_access).
func (r *Rule) ATTACK() (id, tactic string) {
	for _, t := range r.Tags {
		t = strings.ToLower(t)
		name, ok := strings.CutPrefix(t, "attack.")
		switch {
		case !ok:
		case techniqueTag.MatchString(name):
			if id == "" {
				id = strings.ToUpper(name)
			}
		case tactics[name] != "" && tactic == "":
			tactic = tactics[name]
		}
	}
	return id, tactic
}

var techniqueTag = regexp.MustCompile(`^t\d{4}(\.\d{3})?$`)

var tactics = map[string]string{
	"reconnaissance": "Reconnaissance", "resource_development": "Resource Development", "initial_access": "Initial Access",
	"execution": "Execution", "persistence": "Persistence", "privilege_escalation": "Privilege Escalation",
	"defense_evasion": "Defense Evasion", "credential_access": "Credential Access", "discovery": "Discovery",
	"lateral_movement": "Lateral Movement", "collection": "Collection", "command_and_control": "Command and Control",
	"exfiltration": "Exfiltration", "impact": "Impact",
}

type ruleFile struct {
	Title       string                 `yaml:"title"`
	ID          string                 `yaml:"id"`
	Level       string                 `yaml:"level"`
	Description string                 `yaml:"description"`
	Tags        []string               `yaml:"tags"`
	Logsource   logsource              `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
}

type logsource struct {
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
	Category string `yaml:"category"`
}

// Load reads every *.yml / *.yaml under dir (recursively, in path order). Rules that
// use unsupported features are skipped and listed in skipped with the reason.
func Load(dir string) (rules []*Rule, skipped []string, err error) {
	var paths []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ext := filepath.Ext(p); !d.IsDir() && (ext == ".yml" || ext == ".yaml") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)
	for _, p := range paths {
		data, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			return nil, nil, err
		}
		r, err := Parse(data)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		sum := sha256.Sum256(data)
		r.File, r.SHA256 = p, hex.EncodeToString(sum[:])
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, skipped, fmt.Errorf("%s: no usable Sigma rules (%d skipped)", dir, len(skipped))
	}
	return rules, skipped, nil
}

// Parse compiles one rule document.
func Parse(data []byte) (*Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var rf ruleFile
	if err := dec.Decode(&rf); err != nil {
		return nil, err
	}
	var extra interface{}
	if dec.Decode(&extra) == nil {
		return nil, errors.New("unsupported: multi-document rule collection")
	}
	if rf.Title == "" || rf.Detection == nil {
		return nil, errors.New("title and detection are required")
	}
	source, err := compileLogsource(rf.Logsource)
	if err != nil {
		return nil, err
	}
	cond, agg, err := compileDetection(rf.Detection)
	if err != nil {
		return nil, err
	}
	return &Rule{Title: rf.Title, ID: rf.ID, Level: strings.ToLower(rf.Level), Description: strings.TrimSpace(rf.Description),
		Tags: rf.Tags, Agg: agg, source: source, cond: cond}, nil
}

// ---- log sources ----

// isWindows uses the exact key: the Windows JSON, XML and CSV paths all write "EventID",
// and a case-insensitive scan of every syslog entry's fields was most of Sigma's cost.
func isWindows(e *models.LogEntry) bool { return e.Fields["EventID"] != nil }

func eventID(e *models.LogEntry, ids ...string) bool {
	v, _ := value(e, "EventID")
	for _, id := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func channelHas(e *models.LogEntry, s string) bool {
	v, _ := value(e, "Channel")
	return strings.Contains(strings.ToLower(v), s)
}

var categories = map[string]func(*models.LogEntry) bool{
	"process_creation": func(e *models.LogEntry) bool {
		return eventID(e, "4688") || eventID(e, "1") && channelHas(e, "sysmon")
	},
	"process_access":     func(e *models.LogEntry) bool { return eventID(e, "10") && channelHas(e, "sysmon") },
	"network_connection": func(e *models.LogEntry) bool { return eventID(e, "3") && channelHas(e, "sysmon") },
	"registry_set":       func(e *models.LogEntry) bool { return eventID(e, "13") && channelHas(e, "sysmon") },
	"file_event":         func(e *models.LogEntry) bool { return eventID(e, "11") && channelHas(e, "sysmon") },
	"ps_script":          func(e *models.LogEntry) bool { return eventID(e, "4104") },
	"ps_module":          func(e *models.LogEntry) bool { return eventID(e, "4103") },
}

var services = map[string]func(*models.LogEntry) bool{
	"security":   func(e *models.LogEntry) bool { return channelHas(e, "security") },
	"system":     func(e *models.LogEntry) bool { v, _ := value(e, "Channel"); return strings.EqualFold(v, "system") },
	"sysmon":     func(e *models.LogEntry) bool { return channelHas(e, "sysmon") },
	"powershell": func(e *models.LogEntry) bool { return channelHas(e, "powershell") },
	// Linux services: the product filter is the only reliable one for syslog text.
	"auth": func(*models.LogEntry) bool { return true }, "sshd": func(*models.LogEntry) bool { return true },
	"syslog": func(*models.LogEntry) bool { return true },
}

func compileLogsource(ls logsource) (func(*models.LogEntry) bool, error) {
	var checks []func(*models.LogEntry) bool
	switch strings.ToLower(ls.Product) {
	case "windows":
		checks = append(checks, isWindows)
	case "linux":
		checks = append(checks, func(e *models.LogEntry) bool { return !isWindows(e) })
	case "":
	default:
		return nil, fmt.Errorf("unsupported: logsource product %q", ls.Product)
	}
	if c := strings.ToLower(ls.Category); c != "" {
		f := categories[c]
		if f == nil {
			return nil, fmt.Errorf("unsupported: logsource category %q", c)
		}
		checks = append(checks, f)
	}
	if s := strings.ToLower(ls.Service); s != "" {
		f := services[s]
		if f == nil {
			return nil, fmt.Errorf("unsupported: logsource service %q", s)
		}
		checks = append(checks, f)
	}
	return func(e *models.LogEntry) bool {
		for _, c := range checks {
			if !c(e) {
				return false
			}
		}
		return true
	}, nil
}

// ---- field values ----

// aliases are other names the same Sigma field has in some sources (lower case).
var aliases = map[string][]string{
	"image":       {"NewProcessName"},    // Security 4688
	"parentimage": {"ParentProcessName"}, // Security 4688
	"user":        {"SubjectUserName", "TargetUserName"},
}

// value returns a field as text: the entry's fields (case-insensitive), then aliases,
// then the entry's own message / host.
func value(e *models.LogEntry, name string) (string, bool) {
	if v, ok := lookup(e.Fields, name); ok {
		return v, true
	}
	lname := strings.ToLower(name)
	for _, alt := range aliases[lname] {
		if v, ok := lookup(e.Fields, alt); ok {
			return v, true
		}
	}
	switch lname {
	case "message":
		return e.Message, e.Message != ""
	case "computer", "hostname":
		return e.Source, e.Source != ""
	}
	return "", false
}

func lookup(fields map[string]interface{}, name string) (string, bool) {
	v, ok := fields[name]
	if !ok {
		for k, x := range fields {
			if strings.EqualFold(k, name) {
				v, ok = x, true
				break
			}
		}
	}
	if !ok || v == nil {
		return "", false
	}
	if s, isStr := v.(string); isStr {
		return s, true
	}
	return fmt.Sprint(v), true // JSON numbers: 4625 → "4625"
}
