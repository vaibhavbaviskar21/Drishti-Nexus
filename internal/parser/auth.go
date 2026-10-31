package parser

import (
	"drishti-nexus/internal/models"
	"regexp"
	"strconv"
	"strings"
)

// Authentication field extraction.
//
// Detection rules key on these fields instead of keyword-matching free text:
//
//	auth_result  "failure" | "success" | "info"   ("info" = auth-related but not an attempt,
//	                                                e.g. "PAM 5 more authentication failures")
//	auth_event   what kind of line produced it (see the patterns below)
//	auth_count   attempts represented by the line ("message repeated 3 times" → 3)
//	user, src_ip, src_port
//
// One sshd login attempt typically writes several lines (pam_unix failure, "Failed
// password", "Invalid user"); they share the sshd PID and second. The detection
// engine collapses them into one attempt using auth_event + pid.

type authPattern struct {
	re     *regexp.Regexp
	event  string
	result string
	// capture group indices (0 = absent)
	user, ip, port, count int

	lit string // literal every match starts with (computed in init) — cheap prefilter
}

func init() {
	// LiteralPrefix ignores anchored patterns, so compute it on the unanchored form.
	for i := range authPatterns {
		unanchored := strings.TrimPrefix(authPatterns[i].re.String(), "^")
		authPatterns[i].lit, _ = regexp.MustCompile(unanchored).LiteralPrefix()
	}
}

var authPatterns = []authPattern{
	{re: regexp.MustCompile(`^message repeated (\d+) times: \[ ?Failed (?:password|publickey|none|keyboard-interactive/pam) for (?:invalid user )?(.*?) from (\S+) port (\d+)`),
		event: "password_failed", result: "failure", count: 1, user: 2, ip: 3, port: 4},
	{re: regexp.MustCompile(`^Failed (?:password|publickey|none|keyboard-interactive/pam) for (?:invalid user )?(.*?) from (\S+) port (\d+)`),
		event: "password_failed", result: "failure", user: 1, ip: 2, port: 3},
	{re: regexp.MustCompile(`^Invalid user (.*?) from (\S+)(?: port (\d+))?\s*$`),
		event: "invalid_user", result: "failure", user: 1, ip: 2, port: 3},
	{re: regexp.MustCompile(`^pam_unix\([^)]*:auth\): authentication failure;(?:.*?rhost=(\S*))?(?:\s+user=(\S+))?`),
		event: "pam_failure", result: "failure", ip: 1, user: 2},
	{re: regexp.MustCompile(`^authentication failure;.*?rhost=(\S*)(?:\s+user=(\S+))?`), // "sshd(pam_unix)[pid]: authentication failure; ..."
		event: "pam_failure", result: "failure", ip: 1, user: 2},
	{re: regexp.MustCompile(`^(?:pam_unix\([^)]*:auth\): )?check pass; user unknown`),
		event: "pam_check_pass", result: "failure"},
	{re: regexp.MustCompile(`^Authentication failed from (\S+)`), // logind / ftpd style
		event: "auth_failed", result: "failure", ip: 1},
	{re: regexp.MustCompile(`^Accepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic|hostbased) for (\S+) from (\S+) port (\d+)`),
		event: "accepted", result: "success", user: 1, ip: 2, port: 3},
	{re: regexp.MustCompile(`^(?:pam_unix\([^)]*:session\): )?session opened for user (\S+)`),
		event: "session_opened", result: "info", user: 1},
	{re: regexp.MustCompile(`^(?:PAM \d+ more authentication failures?|PAM service\(\S+\) ignoring max retries|Disconnecting: Too many authentication failures)`),
		event: "auth_summary", result: "info"},
}

// Windows Security event IDs (Mordor / EVTX JSON exports).
var windowsAuthEvents = map[int]struct{ event, result string }{
	4624: {"windows_logon", "success"},
	4625: {"windows_logon_failed", "failure"},
	4771: {"kerberos_preauth_failed", "failure"},
	4776: {"ntlm_validation", "info"}, // success or failure depending on Status; not counted
}

func extractAuthFields(entry *models.LogEntry) {
	if entry.Fields == nil {
		return
	}
	if extractWindowsAuth(entry) {
		return
	}

	msg := entry.Message
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	for _, p := range authPatterns {
		// Skip the regex when the message cannot start with its required literal.
		if p.lit != "" && !strings.HasPrefix(msg, p.lit) {
			continue
		}
		m := p.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		f := entry.Fields
		f["auth_event"] = p.event
		f["auth_result"] = p.result
		count := 1
		if p.count > 0 {
			if n, err := strconv.Atoi(m[p.count]); err == nil && n > 0 {
				count = n
			}
		}
		f["auth_count"] = count
		setIf(f, "user", m, p.user)
		setIf(f, "src_ip", m, p.ip)
		setIf(f, "src_port", m, p.port)
		return
	}
}

func extractWindowsAuth(entry *models.LogEntry) bool {
	raw, ok := lookup(entry.Fields, "EventID")
	if !ok {
		return false
	}
	id, ok := raw.(float64)
	if !ok {
		return false
	}
	f := entry.Fields
	ev, ok := windowsAuthEvents[int(id)]
	if !ok {
		// A structured event that is not an authentication event: say so, so the
		// detection engine does not keyword-match its free text (script blocks,
		// process command lines) as logins.
		f["auth_result"] = "none"
		return true
	}
	f["auth_event"] = ev.event
	f["auth_result"] = ev.result
	f["auth_count"] = 1
	if u, ok := lookup(f, "TargetUserName"); ok {
		if s, ok := u.(string); ok && s != "" && s != "-" {
			f["user"] = s
		}
	}
	if ip, ok := lookup(f, "IpAddress"); ok {
		if s, ok := ip.(string); ok && s != "" && s != "-" {
			f["src_ip"] = s
		}
	}
	return true
}

func setIf(f map[string]interface{}, key string, m []string, idx int) {
	if idx <= 0 || idx >= len(m) {
		return
	}
	v := strings.TrimSpace(m[idx])
	if v == "" || v == "-" {
		return
	}
	f[key] = v
}
