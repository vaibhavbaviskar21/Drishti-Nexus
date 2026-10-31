package parser

import (
	"testing"
)

func TestExtractAuthFields(t *testing.T) {
	tests := []struct {
		name           string
		line           string
		event, result  string
		user, ip, port string
		count          int
	}{
		{"failed password", "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for root from 112.95.230.3 port 49464 ssh2",
			"password_failed", "failure", "root", "112.95.230.3", "49464", 1},
		{"failed password invalid user", "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2",
			"password_failed", "failure", "webmaster", "173.234.31.186", "38926", 1},
		{"failed publickey", "Mar  1 10:00:00 h sshd[1]: Failed publickey for git from 10.0.0.9 port 2222 ssh2: RSA SHA256:abc",
			"password_failed", "failure", "git", "10.0.0.9", "2222", 1},
		{"message repeated", "Dec 10 07:08:28 LabSZ sshd[24208]: message repeated 5 times: [ Failed password for root from 112.95.230.3 port 49464 ssh2]",
			"password_failed", "failure", "root", "112.95.230.3", "49464", 5},
		{"invalid user", "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
			"invalid_user", "failure", "webmaster", "173.234.31.186", "", 1},
		{"invalid user with port", "Mar  1 10:00:00 h sshd[1]: Invalid user admin from 10.1.1.1 port 4444",
			"invalid_user", "failure", "admin", "10.1.1.1", "4444", 1},
		{"pam failure with user", "Dec 10 06:55:48 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=112.95.230.3  user=root",
			"pam_failure", "failure", "root", "112.95.230.3", "", 1},
		{"pam failure Linux.log style", "Jun 15 02:04:59 combo sshd(pam_unix)[20882]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root",
			"pam_failure", "failure", "root", "220-135-151-1.hinet-ip.hinet.net", "", 1},
		{"pam failure without rhost value", "Mar  1 10:00:00 h login[5]: pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=tty1 ruser= rhost=",
			"pam_failure", "failure", "", "", "", 1},
		{"check pass", "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown",
			"pam_check_pass", "failure", "", "", "", 1},
		{"accepted", "Mar  1 10:00:00 h sshd[9]: Accepted publickey for alice from 192.168.1.5 port 50000 ssh2: RSA SHA256:x",
			"accepted", "success", "alice", "192.168.1.5", "50000", 1},
		{"session opened is info", "Mar  1 10:00:00 h CRON[9]: pam_unix(cron:session): session opened for user dave by (uid=0)",
			"session_opened", "info", "dave", "", "", 1},
		{"PAM summary is info", "Dec 10 07:02:47 LabSZ sshd[24206]: PAM 5 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=112.95.230.3  user=root",
			"auth_summary", "info", "", "", "", 1},
		{"too many failures is info", "Dec 10 07:02:47 LabSZ sshd[24206]: Disconnecting: Too many authentication failures for root [preauth]",
			"auth_summary", "info", "", "", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := parseOne(t, Options{}, tt.line)
			f := e.Fields
			str := func(k string) string { s, _ := f[k].(string); return s }
			if str("auth_event") != tt.event || str("auth_result") != tt.result {
				t.Fatalf("event=%q result=%q, want %q %q", str("auth_event"), str("auth_result"), tt.event, tt.result)
			}
			if str("user") != tt.user || str("src_ip") != tt.ip || str("src_port") != tt.port {
				t.Errorf("user=%q ip=%q port=%q, want %q %q %q", str("user"), str("src_ip"), str("src_port"), tt.user, tt.ip, tt.port)
			}
			if f["auth_count"] != tt.count {
				t.Errorf("auth_count=%v, want %d", f["auth_count"], tt.count)
			}
		})
	}
}

func TestExtractAuthFields_NonAuthLinesUntouched(t *testing.T) {
	for _, line := range []string{
		"Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.example.com [1.2.3.4] failed - POSSIBLE BREAK-IN ATTEMPT!",
		"Dec 10 06:55:46 LabSZ sshd[24200]: Connection closed by 1.2.3.4 [preauth]",
		"Mar  1 10:00:00 h systemd[1]: Failed to start nginx.service",
	} {
		e := parseOne(t, Options{}, line)
		if _, ok := e.Fields["auth_result"]; ok {
			t.Errorf("%q tagged as auth: %v", line, e.Fields)
		}
	}
}

func TestExtractAuthFields_Windows(t *testing.T) {
	e := parseOne(t, Options{}, `{"@timestamp":"2020-09-20T12:00:00Z","Hostname":"DC1","EventID":4625,"TargetUserName":"bob","IpAddress":"10.0.0.7","Message":"An account failed to log on."}`)
	if e.Fields["auth_result"] != "failure" || e.Fields["user"] != "bob" || e.Fields["src_ip"] != "10.0.0.7" {
		t.Errorf("4625: %v", e.Fields)
	}
	e = parseOne(t, Options{}, `{"@timestamp":"2020-09-20T12:00:00Z","Hostname":"DC1","EventID":4624,"TargetUserName":"bob","IpAddress":"-"}`)
	if e.Fields["auth_result"] != "success" || e.Fields["src_ip"] != nil {
		t.Errorf("4624: %v", e.Fields)
	}
	// Structured non-auth events must be marked so their free text is not keyword-matched.
	e = parseOne(t, Options{}, `{"@timestamp":"2020-09-20T12:00:00Z","Hostname":"WS1","EventID":4103,"Message":"Failed to find user in script"}`)
	if e.Fields["auth_result"] != "none" {
		t.Errorf("4103 should be auth_result=none: %v", e.Fields)
	}
}
