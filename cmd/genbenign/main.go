// cmd/genbenign/main.go
// Generates a realistic week of benign syslog / auth.log entries.
// Used as the false-positive baseline dataset (Phase 0+).
//
// Usage:
//
//	go run ./cmd/genbenign -days 7 -lines 50000 -out testdata/benign/auth_benign.log
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"time"
)

var (
	hosts = []string{
		"web01", "web02", "db01", "app01", "app02",
		"monitor01", "bastion01", "mail01",
	}
	users = []string{
		"alice", "bob", "carol", "dave", "eve",
		"frank", "grace", "heidi", "ivan", "judy",
		"deploy", "backup", "svc-monitor", "svc-backup",
	}
	sudoCommands = []string{
		"systemctl restart nginx",
		"apt-get update",
		"journalctl -u postgresql -n 100",
		"tail -n 200 /var/log/syslog",
		"service cron status",
		"df -h",
		"du -sh /var/log",
	}
	services = []string{
		"sshd", "cron", "kernel", "systemd", "sudo",
		"su", "CRON", "postfix", "nginx", "postgresql",
	}
)

func main() {
	daysFlag := flag.Int("days", 7, "Number of days of logs to generate")
	linesFlag := flag.Int("lines", 50000, "Approximate number of log lines to generate")
	outFlag := flag.String("out", "testdata/benign/auth_benign.log", "Output file path")
	seedFlag := flag.Int64("seed", 42, "Random seed for reproducibility")
	endFlag := flag.String("end", "2025-12-31T00:00:00Z", "End of the generated period (RFC 3339); fixed so output is byte-identical across runs")
	flag.Parse()

	endTime, err := time.Parse(time.RFC3339, *endFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid -end: %v\n", err)
		os.Exit(1)
	}
	// Seeded math/rand on purpose: the dataset must be byte-identical across runs.
	rng := rand.New(rand.NewSource(*seedFlag)) // #nosec G404 -- reproducible test data, not security-sensitive

	if err := os.MkdirAll(filepath.Dir(*outFlag), 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create output directory: %v\n", err)
		os.Exit(1)
	}
	f, err := os.Create(filepath.Clean(*outFlag))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create output file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 1024*1024)

	endTime = endTime.UTC()
	startTime := endTime.Add(-time.Duration(*daysFlag) * 24 * time.Hour)
	span := endTime.Sub(startTime)

	// Timestamps are uniform over the period (no business-hours bias) and written
	// in chronological order, like a real log file.
	stamps := make([]time.Time, *linesFlag)
	for i := range stamps {
		stamps[i] = startTime.Add(time.Duration(rng.Int63n(int64(span))))
	}
	sort.Slice(stamps, func(i, j int) bool { return stamps[i].Before(stamps[j]) })

	for _, ts := range stamps {
		fmt.Fprintln(w, generateLine(rng, ts))
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Write failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Generated %d lines → %s\n", len(stamps), *outFlag)
}

func generateLine(rng *rand.Rand, ts time.Time) string {
	host := hosts[rng.Intn(len(hosts))]
	svc := services[rng.Intn(len(services))]
	pid := 1000 + rng.Intn(60000)

	// Syslog timestamp format: "Jan  2 15:04:05"
	tsFmt := ts.Format("Jan _2 15:04:05")

	switch svc {
	case "sshd":
		return sshLine(rng, tsFmt, host, pid)
	case "sudo":
		return sudoLine(rng, tsFmt, host, pid)
	case "CRON":
		return cronLine(rng, tsFmt, host, pid)
	case "su":
		return suLine(rng, tsFmt, host, pid)
	default:
		return genericLine(rng, tsFmt, host, svc, pid)
	}
}

func sshLine(rng *rand.Rand, ts, host string, pid int) string {
	user := users[rng.Intn(len(users))]
	ip := randIP(rng)
	port := 20000 + rng.Intn(40000)

	// Realistic SSH events — mostly successful, occasional single failure
	roll := rng.Intn(100)
	switch {
	case roll < 75:
		return fmt.Sprintf("%s %s sshd[%d]: Accepted publickey for %s from %s port %d ssh2: RSA SHA256:%s",
			ts, host, pid, user, ip, port, randHash(rng))
	case roll < 85:
		return fmt.Sprintf("%s %s sshd[%d]: pam_unix(sshd:session): session opened for user %s by (uid=0)",
			ts, host, pid, user)
	case roll < 90:
		return fmt.Sprintf("%s %s sshd[%d]: pam_unix(sshd:session): session closed for user %s",
			ts, host, pid, user)
	case roll < 95:
		// Single failure — normal, not brute-force
		return fmt.Sprintf("%s %s sshd[%d]: Failed password for %s from %s port %d ssh2",
			ts, host, pid, user, ip, port)
	default:
		return fmt.Sprintf("%s %s sshd[%d]: Disconnected from authenticating user %s %s port %d [preauth]",
			ts, host, pid, user, ip, port)
	}
}

func sudoLine(rng *rand.Rand, ts, host string, pid int) string {
	user := users[rng.Intn(len(users))]
	cmd := sudoCommands[rng.Intn(len(sudoCommands))]
	return fmt.Sprintf("%s %s sudo[%d]: %s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=%s",
		ts, host, pid, user, user, cmd)
}

func cronLine(rng *rand.Rand, ts, host string, pid int) string {
	user := users[rng.Intn(len(users))]
	roll := rng.Intn(2)
	if roll == 0 {
		return fmt.Sprintf("%s %s CRON[%d]: pam_unix(cron:session): session opened for user %s by (uid=0)",
			ts, host, pid, user)
	}
	return fmt.Sprintf("%s %s CRON[%d]: pam_unix(cron:session): session closed for user %s",
		ts, host, pid, user)
}

func suLine(rng *rand.Rand, ts, host string, pid int) string {
	user := users[rng.Intn(len(users))]
	return fmt.Sprintf("%s %s su[%d]: (to root) %s on pts/0",
		ts, host, pid, user)
}

func genericLine(rng *rand.Rand, ts, host, svc string, pid int) string {
	messages := []string{
		"Starting periodic command scheduler",
		"Started Session Slice of User root",
		"New session 42 of user root",
		"Reached target Basic System",
		"pam_unix(login:auth): authentication failure; logname= uid=0 euid=0",
		"systemd[1]: Started Run anacron jobs",
		"kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=10.0.0.1 DST=10.0.0.5 PROTO=TCP",
		"postfix/smtpd[12345]: connect from mail.example.com[203.0.113.10]",
	}
	msg := messages[rng.Intn(len(messages))]
	return fmt.Sprintf("%s %s %s[%d]: %s", ts, host, svc, pid, msg)
}

func randIP(rng *rand.Rand) string {
	// Use RFC 5737 / RFC 1918 ranges — no real public IPs
	prefixes := []string{"192.168.1", "10.0.0", "172.16.0", "203.0.113"}
	prefix := prefixes[rng.Intn(len(prefixes))]
	return fmt.Sprintf("%s.%d", prefix, 1+rng.Intn(254))
}

func randHash(rng *rand.Rand) string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
	b := make([]byte, 43)
	for i := range b {
		b[i] = chars[rng.Intn(len(chars))]
	}
	return string(b)
}
