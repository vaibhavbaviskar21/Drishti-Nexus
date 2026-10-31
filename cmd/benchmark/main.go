// Command benchmark measures parsing quality, detection output and throughput
// of the full pipeline on the benchmark datasets. Results feed BASELINE.md.
//
//	go run ./cmd/benchmark -suite -out benchmarks/results/phase1.json
//	go run ./cmd/benchmark -file some.log
package main

import (
	"drishti-nexus/internal/config"
	"drishti-nexus/internal/pipeline"
	"drishti-nexus/internal/version"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"
)

// Dataset is one benchmark input.
type Dataset struct {
	Name   string   `json:"name"`
	Files  []string `json:"files"`
	Benign bool     `json:"benign"` // alerts on a benign set are false positives
	Note   string   `json:"note,omitempty"`
}

// Suite is the standard benchmark set (see testdata/DATASETS.md).
var Suite = []Dataset{
	{Name: "loghub-ssh", Files: []string{"testdata/datasets/loghub-ssh/SSH.log"},
		Note: "Real sshd log, lab server under sustained internet brute force (LogHub)"},
	{Name: "loghub-linux", Files: []string{"testdata/datasets/loghub-linux/Linux.log"},
		Note: "Real /var/log/messages from one Linux host (LogHub); contains real brute-force bursts"},
	{Name: "mordor-mimikatz", Files: []string{"testdata/datasets/mordor/empire_mimikatz_logonpasswords_2020-08-07103224.json"},
		Note: "Windows Security/Sysmon/PowerShell JSON events, Empire Mimikatz (OTRF)"},
	{Name: "mordor-psexec", Files: []string{"testdata/datasets/mordor/empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608.json"},
		Note: "Windows events, Empire PsExec lateral movement (OTRF)"},
	{Name: "synthetic-benign", Files: []string{"testdata/benign/auth_benign.log"}, Benign: true,
		Note: "Generated benign auth/syslog week (cmd/genbenign, seed 42)"},
	{Name: "fixture-openssh-2k", Files: []string{"testdata/fixtures/loghub_openssh_2k.log"},
		Note: "First 2,000 lines of LogHub OpenSSH (committed fixture)"},
}

type DatasetResult struct {
	Dataset
	Skipped       string         `json:"skipped,omitempty"`
	Lines         int            `json:"lines"`
	Entries       int            `json:"entries"`
	ParseQuality  map[string]int `json:"parse_quality"`
	StructuredPct float64        `json:"structured_pct"` // Clean+Partial share of entries
	CleanPct      float64        `json:"clean_pct"`
	ByParser      map[string]int `json:"by_parser"`
	Repairs       map[string]int `json:"repairs"`
	Alerts        int            `json:"alerts"`
	Incidents     int            `json:"incidents"`
	AlertsByRule  map[string]int `json:"alerts_by_rule"`
	AlertsPer1k   float64        `json:"alerts_per_1k_lines"`
	DurationMs    int64          `json:"duration_ms"`
	LinesPerSec   int64          `json:"lines_per_sec"`
	AllocMB       float64        `json:"alloc_mb"`
}

type Report struct {
	GeneratedAt    time.Time        `json:"generated_at"`
	DrishtiVersion string           `json:"drishti_version"`
	GoVersion      string           `json:"go_version"`
	Platform       string           `json:"platform"`
	ConfigPath     string           `json:"config_path"`
	Timezone       string           `json:"assumed_timezone"`
	Datasets       []*DatasetResult `json:"datasets"`
}

func main() {
	suite := flag.Bool("suite", false, "run the standard dataset suite")
	file := flag.String("file", "", "benchmark a single file")
	dir := flag.String("dir", "", "benchmark every file in a directory as one dataset")
	out := flag.String("out", "", "write JSON report to this path")
	cfgPath := flag.String("config", "", "detection config (default: configs/config.yaml)")
	tz := flag.String("tz", "UTC", "timezone assumed for timestamps without an offset")
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile to this file")
	flag.Parse()

	if *cpuProfile != "" {
		pf, err := os.Create(filepath.Clean(*cpuProfile))
		if err != nil {
			fail(err)
		}
		if err := pprof.StartCPUProfile(pf); err != nil {
			fail(err)
		}
		defer func() {
			pprof.StopCPUProfile()
			_ = pf.Close()
		}()
	}

	var datasets []Dataset
	switch {
	case *suite:
		datasets = Suite
	case *file != "":
		datasets = []Dataset{{Name: filepath.Base(*file), Files: []string{*file}}}
	case *dir != "":
		files, err := collect(*dir)
		if err != nil {
			fail(err)
		}
		datasets = []Dataset{{Name: filepath.Base(*dir), Files: files}}
	default:
		fail(fmt.Errorf("provide -suite, -file or -dir"))
	}

	cfg, used, err := config.Load(*cfgPath)
	if err != nil {
		fail(err)
	}
	loc, err := time.LoadLocation(*tz)
	if err != nil {
		fail(err)
	}

	report := &Report{
		GeneratedAt:    time.Now().UTC(),
		DrishtiVersion: version.Version,
		GoVersion:      runtime.Version(),
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		ConfigPath:     used,
		Timezone:       loc.String(),
	}

	for _, ds := range datasets {
		r := run(ds, pipeline.Options{Config: cfg, ConfigPath: used, Location: loc, Command: "benchmark", ToolVersion: version.Version})
		report.Datasets = append(report.Datasets, r)
		print(r)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fail(err)
	}
	if *out == "" {
		fmt.Println(string(data))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		fail(err)
	}
	fmt.Printf("\n✓ report written to %s\n", *out)
}

func run(ds Dataset, opts pipeline.Options) *DatasetResult {
	r := &DatasetResult{Dataset: ds}
	for _, f := range ds.Files {
		if _, err := os.Stat(f); err != nil {
			r.Skipped = fmt.Sprintf("missing %s (run scripts/fetch-datasets.sh / make genbenign)", f)
			return r
		}
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res, err := pipeline.Run(ds.Files, opts)
	if err != nil {
		r.Skipped = "error: " + err.Error()
		return r
	}
	runtime.ReadMemStats(&after)

	st := res.Stats
	r.Lines, r.Entries = st.Lines, st.Entries
	r.ParseQuality, r.ByParser, r.Repairs = st.ParseQuality, st.ByParser, st.Repairs
	r.Alerts, r.Incidents, r.AlertsByRule = st.Alerts, st.Incidents, st.AlertsByRule
	r.DurationMs = st.DurationMs
	r.AllocMB = float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)
	if st.Entries > 0 {
		clean := st.ParseQuality["Clean"]
		r.CleanPct = pct(clean, st.Entries)
		r.StructuredPct = pct(clean+st.ParseQuality["Partial"], st.Entries)
	}
	if st.Lines > 0 {
		r.AlertsPer1k = float64(st.Alerts) * 1000 / float64(st.Lines)
	}
	if st.DurationMs > 0 {
		r.LinesPerSec = int64(st.Lines) * 1000 / st.DurationMs
	}
	return r
}

func print(r *DatasetResult) {
	fmt.Printf("→ %s\n", r.Name)
	if r.Skipped != "" {
		fmt.Printf("  SKIPPED: %s\n\n", r.Skipped)
		return
	}
	fmt.Printf("  lines %d | entries %d | structured %.2f%% (clean %.2f%%) | %d ms | %d lines/s | %.0f MB alloc\n",
		r.Lines, r.Entries, r.StructuredPct, r.CleanPct, r.DurationMs, r.LinesPerSec, r.AllocMB)
	fmt.Printf("  quality %v | parsers %v | repairs %v\n", r.ParseQuality, r.ByParser, r.Repairs)
	label := "alerts"
	if r.Benign {
		label = "alerts (all false positives)"
	}
	fmt.Printf("  %s: %d in %d incidents (%.2f per 1k lines)\n", label, r.Alerts, r.Incidents, r.AlertsPer1k)
	for _, k := range pipeline.SortedKeys(r.AlertsByRule) {
		fmt.Printf("    %-36s %d\n", k, r.AlertsByRule[k])
	}
	fmt.Println()
}

func collect(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.HasPrefix(info.Name(), ".") {
			return err
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

func pct(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
