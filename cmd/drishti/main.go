// Command drishti is the Drishti Nexus offline log analysis tool.
package main

import (
	"drishti-nexus/internal/cli"
	"drishti-nexus/internal/version"
	"drishti-nexus/internal/web"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	_ "time/tzdata" // embed the IANA zone database: -tz works on air-gapped hosts without one
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command, args := os.Args[1], os.Args[2:]
	var err error
	switch command {
	case "tail":
		err = cli.TailCommand(args)
	case "analyze":
		err = cli.AnalyzeCommand(args)
	case "scan":
		err = cli.ScanCommand(args)
	case "serve":
		err = serve(args)
	case "audit":
		err = cli.AuditCommand(args)
	case "version":
		fmt.Printf("Drishti Nexus v%s\n", version.Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var common cli.Common
	common.Register(fs)
	port := fs.Int("port", 8080, "port to listen on")
	host := fs.String("host", "127.0.0.1", "interface to bind (use 0.0.0.0 to expose on the network)")
	logFile := fs.String("log", "", "log file to load")
	if _, err := cli.ParseInterleaved(fs, args); err != nil {
		return err
	}
	if err := common.Load(); err != nil {
		return err
	}

	opts := web.Options{
		Addr:     *host + ":" + strconv.Itoa(*port),
		Pipeline: common.PipelineOptions("serve", args),
	}
	if *logFile != "" {
		opts.LogFiles = []string{*logFile}
	}
	return web.NewServer(common.Config).Start(opts)
}

func printUsage() {
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║       Drishti Nexus - Usage Guide         ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("COMMANDS:")
	fmt.Println()
	fmt.Println("  tail <logfile> [-db case.db] [-follow=false] [-quiet]")
	fmt.Println("    Follow a log file live; with -db, an interrupted session resumes")
	fmt.Println("    Example: drishti tail -db case.db /var/log/auth.log")
	fmt.Println()
	fmt.Println("  analyze <logfile|dir> [...]")
	fmt.Println("    Historical analysis with a summary report")
	fmt.Println("    Example: drishti analyze -tz Asia/Kolkata /var/log/syslog")
	fmt.Println()
	fmt.Println("  scan <logfile|dir> [...] [-output report.json] [-db case.db] [-alerts-only]")
	fmt.Println("    Export findings to JSON + CSV with chain-of-custody metadata")
	fmt.Println("    Example: drishti scan access.log -output report.json")
	fmt.Println()
	fmt.Println("  serve [-port 8080] [-host 127.0.0.1] [-log <file>]")
	fmt.Println("    Web dashboard (localhost only by default)")
	fmt.Println()
	fmt.Println("  audit verify [-audit-log drishti_audit.log]")
	fmt.Println("    Verify the tamper-evident hash chain of the audit log")
	fmt.Println()
	fmt.Println("  version | help")
	fmt.Println()
	fmt.Println("COMMON FLAGS (tail, analyze, scan, serve):")
	fmt.Println("  -config <file>     detection config (default configs/config.yaml, then ./config.yaml)")
	fmt.Println("  -tz <zone>         timezone assumed for timestamps without an offset (default UTC)")
	fmt.Println("  -audit-log <file>  append-only audit log (default drishti_audit.log)")
	fmt.Println()
	fmt.Println("Source logs are only ever opened read-only; every session is hashed and audited.")
}
