package main

import (
	"drishti-nexus/internal/cli"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/web"
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const version = "1.0.0"

func main() {
	// Define subcommands
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Load configuration
	config, err := loadConfig("config.yaml")
	if err != nil {
		fmt.Printf("Warning: Failed to load config: %v\n", err)
		config = getDefaultConfig()
	}

	command := os.Args[1]

	switch command {
	case "tail":
		handleTailCommand(config)
	case "analyze":
		handleAnalyzeCommand(config)
	case "scan":
		handleScanCommand(config)
	case "serve":
		handleServeCommand(config)
	case "version":
		fmt.Printf("Drishti Nexus v%s\n", version)
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func handleTailCommand(config *models.Config) {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	fs.Parse(os.Args[2:])

	if fs.NArg() < 1 {
		fmt.Println("Usage: drishti tail <logfile>")
		os.Exit(1)
	}

	logFile := fs.Arg(0)
	if err := cli.TailCommand(logFile, config); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func handleAnalyzeCommand(config *models.Config) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	fs.Parse(os.Args[2:])

	if fs.NArg() < 1 {
		fmt.Println("Usage: drishti analyze <logfile>")
		os.Exit(1)
	}

	logFile := fs.Arg(0)
	if err := cli.AnalyzeCommand(logFile, config); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func handleScanCommand(config *models.Config) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	output := fs.String("output", "", "Output file for results (default: auto-generated)")
	fs.Parse(os.Args[2:])

	if fs.NArg() < 1 {
		fmt.Println("Usage: drishti scan <logfile> [-output <file>]")
		os.Exit(1)
	}

	logFile := fs.Arg(0)
	if err := cli.ScanCommand(logFile, *output, config); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func handleServeCommand(config *models.Config) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 8080, "Port to run the web server on")
	logFile := fs.String("log", "", "Log file to load and monitor")
	fs.Parse(os.Args[2:])

	server := web.NewServer(config)
	if err := server.Start(*port, *logFile); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func loadConfig(filename string) (*models.Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config models.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func getDefaultConfig() *models.Config {
	return &models.Config{
		Rules: []models.DetectionRule{},
		NormalHours: struct {
			Start int `yaml:"start"`
			End   int `yaml:"end"`
		}{
			Start: 9,
			End:   17,
		},
		MaxLogEntries: 100000,
	}
}

func printUsage() {
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║       Drishti Nexus - Usage Guide        ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("COMMANDS:")
	fmt.Println()
	fmt.Println("  tail <logfile>")
	fmt.Println("    Monitor log file in real-time with colorized output")
	fmt.Println("    Example: drishti tail /var/log/auth.log")
	fmt.Println()
	fmt.Println("  analyze <logfile>")
	fmt.Println("    Perform historical analysis and generate summary report")
	fmt.Println("    Example: drishti analyze /var/log/syslog")
	fmt.Println()
	fmt.Println("  scan <logfile> [-output <file>]")
	fmt.Println("    Scan log file and export findings to JSON/CSV")
	fmt.Println("    Example: drishti scan access.log -output report.json")
	fmt.Println()
	fmt.Println("  serve [-port 8080] [-log <file>]")
	fmt.Println("    Start web dashboard for interactive analysis")
	fmt.Println("    Example: drishti serve -port 8080 -log test.log")
	fmt.Println()
	fmt.Println("  version")
	fmt.Println("    Display version information")
	fmt.Println()
	fmt.Println("  help")
	fmt.Println("    Show this usage guide")
	fmt.Println()
	fmt.Println("CONFIGURATION:")
	fmt.Println("  Edit config.yaml to customize detection rules and settings")
	fmt.Println()
}
