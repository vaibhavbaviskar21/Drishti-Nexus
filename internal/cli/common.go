package cli

import (
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/config"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/pipeline"
	"drishti-nexus/internal/storage"
	"drishti-nexus/internal/version"
	"flag"
	"fmt"
	"os"
	"time"
)

// Common holds flags shared by every analysis command.
type Common struct {
	ConfigPath string
	TZ         string
	AuditLog   string

	Config   *models.Config
	usedPath string
	Location *time.Location
}

// Register adds the shared flags to fs.
func (c *Common) Register(fs *flag.FlagSet) {
	fs.StringVar(&c.ConfigPath, "config", "", "detection config (default: configs/config.yaml, then ./config.yaml, then built-in)")
	fs.StringVar(&c.TZ, "tz", "UTC", "IANA timezone assumed for timestamps without an offset (e.g. Asia/Kolkata)")
	fs.StringVar(&c.AuditLog, "audit-log", audit.DefaultLogPath, "append-only audit log path")
}

// Load resolves the config and timezone after flags are parsed.
func (c *Common) Load() error {
	cfg, used, err := config.Load(c.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	c.Config, c.usedPath = cfg, used
	if used == "" {
		fmt.Fprintln(os.Stderr, "Note: no config file found; using built-in defaults")
	}
	loc, err := time.LoadLocation(c.TZ)
	if err != nil {
		return fmt.Errorf("invalid -tz %q: %w", c.TZ, err)
	}
	c.Location = loc
	return nil
}

// PipelineOptions builds pipeline options for a command.
func (c *Common) PipelineOptions(command string, args []string) pipeline.Options {
	return pipeline.Options{
		Config:       c.Config,
		ConfigPath:   c.usedPath,
		Location:     c.Location,
		Command:      command,
		Args:         args,
		AuditLogPath: c.AuditLog,
		ToolVersion:  version.Version,
	}
}

// ParseInterleaved parses flags that may appear before or after positional
// arguments ("scan file.log -output r.json" and "scan -output r.json file.log").
func ParseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func printEvidence(s *audit.Session) {
	for _, ev := range s.Evidence {
		fmt.Printf("Evidence: %s\n  SHA-256: %s  (%d bytes, opened read-only)\n", ev.Path, ev.SHA256Before, ev.SizeBytes)
	}
	fmt.Printf("Audit session: %s\n", s.SessionID)
}

func printCustody(s *audit.Session, auditLog string) {
	for _, ev := range s.Evidence {
		if ev.Unchanged == nil {
			continue
		}
		if *ev.Unchanged {
			fmt.Printf("✓ Evidence unchanged after analysis: %s\n", ev.Path)
		} else {
			fmt.Printf("✗ EVIDENCE HASH CHANGED DURING ANALYSIS: %s (before %s, after %s)\n", ev.Path, ev.SHA256Before, ev.SHA256After)
		}
	}
	if auditLog != "" {
		fmt.Printf("Audit trail: %s (session %s)\n", auditLog, s.SessionID)
	}
}

// closeStore commits and closes a persistent store. A failed close can lose the
// last batch of writes, so it is reported rather than ignored.
func closeStore(s *storage.SQLiteStorage) {
	if err := s.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: closing database: %v\n", err)
	}
}
