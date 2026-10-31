package cli

import (
	"drishti-nexus/internal/audit"
	"flag"
	"fmt"
)

// AuditCommand handles "drishti audit verify [-audit-log path]".
func AuditCommand(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("usage: drishti audit verify [-audit-log <path>]")
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	path := fs.String("audit-log", audit.DefaultLogPath, "audit log to verify")
	if _, err := ParseInterleaved(fs, args[1:]); err != nil {
		return err
	}

	res, err := audit.Verify(*path)
	if err != nil {
		if res != nil {
			fmt.Printf("✗ %s: %d records verified before the failure\n", *path, res.Records)
		}
		return fmt.Errorf("audit log verification failed: %w", err)
	}
	fmt.Printf("✓ %s: %d records, %d sessions — hash chain intact\n", *path, res.Records, len(res.Sessions))
	return nil
}
