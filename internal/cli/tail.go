package cli

import (
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/pipeline"
	"drishti-nexus/internal/storage"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/fatih/color"
)

// TailCommand follows a log file and displays entries and alerts in real time.
// With -db, progress is checkpointed so an interrupted session resumes.
func TailCommand(args []string) error {
	fs := flag.NewFlagSet("tail", flag.ContinueOnError)
	var common Common
	common.Register(fs)
	follow := fs.Bool("follow", true, "keep watching for appended lines (false: read to end and exit)")
	poll := fs.Duration("poll", time.Second, "poll interval while waiting for new lines")
	db := fs.String("db", "", "SQLite database for persistence; re-running with the same -db resumes from the last checkpoint")
	quiet := fs.Bool("quiet", false, "only print alerts, not every log line")
	files, err := ParseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return fmt.Errorf("usage: drishti tail [flags] <logfile>")
	}
	if err := common.Load(); err != nil {
		return err
	}

	opts := common.PipelineOptions("tail", args)
	if *db != "" {
		store, err := storage.OpenSQLite(*db)
		if err != nil {
			return err
		}
		defer closeStore(store)
		opts.Store, opts.StorageDesc, opts.KeepLogs = store, "sqlite:"+*db, true
	}

	debugColor := color.New(color.FgCyan)
	infoColor := color.New(color.FgWhite)
	warnColor := color.New(color.FgYellow)
	errorColor := color.New(color.FgRed)
	criticalColor := color.New(color.FgRed, color.Bold)
	alertColor := color.New(color.FgMagenta, color.Bold)

	alertCount := 0
	opts.OnEntry = func(entry *models.LogEntry, alerts []*models.Alert) {
		if !*quiet {
			var c *color.Color
			switch entry.Severity {
			case models.SeverityDebug:
				c = debugColor
			case models.SeverityWarning:
				c = warnColor
			case models.SeverityError:
				c = errorColor
			case models.SeverityCritical, models.SeverityAlert, models.SeverityEmergency:
				c = criticalColor
			default:
				c = infoColor
			}
			_, _ = c.Printf("[%s] [%s] %s: %s\n", entry.Timestamp.Format("2006-01-02 15:04:05Z"), entry.Severity, entry.Source, entry.Message)
		}
		for _, alert := range alerts {
			alertCount++
			mitre := ""
			if alert.MITRETechniqueID != "" {
				mitre = fmt.Sprintf(" [%s]", alert.MITRETechniqueID)
			}
			_, _ = alertColor.Printf("  🚨 ALERT %s [%s] (%s): %s%s\n", alert.ID, alert.Severity, alert.IncidentID, alert.Description, mitre)
		}
	}

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	go func() {
		<-sig
		fmt.Println("\nInterrupt received — checkpointing and closing session...")
		close(stop)
	}()

	fmt.Println("===================================")
	fmt.Println("Drishti Nexus - Live Log Monitor")
	fmt.Println("===================================")

	res, err := pipeline.Follow(files[0], opts, pipeline.FollowOptions{
		Follow: *follow,
		Poll:   *poll,
		Stop:   stop,
		OnResume: func(offset int64, lines int) {
			if offset > 0 {
				fmt.Printf("Resuming from checkpoint: byte %d, line %d\n", offset, lines)
			}
		},
	})
	if res == nil {
		return err
	}
	printEvidence(res.Session)

	status := "ok"
	select {
	case <-stop:
		status = "interrupted"
	default:
	}
	if err != nil {
		status = "error: " + err.Error()
	}
	ferr := res.Finish(&opts, status)

	fmt.Println("\n===================================")
	fmt.Printf("Lines processed: %d\n", res.Stats.Lines)
	fmt.Printf("New alerts: %d (total stored: %d in %d incidents)\n", alertCount, res.Stats.Alerts, res.Stats.Incidents)
	printCustody(res.Session, opts.AuditLogPath)
	fmt.Println("===================================")
	if err != nil {
		return err
	}
	return ferr
}
