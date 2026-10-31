package storage

import (
	"drishti-nexus/internal/models"
	"time"
)

// Storage defines the interface for log and alert persistence
type Storage interface {
	AddLog(entry *models.LogEntry)
	AddAlert(alert *models.Alert)
	// UpdateAlert persists changes to an alert previously passed to AddAlert
	// (aggregated count, last-seen time, related alerts).
	UpdateAlert(alert *models.Alert)
	GetLogs() []*models.LogEntry
	GetAlerts() []*models.Alert
	GetLogsSince(since time.Time) []*models.LogEntry
	GetLogsBySource(source string) []*models.LogEntry
	GetRecentLogs(n int) []*models.LogEntry
	Count() (logs, alerts int)
	GetLogsBySeverity(minSeverity models.Severity) []*models.LogEntry
	Clear()
}

// Checkpoint records how far a source has been processed so a crashed or
// interrupted session can resume instead of starting over.
type Checkpoint struct {
	SourcePath  string    `json:"source_path"`
	Offset      int64     `json:"offset"`       // byte offset of the next unread line
	Lines       int       `json:"lines"`        // physical lines consumed
	HeadSHA256  string    `json:"head_sha256"`  // hash of the first bytes, detects file replacement
	EngineState []byte    `json:"engine_state"` // detection.Engine snapshot
	UpdatedAt   time.Time `json:"updated_at"`
}

// Checkpointer is implemented by backends that can persist resume state.
type Checkpointer interface {
	SaveCheckpoint(cp *Checkpoint) error
	LoadCheckpoint(sourcePath string) (*Checkpoint, error) // nil, nil when absent
}

// Ensure MemoryStorage implements Storage
var _ Storage = (*MemoryStorage)(nil)
