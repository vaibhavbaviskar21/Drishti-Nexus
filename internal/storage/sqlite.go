package storage

import (
	"database/sql"
	"drishti-nexus/internal/models"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver: keeps the single static binary (no cgo)
)

// SQLiteStorage is an optional persistent backend. Writes are batched into
// transactions (committed every batchSize operations, before reads, and on
// checkpoint/close) so a crash loses at most the last uncommitted batch, and the
// checkpoint is always committed together with the data it describes.
type SQLiteStorage struct {
	mu      sync.Mutex
	db      *sql.DB
	tx      *sql.Tx
	pending int
	err     error // first write error; surfaced by Err/Close
}

const batchSize = 2000

const schema = `
CREATE TABLE IF NOT EXISTS logs (
	seq      INTEGER PRIMARY KEY AUTOINCREMENT,
	id       TEXT NOT NULL UNIQUE,
	ts       INTEGER NOT NULL,
	source   TEXT NOT NULL,
	severity INTEGER NOT NULL,
	body     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS logs_source ON logs(source);
CREATE TABLE IF NOT EXISTS alerts (
	seq  INTEGER PRIMARY KEY AUTOINCREMENT,
	id   TEXT NOT NULL UNIQUE,
	body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
	source_path  TEXT PRIMARY KEY,
	byte_offset  INTEGER NOT NULL,
	lines        INTEGER NOT NULL,
	head_sha256  TEXT NOT NULL,
	engine_state BLOB,
	updated_at   TEXT NOT NULL
);`

// OpenSQLite opens (creating if needed) a SQLite database at path.
func OpenSQLite(path string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // one writer; serializes access through the driver
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite %s: %w", pragma, err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite schema: %w", err)
	}
	return &SQLiteStorage{db: db}, nil
}

// Err returns the first write error encountered, if any.
func (s *SQLiteStorage) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close commits pending writes and closes the database.
func (s *SQLiteStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitLocked()
	cerr := s.db.Close()
	if s.err != nil {
		return s.err
	}
	return cerr
}

// Abort discards uncommitted writes and closes the database, leaving it exactly
// as a crash would (everything up to the last commit/checkpoint survives).
func (s *SQLiteStorage) Abort() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tx != nil {
		_ = s.tx.Rollback()
		s.tx = nil
	}
	return s.db.Close()
}

// Flush commits pending writes.
func (s *SQLiteStorage) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitLocked()
	return s.err
}

func (s *SQLiteStorage) execLocked(query string, args ...interface{}) {
	if s.tx == nil {
		tx, err := s.db.Begin()
		if err != nil {
			s.fail(err)
			return
		}
		s.tx = tx
	}
	if _, err := s.tx.Exec(query, args...); err != nil {
		s.fail(err)
		return
	}
	s.pending++
	if s.pending >= batchSize {
		s.commitLocked()
	}
}

func (s *SQLiteStorage) commitLocked() {
	if s.tx == nil {
		return
	}
	if err := s.tx.Commit(); err != nil {
		s.fail(err)
	}
	s.tx = nil
	s.pending = 0
}

func (s *SQLiteStorage) fail(err error) {
	if s.err == nil {
		s.err = err
	}
}

func (s *SQLiteStorage) AddLog(entry *models.LogEntry) {
	body, err := json.Marshal(entry)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.fail(err)
		return
	}
	s.execLocked(`INSERT OR REPLACE INTO logs(id, ts, source, severity, body) VALUES(?,?,?,?,?)`,
		entry.ID, entry.Timestamp.UnixNano(), entry.Source, int(entry.Severity), string(body))
}

func (s *SQLiteStorage) AddAlert(alert *models.Alert) {
	s.putAlert(alert)
}

func (s *SQLiteStorage) UpdateAlert(alert *models.Alert) {
	s.putAlert(alert)
}

func (s *SQLiteStorage) putAlert(alert *models.Alert) {
	body, err := json.Marshal(alert)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.fail(err)
		return
	}
	s.execLocked(`INSERT INTO alerts(id, body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`,
		alert.ID, string(body))
}

func (s *SQLiteStorage) queryLogs(query string, args ...interface{}) []*models.LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitLocked()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		s.fail(err)
		return nil
	}
	defer func() { _ = rows.Close() }()
	out := make([]*models.LogEntry, 0)
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			s.fail(err)
			return out
		}
		var e models.LogEntry
		if err := json.Unmarshal([]byte(body), &e); err != nil {
			s.fail(err)
			continue
		}
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		s.fail(err)
	}
	return out
}

func (s *SQLiteStorage) GetLogs() []*models.LogEntry {
	return s.queryLogs(`SELECT body FROM logs ORDER BY seq`)
}

func (s *SQLiteStorage) GetLogsSince(since time.Time) []*models.LogEntry {
	return s.queryLogs(`SELECT body FROM logs WHERE ts >= ? ORDER BY seq`, since.UnixNano())
}

func (s *SQLiteStorage) GetLogsBySource(source string) []*models.LogEntry {
	return s.queryLogs(`SELECT body FROM logs WHERE source = ? ORDER BY seq`, source)
}

func (s *SQLiteStorage) GetRecentLogs(n int) []*models.LogEntry {
	return s.queryLogs(`SELECT body FROM (SELECT seq, body FROM logs ORDER BY seq DESC LIMIT ?) ORDER BY seq`, n)
}

func (s *SQLiteStorage) GetLogsBySeverity(minSeverity models.Severity) []*models.LogEntry {
	return s.queryLogs(`SELECT body FROM logs WHERE severity >= ? ORDER BY seq`, int(minSeverity))
}

func (s *SQLiteStorage) GetAlerts() []*models.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitLocked()
	rows, err := s.db.Query(`SELECT body FROM alerts ORDER BY seq`)
	if err != nil {
		s.fail(err)
		return nil
	}
	defer func() { _ = rows.Close() }()
	out := make([]*models.Alert, 0)
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			s.fail(err)
			return out
		}
		var a models.Alert
		if err := json.Unmarshal([]byte(body), &a); err != nil {
			s.fail(err)
			continue
		}
		out = append(out, &a)
	}
	if err := rows.Err(); err != nil {
		s.fail(err)
	}
	return out
}

func (s *SQLiteStorage) Count() (logs, alerts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitLocked()
	if err := s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM logs), (SELECT COUNT(*) FROM alerts)`).Scan(&logs, &alerts); err != nil {
		s.fail(err)
	}
	return logs, alerts
}

func (s *SQLiteStorage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execLocked(`DELETE FROM logs`)
	s.execLocked(`DELETE FROM alerts`)
	s.execLocked(`DELETE FROM checkpoints`)
	s.commitLocked()
}

// SaveCheckpoint stores resume state and commits it atomically with all data
// written before it.
func (s *SQLiteStorage) SaveCheckpoint(cp *Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execLocked(`INSERT INTO checkpoints(source_path, byte_offset, lines, head_sha256, engine_state, updated_at)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(source_path) DO UPDATE SET byte_offset=excluded.byte_offset, lines=excluded.lines,
			head_sha256=excluded.head_sha256, engine_state=excluded.engine_state, updated_at=excluded.updated_at`,
		cp.SourcePath, cp.Offset, cp.Lines, cp.HeadSHA256, cp.EngineState, cp.UpdatedAt.UTC().Format(time.RFC3339Nano))
	s.commitLocked()
	return s.err
}

// LoadCheckpoint returns the stored checkpoint for sourcePath, or nil if none.
func (s *SQLiteStorage) LoadCheckpoint(sourcePath string) (*Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitLocked()
	cp := &Checkpoint{SourcePath: sourcePath}
	var updated string
	err := s.db.QueryRow(`SELECT byte_offset, lines, head_sha256, engine_state, updated_at FROM checkpoints WHERE source_path = ?`, sourcePath).
		Scan(&cp.Offset, &cp.Lines, &cp.HeadSHA256, &cp.EngineState, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cp.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return cp, nil
}

var (
	_ Storage      = (*SQLiteStorage)(nil)
	_ Checkpointer = (*SQLiteStorage)(nil)
)
