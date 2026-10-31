package storage

import (
	"drishti-nexus/internal/models"
	"log"
	"sync"
	"time"
)

// MemoryStorage provides in-memory storage for log entries and alerts
type MemoryStorage struct {
	mu         sync.RWMutex
	logs       []*models.LogEntry
	alerts     []*models.Alert
	maxEntries int

	// Indexes for fast lookups
	logsByTime   map[string][]*models.LogEntry // time bucket -> logs
	logsBySource map[string][]*models.LogEntry // source -> logs
}

// NewMemoryStorage creates a new in-memory storage instance
func NewMemoryStorage(maxEntries int) *MemoryStorage {
	return &MemoryStorage{
		logs:         make([]*models.LogEntry, 0, maxEntries),
		alerts:       make([]*models.Alert, 0),
		maxEntries:   maxEntries,
		logsByTime:   make(map[string][]*models.LogEntry),
		logsBySource: make(map[string][]*models.LogEntry),
	}
}

// AddLog adds a log entry to storage
func (s *MemoryStorage) AddLog(entry *models.LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check capacity and evict oldest if needed
	if len(s.logs) >= s.maxEntries {
		s.evictOldest()
	}

	s.logs = append(s.logs, entry)

	// Update indexes
	timeBucket := entry.Timestamp.Format("2006-01-02T15")
	s.logsByTime[timeBucket] = append(s.logsByTime[timeBucket], entry)
	s.logsBySource[entry.Source] = append(s.logsBySource[entry.Source], entry)
}

// AddAlert adds an alert to storage
func (s *MemoryStorage) AddAlert(alert *models.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.alerts = append(s.alerts, alert)
}

// UpdateAlert is a no-op: the engine mutates the stored alert pointer in place.
func (s *MemoryStorage) UpdateAlert(alert *models.Alert) {}

// GetLogs returns all logs
func (s *MemoryStorage) GetLogs() []*models.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.LogEntry, len(s.logs))
	copy(result, s.logs)
	return result
}

// GetAlerts returns all alerts
func (s *MemoryStorage) GetAlerts() []*models.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.Alert, len(s.alerts))
	copy(result, s.alerts)
	return result
}

// GetLogsSince returns logs since a given time
func (s *MemoryStorage) GetLogsSince(since time.Time) []*models.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.LogEntry, 0)
	for _, log := range s.logs {
		if log.Timestamp.After(since) || log.Timestamp.Equal(since) {
			result = append(result, log)
		}
	}
	return result
}

// GetLogsBySource returns logs from a specific source
func (s *MemoryStorage) GetLogsBySource(source string) []*models.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if logs, ok := s.logsBySource[source]; ok {
		result := make([]*models.LogEntry, len(logs))
		copy(result, logs)
		return result
	}
	return []*models.LogEntry{}
}

// GetRecentLogs returns the N most recent logs
func (s *MemoryStorage) GetRecentLogs(n int) []*models.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if n > len(s.logs) {
		n = len(s.logs)
	}

	result := make([]*models.LogEntry, n)
	copy(result, s.logs[len(s.logs)-n:])
	return result
}

// Count returns statistics
func (s *MemoryStorage) Count() (logs, alerts int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.logs), len(s.alerts)
}

// GetLogsBySeverity returns logs of a specific severity or higher
func (s *MemoryStorage) GetLogsBySeverity(minSeverity models.Severity) []*models.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.LogEntry, 0)
	for _, log := range s.logs {
		if log.Severity >= minSeverity {
			result = append(result, log)
		}
	}
	return result
}

// evictOldest removes the oldest 20% of logs
func (s *MemoryStorage) evictOldest() {
	evictCount := s.maxEntries / 5
	if evictCount < 1 {
		evictCount = 1
	}

	log.Printf("⚠ Memory limit reached (%d logs). Evicting oldest %d entries (LRU policy)", s.maxEntries, evictCount)

	// Remove from main slice
	evicted := s.logs[:evictCount]
	s.logs = s.logs[evictCount:]

	// Clean up indexes
	for _, entry := range evicted {
		timeBucket := entry.Timestamp.Format("2006-01-02T15")
		if logs, ok := s.logsByTime[timeBucket]; ok {
			s.logsByTime[timeBucket] = removeEntry(logs, entry)
		}

		if logs, ok := s.logsBySource[entry.Source]; ok {
			s.logsBySource[entry.Source] = removeEntry(logs, entry)
		}
	}
}

func removeEntry(slice []*models.LogEntry, entry *models.LogEntry) []*models.LogEntry {
	result := make([]*models.LogEntry, 0, len(slice))
	for _, e := range slice {
		if e.ID != entry.ID {
			result = append(result, e)
		}
	}
	return result
}

// Clear removes all data
func (s *MemoryStorage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logs = make([]*models.LogEntry, 0, s.maxEntries)
	s.alerts = make([]*models.Alert, 0)
	s.logsByTime = make(map[string][]*models.LogEntry)
	s.logsBySource = make(map[string][]*models.LogEntry)
}
