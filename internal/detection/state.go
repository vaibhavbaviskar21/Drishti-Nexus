package detection

import (
	"drishti-nexus/internal/models"
	"encoding/json"
	"fmt"
	"time"
)

// State is the engine's mutable tracking state. It is plain data so it can be
// checkpointed (SQLite backend) and restored after a crash without losing
// in-flight windows, open alerts or incident numbering.
type State struct {
	Version     int       `json:"version"`
	AlertSeq    int       `json:"alert_seq"`
	IncidentSeq int       `json:"incident_seq"`
	Processed   int       `json:"processed"`
	Latest      time.Time `json:"latest"`

	Failures      map[string][]failureMark  `json:"failures"`
	AttemptGroups map[string]*attemptGroup  `json:"attempt_groups"`
	Open          map[string]*openAlert     `json:"open_alerts"`
	Incidents     map[string]*incidentState `json:"incidents"`
	Compromised   map[string]*compromise    `json:"compromised"` // user → latest brute-force success
}

const stateVersion = 1

type failureMark struct {
	At time.Time `json:"at"`
	N  int       `json:"n"`
	ID string    `json:"id"` // evidence entry ID
}

type attemptGroup struct {
	Start time.Time       `json:"start"`
	Kinds map[string]bool `json:"kinds"`
}

type openAlert struct {
	AlertID  string    `json:"alert_id"`
	LastSeen time.Time `json:"last_seen"`
}

// compromise is a brute-force success: the account's password is presumed known to the attacker.
type compromise struct {
	Host     string    `json:"host"`
	Key      string    `json:"key"` // correlation key of the brute-force alert
	At       time.Time `json:"at"`
	Evidence string    `json:"evidence"` // entry ID of the successful login
}

type incidentState struct {
	ID       string    `json:"id"`
	LastSeen time.Time `json:"last_seen"`
}

func newState() *State {
	return &State{
		Version:       stateVersion,
		Failures:      make(map[string][]failureMark),
		AttemptGroups: make(map[string]*attemptGroup),
		Open:          make(map[string]*openAlert),
		Incidents:     make(map[string]*incidentState),
		Compromised:   make(map[string]*compromise),
	}
}

// Snapshot serializes the engine state.
func (e *Engine) Snapshot() ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return json.Marshal(e.state)
}

// Restore replaces the engine state with a snapshot taken by Snapshot. Open
// alerts are re-attached from storage so later repeats keep aggregating into them.
func (e *Engine) Restore(data []byte) error {
	st := newState()
	if err := json.Unmarshal(data, st); err != nil {
		return fmt.Errorf("decode engine state: %w", err)
	}
	if st.Version != stateVersion {
		return fmt.Errorf("engine state version %d not supported (want %d)", st.Version, stateVersion)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = st
	e.alerts = make(map[string]*models.Alert)
	byID := make(map[string]*models.Alert)
	for _, a := range e.storage.GetAlerts() {
		byID[a.ID] = a
	}
	for _, k := range sortedKeys(st.Open) {
		o := st.Open[k]
		if a, ok := byID[o.AlertID]; ok {
			e.alerts[o.AlertID] = a
		} else {
			delete(st.Open, k)
		}
	}
	return nil
}
