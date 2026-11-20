package web

import (
	"drishti-nexus/internal/audit"
	"drishti-nexus/internal/detection"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/pipeline"
	"drishti-nexus/internal/storage"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

//go:embed templates/* static/*
var embeddedFS embed.FS

// contentSecurityPolicy: everything is served from this binary; log content is
// attacker-controlled, so no inline script, no external origins.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Options configure the dashboard.
type Options struct {
	Addr     string // listen address; default 127.0.0.1:8080 (localhost only)
	LogFiles []string
	Pipeline pipeline.Options // config, timezone, audit trail for loaded files

	// Follow keeps reading lines appended to the single file in LogFiles and
	// pushes updates to open dashboards, until Stop is closed.
	Follow bool
	Stop   <-chan struct{}
}

type Server struct {
	storage   storage.Storage
	detection *detection.Engine
	config    *models.Config

	// Set after evidence is loaded; nil when the dashboard starts empty. The session
	// is kept as a JSON snapshot: while following, the pipeline still owns the object.
	mu          sync.RWMutex
	sessionJSON []byte
	stats       *pipeline.Stats

	// WebSocket clients
	clients   map[*websocket.Conn]bool
	clientsMu sync.RWMutex

	upgrader websocket.Upgrader
}

func NewServer(config *models.Config) *Server {
	store := storage.NewMemoryStorage(config.MaxLogEntries)

	return &Server{
		storage:   store,
		detection: detection.NewEngine(store, config),
		config:    config,
		clients:   make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: sameOrigin,
		},
	}
}

// sameOrigin only accepts WebSocket upgrades from pages served by this dashboard,
// preventing other local web pages from reading log data (CSWSH).
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// Handler returns the dashboard's routes wrapped in the security headers.
func (s *Server) Handler() http.Handler {
	router := mux.NewRouter()

	router.HandleFunc("/api/stats", s.handleStats).Methods("GET")
	router.HandleFunc("/api/logs", s.handleLogs).Methods("GET")
	router.HandleFunc("/api/alerts", s.handleAlerts).Methods("GET")
	router.HandleFunc("/api/alerts/{id}", s.handleAlert).Methods("GET")
	router.HandleFunc("/api/incidents", s.handleIncidents).Methods("GET")
	router.HandleFunc("/api/session", s.handleSession).Methods("GET")
	router.HandleFunc("/api/ws", s.handleWebSocket)

	router.PathPrefix("/static/").Handler(http.FileServer(http.FS(embeddedFS)))
	router.HandleFunc("/", s.handleIndex).Methods("GET")
	return securityHeaders(router)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// Load runs the pipeline over files and keeps its results for the dashboard.
func (s *Server) Load(files []string, popts pipeline.Options) {
	popts.Store = s.storage
	popts.KeepLogs = true
	res, err := pipeline.Run(files, popts)
	if err != nil {
		log.Printf("Warning: failed to load log file: %v", err)
	}
	if res == nil {
		return
	}
	s.detection = res.Engine
	if ferr := res.Finish(&popts, "ok"); ferr != nil {
		log.Printf("Warning: %v", ferr)
	}
	s.setSession(res.Session)
	s.mu.Lock()
	s.stats = res.Stats
	s.mu.Unlock()
	fmt.Printf("Loaded %d entries, %d alerts\n\n", res.Stats.Entries, res.Stats.Alerts)
}

func (s *Server) setSession(sess *audit.Session) {
	data, err := json.Marshal(sess)
	if err != nil {
		log.Printf("Warning: encoding audit session: %v", err)
		return
	}
	s.mu.Lock()
	s.sessionJSON = data
	s.mu.Unlock()
}

// Follow analyses path, then keeps reading lines appended to it, telling open
// dashboards to refresh at most once a second, until stop is closed. The audit
// session is finished (session_end, final hashes) before it returns.
func (s *Server) Follow(path string, popts pipeline.Options, stop <-chan struct{}) error {
	popts.Store, popts.KeepLogs = s.storage, true
	popts.OnStart = func(res *pipeline.Result) error {
		s.setSession(res.Session)
		return nil
	}
	var dirty atomic.Bool
	popts.OnEntry = func(*models.LogEntry, []*models.Alert) { dirty.Store(true) }

	done := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if dirty.Swap(false) {
					s.BroadcastUpdate(map[string]string{"type": "update"})
				}
			}
		}
	}()
	res, err := pipeline.Follow(path, popts, pipeline.FollowOptions{Follow: true, Stop: stop})
	close(done)
	if res == nil {
		return err
	}
	status := "ok"
	if err != nil {
		status = "error: " + err.Error()
	}
	if ferr := res.Finish(&popts, status); err == nil {
		err = ferr
	}
	s.setSession(res.Session)
	return err
}

func (s *Server) Start(opts Options) error {
	if opts.Follow && len(opts.LogFiles) != 1 {
		return fmt.Errorf("-follow takes exactly one log file, got %d", len(opts.LogFiles))
	}
	if len(opts.LogFiles) > 0 && !opts.Follow {
		s.Load(opts.LogFiles, opts.Pipeline)
	}

	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "" {
		host = "localhost"
	}
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║   Drishti Nexus - Web Dashboard           ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Server running at: http://%s\n", net.JoinHostPort(host, port))
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if !opts.Follow {
		return srv.ListenAndServe()
	}
	// Bind before analysing, so a busy port fails before an audit session opens.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("dashboard server: %v", err)
		}
	}()
	fmt.Printf("Following %s (Ctrl+C to stop and close the audit session)\n\n", opts.LogFiles[0])
	err = s.Follow(opts.LogFiles[0], opts.Pipeline, opts.Stop)
	_ = srv.Close()
	return err
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := embeddedFS.ReadFile("templates/index.html")
	if err != nil {
		http.Error(w, "Failed to load page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// countItem is one row of a ranked breakdown.
type countItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func topN(m map[string]int, n int) []countItem {
	out := make([]countItem, 0, len(m))
	for k, v := range m {
		out = append(out, countItem{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	logCount, alertCount := s.storage.Count()

	severityCounts := make(map[string]int)
	sources := make(map[string]int)
	quality := make(map[string]int)
	for _, e := range s.storage.GetLogs() {
		severityCounts[e.Severity.String()]++
		sources[e.Source]++
		quality[e.ParseQuality]++
	}

	alerts := s.storage.GetAlerts()
	alertsBySeverity := make(map[string]int)
	alertsByRule := make(map[string]int)
	incidents := make(map[string]bool)
	for _, a := range alerts {
		alertsBySeverity[a.Severity]++
		alertsByRule[a.RuleName]++
		incidents[incidentKey(a)] = true
	}

	lines := logCount
	s.mu.RLock()
	if s.stats != nil {
		// Pipeline totals cover every line read, including entries evicted from memory.
		lines, quality = s.stats.Lines, s.stats.ParseQuality
	}
	s.mu.RUnlock()
	entries := 0
	for _, n := range quality {
		entries += n
	}
	cleanPct := 0.0
	if entries > 0 {
		cleanPct = float64(quality[models.QualityClean]) * 100 / float64(entries)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"log_count":          logCount,
		"alert_count":        alertCount,
		"incident_count":     len(incidents),
		"lines":              lines,
		"entries":            entries,
		"parse_quality":      quality,
		"clean_parse_pct":    cleanPct,
		"severity_breakdown": severityCounts,
		"alerts_by_severity": alertsBySeverity,
		"alerts_by_rule":     topN(alertsByRule, 20),
		"top_sources":        topN(sources, 10),
		"timestamp":          time.Now(),
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.storage.GetRecentLogs(200))
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := s.storage.GetAlerts()

	// Most recent first
	reversed := make([]*models.Alert, len(alerts))
	for i, alert := range alerts {
		reversed[len(alerts)-1-i] = alert
	}
	writeJSON(w, http.StatusOK, reversed)
}

// evidenceLine is a cited log entry resolved to its raw text.
type evidenceLine struct {
	ID     string `json:"id"`
	Found  bool   `json:"found"` // false when the entry was evicted from memory
	Source string `json:"source,omitempty"`
	Raw    string `json:"raw_log,omitempty"`
}

type alertDetail struct {
	*models.Alert
	Evidence []evidenceLine `json:"evidence"`
	Hosts    []string       `json:"hosts"`
}

// logIndex maps entry IDs to entries.
// shortcut: rebuilt per request by scanning memory; add a storage lookup by ID if it gets slow.
func (s *Server) logIndex() map[string]*models.LogEntry {
	logs := s.storage.GetLogs()
	idx := make(map[string]*models.LogEntry, len(logs))
	for _, e := range logs {
		idx[e.ID] = e
	}
	return idx
}

func hostsOf(a *models.Alert, idx map[string]*models.LogEntry) []string {
	set := map[string]bool{}
	for _, id := range a.RelatedLogs {
		if e := idx[id]; e != nil && e.Source != "" {
			set[e.Source] = true
		}
	}
	if src, ok := a.Details["source"].(string); ok && src != "" {
		set[src] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	for _, a := range s.storage.GetAlerts() {
		if a.ID != id {
			continue
		}
		idx := s.logIndex()
		ev := make([]evidenceLine, 0, len(a.RelatedLogs))
		for _, lid := range a.RelatedLogs {
			line := evidenceLine{ID: lid}
			if e := idx[lid]; e != nil {
				line.Found, line.Source, line.Raw = true, e.Source, e.RawLog
			}
			ev = append(ev, line)
		}
		writeJSON(w, http.StatusOK, alertDetail{Alert: a, Evidence: ev, Hosts: hostsOf(a, idx)})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
}

// incident groups alerts that share an IncidentID.
type incident struct {
	ID          string          `json:"id"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
	MaxSeverity string          `json:"max_severity"`
	Hosts       []string        `json:"hosts"`
	Techniques  []string        `json:"techniques"`
	AlertCount  int             `json:"alert_count"`
	Alerts      []*models.Alert `json:"alerts"` // chronological timeline
}

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// incidentKey: alerts without an incident ID stand alone.
func incidentKey(a *models.Alert) string {
	if a.IncidentID != "" {
		return a.IncidentID
	}
	return a.ID
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	idx := s.logIndex()
	byID := map[string]*incident{}
	hosts := map[string]map[string]bool{}
	techs := map[string]map[string]bool{}
	order := []*incident{}
	for _, a := range s.storage.GetAlerts() {
		key := incidentKey(a)
		inc := byID[key]
		if inc == nil {
			inc = &incident{ID: key, FirstSeen: a.Timestamp, LastSeen: a.LastSeen}
			byID[key], hosts[key], techs[key] = inc, map[string]bool{}, map[string]bool{}
			order = append(order, inc)
		}
		inc.Alerts = append(inc.Alerts, a)
		if a.Timestamp.Before(inc.FirstSeen) {
			inc.FirstSeen = a.Timestamp
		}
		if a.LastSeen.After(inc.LastSeen) {
			inc.LastSeen = a.LastSeen
		}
		if severityRank[a.Severity] > severityRank[inc.MaxSeverity] {
			inc.MaxSeverity = a.Severity
		}
		for _, h := range hostsOf(a, idx) {
			hosts[key][h] = true
		}
		if a.MITRETechniqueID != "" {
			techs[key][a.MITRETechniqueID] = true
		}
	}
	for _, inc := range order {
		inc.AlertCount = len(inc.Alerts)
		inc.Hosts, inc.Techniques = sortedSet(hosts[inc.ID]), sortedSet(techs[inc.ID])
		sort.SliceStable(inc.Alerts, func(i, j int) bool { return inc.Alerts[i].Timestamp.Before(inc.Alerts[j].Timestamp) })
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].LastSeen.After(order[j].LastSeen) })
	writeJSON(w, http.StatusOK, order)
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// handleSession exposes the chain-of-custody record; JSON null when nothing was loaded.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	data := s.sessionJSON
	s.mu.RUnlock()
	if data == nil {
		data = []byte("null")
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(data, '\n'))
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, conn)
		s.clientsMu.Unlock()
		_ = conn.Close()
	}()

	// Keep connection alive
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (s *Server) BroadcastUpdate(data interface{}) {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for client := range s.clients {
		if err := client.WriteJSON(data); err != nil {
			log.Printf("WebSocket write error: %v", err)
		}
	}
}
