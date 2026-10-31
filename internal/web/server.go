package web

import (
	"drishti-nexus/internal/detection"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/pipeline"
	"drishti-nexus/internal/storage"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

//go:embed templates/* static/*
var embeddedFS embed.FS

// Options configure the dashboard.
type Options struct {
	Addr     string // listen address; default 127.0.0.1:8080 (localhost only)
	LogFiles []string
	Pipeline pipeline.Options // config, timezone, audit trail for loaded files
}

type Server struct {
	storage   storage.Storage
	detection *detection.Engine
	config    *models.Config

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

func (s *Server) Start(opts Options) error {
	if len(opts.LogFiles) > 0 {
		popts := opts.Pipeline
		popts.Store = s.storage
		popts.KeepLogs = true
		res, err := pipeline.Run(opts.LogFiles, popts)
		if err != nil {
			log.Printf("Warning: failed to load log file: %v", err)
		}
		if res != nil {
			s.detection = res.Engine
			if ferr := res.Finish(&popts, "ok"); ferr != nil {
				log.Printf("Warning: %v", ferr)
			}
			fmt.Printf("Loaded %d entries, %d alerts\n\n", res.Stats.Entries, res.Stats.Alerts)
		}
	}

	router := mux.NewRouter()

	// API routes
	router.HandleFunc("/api/stats", s.handleStats).Methods("GET")
	router.HandleFunc("/api/logs", s.handleLogs).Methods("GET")
	router.HandleFunc("/api/alerts", s.handleAlerts).Methods("GET")
	router.HandleFunc("/api/ws", s.handleWebSocket)

	// Static files and index from embedded FS
	router.PathPrefix("/static/").Handler(http.FileServer(http.FS(embeddedFS)))
	router.HandleFunc("/", s.handleIndex).Methods("GET")

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
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := embeddedFS.ReadFile("templates/index.html")
	if err != nil {
		http.Error(w, "Failed to load page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write(data)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	logCount, alertCount := s.storage.Count()

	logs := s.storage.GetLogs()

	// Calculate severity distribution
	severityCounts := make(map[string]int)
	for _, log := range logs {
		severityCounts[log.Severity.String()]++
	}

	// Get alert severity distribution
	alerts := s.storage.GetAlerts()
	alertsBySeverity := make(map[string]int)
	for _, alert := range alerts {
		alertsBySeverity[alert.Severity]++
	}

	stats := map[string]interface{}{
		"log_count":          logCount,
		"alert_count":        alertCount,
		"severity_breakdown": severityCounts,
		"alerts_by_severity": alertsBySeverity,
		"timestamp":          time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	logs := s.storage.GetRecentLogs(limit)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := s.storage.GetAlerts()

	// Return most recent alerts first
	reversed := make([]*models.Alert, len(alerts))
	for i, alert := range alerts {
		reversed[len(alerts)-1-i] = alert
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reversed)
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
