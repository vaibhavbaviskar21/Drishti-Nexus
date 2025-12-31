package web

import (
	"bufio"
	"drishti-nexus/internal/detection"
	"drishti-nexus/internal/models"
	"drishti-nexus/internal/parser"
	"drishti-nexus/internal/storage"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

//go:embed templates/* static/*
var embeddedFS embed.FS

type Server struct {
	storage   *storage.MemoryStorage
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
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for localhost
			},
		},
	}
}

func (s *Server) Start(port int, logFile string) error {
	// Load logs if file provided
	if logFile != "" {
		if err := s.loadLogFile(logFile); err != nil {
			log.Printf("Warning: failed to load log file: %v", err)
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

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("\n╔═══════════════════════════════════════════╗\n")
	fmt.Printf("║   Drishti Nexus - Web Dashboard          ║\n")
	fmt.Printf("╚═══════════════════════════════════════════╝\n\n")
	fmt.Printf("Server running at: http://localhost%s\n", addr)
	fmt.Printf("Press Ctrl+C to stop\n\n")

	return http.ListenAndServe(addr, router)
}

func (s *Server) loadLogFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	parserRegistry := parser.NewParserRegistry()
	scanner := bufio.NewScanner(file)
	count := 0

	fmt.Printf("Loading logs from: %s\n", filename)

	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parserRegistry.Parse(line)
		if err != nil || entry == nil {
			continue
		}

		s.storage.AddLog(entry)
		s.detection.AnalyzeLog(entry)
		count++

		if count%10000 == 0 {
			fmt.Printf("\rLoaded %d logs...", count)
		}
	}

	fmt.Printf("\rLoaded %d logs total\n\n", count)
	return scanner.Err()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := embeddedFS.ReadFile("templates/index.html")
	if err != nil {
		http.Error(w, "Failed to load page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(data)
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
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	logs := s.storage.GetRecentLogs(limit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := s.storage.GetAlerts()

	// Return most recent alerts first
	reversed := make([]*models.Alert, len(alerts))
	for i, alert := range alerts {
		reversed[len(alerts)-1-i] = alert
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reversed)
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
		conn.Close()
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
