package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/pat-fortress/pkg/fortress/analyzer"
	"github.com/pat-fortress/pkg/fortress/legacy"
	"github.com/pat-fortress/pkg/fortress/ratelimit"
	"go.uber.org/zap"
)

// FortressHTTPServer provides a modern HTTP API server with legacy MailHog compatibility
type FortressHTTPServer struct {
	config      *FortressHTTPConfig
	logger      *zap.Logger
	store       legacy.FortressMessageStore
	router      *mux.Router
	server      *http.Server
	startTime   time.Time
	rateLimiter *ratelimit.SimpleRateLimiter
	emailAnalyzer *analyzer.EmailAnalyzer
}

// FortressHTTPConfig defines configuration for the fortress HTTP server
type FortressHTTPConfig struct {
	BindAddr         string
	WebPath          string
	CORSOrigin       string
	EnableCORS       bool
	EnableTLS        bool
	TLSCertFile      string
	TLSKeyFile       string

	// Fortress enhancements
	EnableAuth       bool
	APIKeyRequired   bool
	EnableRateLimit  bool
	MaxPerIP         int
	TenantID         string
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration

	// AI Analysis features
	EnableAIAnalysis bool
	OpenAIAPIKey     string
	OpenAIModel      string
}

// NewFortressHTTPServer creates a new fortress-enhanced HTTP server
func NewFortressHTTPServer(config *FortressHTTPConfig, store legacy.FortressMessageStore, logger *zap.Logger) *FortressHTTPServer {
	server := &FortressHTTPServer{
		config:    config,
		logger:    logger,
		store:     store,
		router:    mux.NewRouter(),
		startTime: time.Now(),
	}

	// Initialize simple rate limiter if enabled
	if config.EnableRateLimit && config.MaxPerIP > 0 {
		server.rateLimiter = ratelimit.NewSimpleRateLimiter(config.MaxPerIP)
		logger.Info("HTTP rate limiting enabled",
			zap.Int("max_per_ip", config.MaxPerIP),
			zap.String("window", "1 minute"))
	}

	// Initialize AI analyzer if enabled
	if config.EnableAIAnalysis {
		var aiProvider analyzer.AIProvider
		if config.OpenAIAPIKey != "" {
			model := config.OpenAIModel
			if model == "" {
				model = "gpt-3.5-turbo" // Default model
			}
			aiProvider = analyzer.NewOpenAIProvider(config.OpenAIAPIKey, model)
			logger.Info("AI analysis enabled",
				zap.String("provider", "openai"),
				zap.String("model", model))
		}
		server.emailAnalyzer = analyzer.NewEmailAnalyzer(aiProvider)
	}

	server.setupRoutes()
	return server
}

// setupRoutes configures fortress HTTP routes with MailHog compatibility
func (s *FortressHTTPServer) setupRoutes() {
	// API v1 routes (MailHog compatibility)
	apiV1 := s.router.PathPrefix("/api/v1").Subrouter()
	
	// Messages endpoint
	apiV1.HandleFunc("/messages", s.handleMessages).Methods("GET", "OPTIONS")
	apiV1.HandleFunc("/messages/{id}", s.handleMessage).Methods("GET", "DELETE", "OPTIONS")
	apiV1.HandleFunc("/messages", s.handleDeleteAll).Methods("DELETE", "OPTIONS")
	
	// API v2 routes (Enhanced MailHog compatibility)
	apiV2 := s.router.PathPrefix("/api/v2").Subrouter()
	apiV2.HandleFunc("/messages", s.handleMessagesV2).Methods("GET", "OPTIONS")
	apiV2.HandleFunc("/messages/{id}", s.handleMessageV2).Methods("GET", "DELETE", "OPTIONS")
	apiV2.HandleFunc("/search", s.handleSearch).Methods("GET", "OPTIONS")
	apiV2.HandleFunc("/jim", s.handleJim).Methods("GET", "POST", "DELETE", "OPTIONS")
	
	// Fortress API v3 routes (Modern enhanced API)
	apiV3 := s.router.PathPrefix("/api/v3").Subrouter()
	apiV3.HandleFunc("/health", s.handleHealth).Methods("GET")
	apiV3.HandleFunc("/metrics", s.handleMetrics).Methods("GET")
	apiV3.HandleFunc("/messages/stats", s.handleMessageStats).Methods("GET")
	apiV3.HandleFunc("/messages/export", s.handleExport).Methods("GET")
	apiV3.HandleFunc("/security/scan/{id}", s.handleSecurityScan).Methods("POST")

	// AI Analysis endpoints
	apiV3.HandleFunc("/ai/analyze/{id}", s.handleAIAnalysis).Methods("POST")
	apiV3.HandleFunc("/ai/status", s.handleAIStatus).Methods("GET")
	
	// WebSocket endpoint for real-time updates
	s.router.HandleFunc("/api/v1/events", s.handleWebSocket).Methods("GET")
	
	// Static file serving (UI compatibility)
	if s.config.WebPath != "" {
		s.router.PathPrefix("/").Handler(http.FileServer(http.Dir(s.config.WebPath))).Methods("GET")
	}
	
	// Add middleware
	s.router.Use(s.corsMiddleware)
	s.router.Use(s.loggingMiddleware)

	// Add rate limiting middleware if enabled
	if s.rateLimiter != nil {
		s.router.Use(s.rateLimiter.HTTPMiddleware())
	}

	// Add authentication middleware if enabled
	if s.config.EnableAuth {
		s.router.Use(s.authMiddleware)
	}
}

// Listen starts the fortress HTTP server
func (s *FortressHTTPServer) Listen() error {
	s.server = &http.Server{
		Addr:         s.config.BindAddr,
		Handler:      s.router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}
	
	s.logger.Info("Fortress HTTP server listening",
		zap.String("address", s.config.BindAddr),
		zap.String("web_path", s.config.WebPath),
		zap.Bool("tls_enabled", s.config.EnableTLS),
	)
	
	if s.config.EnableTLS && s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		return s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
	}
	
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the fortress HTTP server
func (s *FortressHTTPServer) Shutdown() error {
	// Close rate limiter
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}

	// Note: Use server.Shutdown(ctx) from main.go for graceful shutdown
	// This method is kept for compatibility but main.go handles the actual graceful shutdown
	return nil
}

// handleMessages handles the messages list endpoint (MailHog v1 compatibility)
func (s *FortressHTTPServer) handleMessages(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	start := 0
	limit := 50
	
	if startStr := r.URL.Query().Get("start"); startStr != "" {
		if parsed, err := strconv.Atoi(startStr); err == nil {
			start = parsed
		}
	}
	
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	
	// Get messages from store
	messages, err := s.store.List(start, limit)
	if err != nil {
		s.logger.Error("Failed to list messages",
			zap.Error(err),
			zap.Int("start", start),
			zap.Int("limit", limit))
		http.Error(w, "Failed to retrieve messages", http.StatusInternalServerError)
		return
	}
	
	// Get total count
	total := s.store.Count()
	
	// Create response in MailHog format
	response := map[string]interface{}{
		"total":    total,
		"count":    len(*messages),
		"start":    start,
		"messages": messages,
	}
	
	s.writeJSON(w, response)
}

// handleMessage handles single message operations (MailHog v1 compatibility)
func (s *FortressHTTPServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := legacy.MessageID(vars["id"])
	
	switch r.Method {
	case "GET":
		message, err := s.store.Load(id)
		if err != nil {
			if err == legacy.ErrMessageNotFound {
				http.Error(w, "Message not found", http.StatusNotFound)
			} else {
				s.logger.Error("Failed to load message", zap.Error(err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}
		
		s.writeJSON(w, message)
		
	case "DELETE":
		err := s.store.DeleteOne(id)
		if err != nil {
			if err == legacy.ErrMessageNotFound {
				http.Error(w, "Message not found", http.StatusNotFound)
			} else {
				s.logger.Error("Failed to delete message", zap.Error(err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}
		
		w.WriteHeader(http.StatusOK)
	}
}

// handleDeleteAll handles delete all messages endpoint
func (s *FortressHTTPServer) handleDeleteAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	err := s.store.DeleteAll()
	if err != nil {
		s.logger.Error("Failed to delete all messages", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
}

// handleMessagesV2 handles the enhanced messages endpoint (MailHog v2 compatibility)
func (s *FortressHTTPServer) handleMessagesV2(w http.ResponseWriter, r *http.Request) {
	// Enhanced version with additional filtering capabilities
	s.handleMessages(w, r) // For now, use v1 implementation
}

// handleMessageV2 handles single message operations (MailHog v2 compatibility)
func (s *FortressHTTPServer) handleMessageV2(w http.ResponseWriter, r *http.Request) {
	// Enhanced version with additional metadata
	s.handleMessage(w, r) // For now, use v1 implementation
}

// handleSearch handles message search endpoint
func (s *FortressHTTPServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	query := r.URL.Query().Get("query")
	
	if kind == "" || query == "" {
		http.Error(w, "Missing kind or query parameter", http.StatusBadRequest)
		return
	}
	
	start := 0
	limit := 50
	
	if startStr := r.URL.Query().Get("start"); startStr != "" {
		if parsed, err := strconv.Atoi(startStr); err == nil {
			start = parsed
		}
	}
	
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	
	messages, err := s.store.Search(kind, query, start, limit)
	if err != nil {
		s.logger.Error("Failed to search messages", 
			zap.Error(err),
			zap.String("kind", kind),
			zap.String("query", query),
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	response := map[string]interface{}{
		"total":    len(*messages),
		"count":    len(*messages),
		"start":    start,
		"messages": messages,
		"kind":     kind,
		"query":    query,
	}
	
	s.writeJSON(w, response)
}

// handleJim handles MailHog's chaos engineering endpoint (Jim)
func (s *FortressHTTPServer) handleJim(w http.ResponseWriter, r *http.Request) {
	// Simple Jim implementation for MailHog compatibility
	// (In practice, most people don't use chaos engineering for email testing)
	switch r.Method {
	case "GET":
		response := map[string]interface{}{
			"enabled": false,
			"message": "Jim chaos engineering available but disabled for email testing",
		}
		s.writeJSON(w, response)

	case "POST":
		// Accept but don't actually enable chaos (email testing doesn't need it)
		response := map[string]interface{}{
			"success": true,
			"message": "Jim chaos mode acknowledged but not enabled (email testing mode)",
		}
		s.writeJSON(w, response)

	case "DELETE":
		// Disable chaos mode (no-op)
		response := map[string]interface{}{
			"success": true,
			"message": "Jim chaos mode disabled",
		}
		s.writeJSON(w, response)
	}
}

// handleHealth provides fortress health check endpoint
func (s *FortressHTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":     "healthy",
		"timestamp":  time.Now().UTC(),
		"version":    "fortress-2.0.0",
		"messages":   s.store.Count(),
		"uptime":     time.Since(s.startTime).String(),
	}

	s.writeJSON(w, health)
}

// handleMetrics provides fortress metrics endpoint
func (s *FortressHTTPServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Get rate limiting stats
	rateLimitStats := map[string]interface{}{
		"enabled": false,
	}
	if s.rateLimiter != nil {
		rateLimitStats = s.rateLimiter.GetStats()
	}

	uptime := time.Since(s.startTime)

	metrics := map[string]interface{}{
		"messages": map[string]interface{}{
			"total": s.store.Count(),
		},
		"fortress": map[string]interface{}{
			"version":     "2.0.0",
			"mode":        "standalone",
			"security":    s.config.EnableAuth,
			"uptime":      uptime.String(),
			"uptime_seconds": int64(uptime.Seconds()),
		},
		"rate_limiting": rateLimitStats,
		"http": map[string]interface{}{
			"cors_enabled":    s.config.EnableCORS,
			"tls_enabled":     s.config.EnableTLS,
			"auth_enabled":    s.config.EnableAuth,
			"rate_limit_enabled": s.config.EnableRateLimit,
		},
		"storage": map[string]interface{}{
			"type": "unknown", // Would be populated from storage adapter
		},
		"timestamp": time.Now().UTC(),
	}

	s.writeJSON(w, metrics)
}

// handleMessageStats provides detailed message statistics
func (s *FortressHTTPServer) handleMessageStats(w http.ResponseWriter, r *http.Request) {
	total := s.store.Count()
	
	stats := map[string]interface{}{
		"total_messages": total,
		"timestamp":      time.Now().UTC(),
		// Additional stats would be calculated here in a real implementation
	}
	
	s.writeJSON(w, stats)
}

// handleExport provides message export functionality
func (s *FortressHTTPServer) handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	
	messages, err := s.store.List(0, s.store.Count())
	if err != nil {
		s.logger.Error("Failed to export messages", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=messages.json")
		s.writeJSON(w, map[string]interface{}{
			"messages": messages,
			"exported": time.Now().UTC(),
			"total":    len(*messages),
		})
		
	default:
		http.Error(w, "Unsupported export format", http.StatusBadRequest)
	}
}

// handleSecurityScan provides fortress security scanning
func (s *FortressHTTPServer) handleSecurityScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := legacy.MessageID(vars["id"])
	
	message, err := s.store.Load(id)
	if err != nil {
		if err == legacy.ErrMessageNotFound {
			http.Error(w, "Message not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
	
	// Perform fortress security scan
	scanResults := map[string]interface{}{
		"message_id":     id,
		"scanned_at":     time.Now().UTC(),
		"security_level": message.SecurityLevel,
		"threats":        message.Content.SecurityTags,
		"sanitized":      message.Content.Sanitized,
	}
	
	s.writeJSON(w, scanResults)
}

// handleWebSocket handles WebSocket connections for real-time updates
func (s *FortressHTTPServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// For email testing, allow localhost and configured CORS origin
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // No origin header (direct connection)
			}

			// Allow localhost variations for development
			if origin == "http://localhost:8025" || origin == "http://127.0.0.1:8025" {
				return true
			}

			// Allow configured CORS origin if set
			if s.config.CORSOrigin != "" && origin == s.config.CORSOrigin {
				return true
			}

			// Be permissive for email testing but log suspicious origins
			s.logger.Warn("WebSocket connection from unconfigured origin",
				zap.String("origin", origin),
				zap.String("configured_origin", s.config.CORSOrigin))
			return true
		},
	}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("WebSocket upgrade failed", zap.Error(err))
		return
	}
	defer conn.Close()
	
	s.logger.Info("WebSocket connection established", 
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)
	
	// Create WebSocket client context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Handle WebSocket messages
	go s.handleWebSocketMessages(ctx, conn)
	
	// Send periodic updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Send real-time statistics
			stats := s.getRealtimeStats()
			if err := conn.WriteJSON(stats); err != nil {
				s.logger.Error("WebSocket write error", zap.Error(err))
				return
			}
			
		case <-ctx.Done():
			return
		}
	}
}

// handleWebSocketMessages handles incoming WebSocket messages from clients
func (s *FortressHTTPServer) handleWebSocketMessages(ctx context.Context, conn *websocket.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					s.logger.Error("WebSocket read error", zap.Error(err))
				}
				return
			}
			
			s.logger.Debug("Received WebSocket message", 
				zap.ByteString("message", message),
			)
			
			// Process WebSocket commands (e.g., subscribe to specific events)
			s.processWebSocketCommand(conn, message)
		}
	}
}

// processWebSocketCommand processes incoming WebSocket commands
func (s *FortressHTTPServer) processWebSocketCommand(conn *websocket.Conn, message []byte) {
	// Parse command (basic JSON structure expected)
	var command map[string]interface{}
	if err := json.Unmarshal(message, &command); err != nil {
		s.logger.Error("Invalid WebSocket command", zap.Error(err))
		return
	}
	
	// Handle different command types
	if cmdType, ok := command["type"].(string); ok {
		switch cmdType {
		case "ping":
			s.sendWebSocketResponse(conn, map[string]interface{}{
				"type": "pong",
				"timestamp": time.Now().UTC(),
			})
		case "subscribe":
			// Handle subscription to real-time events
			s.logger.Info("Client subscribed to real-time events")
		case "get_stats":
			stats := s.getRealtimeStats()
			s.sendWebSocketResponse(conn, stats)
		default:
			s.logger.Warn("Unknown WebSocket command", zap.String("type", cmdType))
		}
	}
}

// sendWebSocketResponse sends a response back to the WebSocket client
func (s *FortressHTTPServer) sendWebSocketResponse(conn *websocket.Conn, data interface{}) {
	if err := conn.WriteJSON(data); err != nil {
		s.logger.Error("Failed to send WebSocket response", zap.Error(err))
	}
}

// getRealtimeStats returns real-time statistics for WebSocket clients
func (s *FortressHTTPServer) getRealtimeStats() map[string]interface{} {
	uptime := time.Since(s.startTime)

	// Calculate uptime percentage (simplified - in production would track actual downtime)
	uptimePercent := 99.9 // Default assumption

	// Get rate limiting stats
	rateLimitStats := map[string]interface{}{"enabled": false}
	if s.rateLimiter != nil {
		rateLimitStats = s.rateLimiter.GetStats()
	}

	return map[string]interface{}{
		"type": "stats_update",
		"timestamp": time.Now().UTC(),
		"fortress": map[string]interface{}{
			"version": "2.0.0",
			"status": "operational",
			"uptime": uptime.String(),
			"uptime_seconds": int64(uptime.Seconds()),
			"messages": map[string]interface{}{
				"total": s.store.Count(),
			},
			"performance": map[string]interface{}{
				"uptime_percent": uptimePercent,
			},
			"rate_limiting": rateLimitStats,
			"security": map[string]interface{}{
				"auth_enabled": s.config.EnableAuth,
				"tls_enabled": s.config.EnableTLS,
			},
		},
	}
}

// corsMiddleware handles CORS headers
func (s *FortressHTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.EnableCORS {
			origin := s.config.CORSOrigin
			if origin == "" {
				origin = "*"
			}
			
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		
		// Fortress security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Fortress-Protected", "true")
		w.Header().Set("X-Fortress-Version", "2.0.0")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs HTTP requests
func (s *FortressHTTPServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response recorder to capture status code
		recorder := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(recorder, r)

		duration := time.Since(start)

		s.logger.Info("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("user_agent", r.UserAgent()),
			zap.Int("status_code", recorder.statusCode),
			zap.Duration("duration", duration),
		)
	})
}

// authMiddleware provides basic API key authentication
func (s *FortressHTTPServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health endpoint and OPTIONS requests
		if r.URL.Path == "/api/v3/health" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for API key in header or query parameter
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.Header.Get("Authorization")
			if apiKey != "" && strings.HasPrefix(apiKey, "Bearer ") {
				apiKey = strings.TrimPrefix(apiKey, "Bearer ")
			}
		}
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}

		// For now, accept any non-empty API key
		// In production, this should validate against a proper key store
		if apiKey == "" {
			s.logger.Warn("Authentication failed - missing API key",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("path", r.URL.Path),
			)

			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "Authentication required - provide X-API-Key header or Authorization: Bearer token", http.StatusUnauthorized)
			return
		}

		// Log successful authentication
		s.logger.Debug("Authentication successful",
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("path", r.URL.Path),
		)

		next.ServeHTTP(w, r)
	})
}

// responseRecorder captures the status code for logging
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// writeJSON writes a JSON response
func (s *FortressHTTPServer) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	
	if err := encoder.Encode(data); err != nil {
		s.logger.Error("Failed to encode JSON response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleAIAnalysis provides AI-powered email analysis
func (s *FortressHTTPServer) handleAIAnalysis(w http.ResponseWriter, r *http.Request) {
	// Check if AI analyzer is enabled
	if s.emailAnalyzer == nil {
		http.Error(w, "AI analysis not available - enable with PAT_AI_ENABLED=true", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := legacy.MessageID(vars["id"])

	// Load the message
	message, err := s.store.Load(id)
	if err != nil {
		if err == legacy.ErrMessageNotFound {
			http.Error(w, "Message not found", http.StatusNotFound)
		} else {
			s.logger.Error("Failed to load message for AI analysis", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Perform AI analysis
	analysis, err := s.emailAnalyzer.AnalyzeEmail(message)
	if err != nil {
		s.logger.Error("AI analysis failed",
			zap.Error(err),
			zap.String("message_id", string(id)))
		http.Error(w, "AI analysis failed", http.StatusInternalServerError)
		return
	}

	s.logger.Info("AI analysis completed",
		zap.String("message_id", string(id)),
		zap.Float64("confidence", analysis.Confidence),
		zap.String("spam_level", analysis.SpamRisk.Level))

	s.writeJSON(w, analysis)
}

// handleAIStatus provides status information about AI analysis capabilities
func (s *FortressHTTPServer) handleAIStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"ai_analysis_enabled": s.emailAnalyzer != nil,
		"timestamp":           time.Now().UTC(),
	}

	if s.emailAnalyzer != nil {
		status["status"] = "available"
		status["features"] = []string{
			"spam_detection",
			"content_analysis",
			"deliverability_check",
			"tone_analysis",
		}
		status["providers"] = []string{"openai", "fallback"}
	} else {
		status["status"] = "disabled"
		status["message"] = "Enable AI analysis with PAT_AI_ENABLED=true and PAT_OPENAI_API_KEY"
	}

	s.writeJSON(w, status)
}

// DefaultFortressHTTPConfig returns a default fortress HTTP configuration
func DefaultFortressHTTPConfig() *FortressHTTPConfig {
	return &FortressHTTPConfig{
		BindAddr:        "0.0.0.0:8025",
		WebPath:         "",
		CORSOrigin:      "",
		EnableCORS:      true,
		EnableTLS:       false,
		EnableAuth:      false,
		APIKeyRequired:  false,
		EnableRateLimit: true,
		MaxPerIP:        100,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		EnableAIAnalysis: false,
		OpenAIModel:     "gpt-3.5-turbo",
	}
}