package http

import (
    "context"
    "encoding/json"
    "net/http"
    "time"

	"github.com/gorilla/mux"
    "github.com/gorilla/websocket"
	"github.com/pat-fortress/pkg/fortress/analyzer"
	"github.com/pat-fortress/pkg/fortress/legacy"
	"github.com/pat-fortress/pkg/fortress/ratelimit"
	"go.uber.org/zap"
    "sync"
)

// FortressHTTPServer provides a modern HTTP API server with legacy MailHog compatibility
type FortressHTTPServer struct {
    config        *FortressHTTPConfig
    logger        *zap.Logger
    store         legacy.FortressMessageStore
    router        *mux.Router
    server        *http.Server
    startTime     time.Time
    rateLimiter   *ratelimit.SimpleRateLimiter
    emailAnalyzer *analyzer.EmailAnalyzer
    wsConns       map[*websocket.Conn]struct{}
    wsMu          sync.RWMutex
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
        wsConns:   make(map[*websocket.Conn]struct{}),
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

// PublishEvent broadcasts a simple event to all connected WebSocket clients
func (s *FortressHTTPServer) PublishEvent(eventType string, payload map[string]interface{}) {
    if payload == nil {
        payload = map[string]interface{}{}
    }
    payload["type"] = eventType
    payload["timestamp"] = time.Now().UTC()

    s.wsMu.RLock()
    defer s.wsMu.RUnlock()
    for conn := range s.wsConns {
        _ = conn.WriteJSON(payload)
    }
}

// setupRoutes configures fortress HTTP routes with MailHog compatibility
func (s *FortressHTTPServer) setupRoutes() {
	// Create handler instances
	messageHandlers := NewMessageHandlers(s)
	fortressHandlers := NewFortressHandlers(s)
	wsHandlers := NewWebSocketHandlers(s)
	middleware := NewMiddlewareHandlers(s)

	// Add middleware in proper order (security first, then functional)
	s.router.Use(middleware.SecurityHeadersMiddleware)
	s.router.Use(middleware.RequestSizeLimitMiddleware)
	s.router.Use(middleware.CSRFProtectionMiddleware)
	s.router.Use(middleware.CORSMiddleware)
	s.router.Use(middleware.LoggingMiddleware)

	// Add rate limiting middleware if enabled
	if s.rateLimiter != nil {
		s.router.Use(s.rateLimiter.HTTPMiddleware())
	}

	// Add authentication middleware if enabled
	if s.config.EnableAuth {
		s.router.Use(middleware.AuthMiddleware)
	}

	// API v1 routes (MailHog compatibility)
	apiV1 := s.router.PathPrefix("/api/v1").Subrouter()

	// Messages endpoint
	apiV1.HandleFunc("/messages", messageHandlers.HandleMessages).Methods("GET", "OPTIONS")
	apiV1.HandleFunc("/messages/{id}", messageHandlers.HandleMessage).Methods("GET", "DELETE", "OPTIONS")
	apiV1.HandleFunc("/messages", messageHandlers.HandleDeleteAll).Methods("DELETE", "OPTIONS")

	// API v2 routes (Enhanced MailHog compatibility)
	apiV2 := s.router.PathPrefix("/api/v2").Subrouter()
	apiV2.HandleFunc("/messages", messageHandlers.HandleMessagesV2).Methods("GET", "OPTIONS")
	apiV2.HandleFunc("/messages/{id}", messageHandlers.HandleMessageV2).Methods("GET", "DELETE", "OPTIONS")
	apiV2.HandleFunc("/search", messageHandlers.HandleSearch).Methods("GET", "OPTIONS")
	apiV2.HandleFunc("/jim", fortressHandlers.HandleJim).Methods("GET", "POST", "DELETE", "OPTIONS")

	// Fortress API v3 routes (Modern enhanced API)
	apiV3 := s.router.PathPrefix("/api/v3").Subrouter()
	apiV3.HandleFunc("/health", fortressHandlers.HandleHealth).Methods("GET")
	apiV3.HandleFunc("/metrics", fortressHandlers.HandleMetrics).Methods("GET")
	apiV3.HandleFunc("/messages/stats", messageHandlers.HandleMessageStats).Methods("GET")
	apiV3.HandleFunc("/messages/export", messageHandlers.HandleExport).Methods("GET")
	apiV3.HandleFunc("/security/scan/{id}", fortressHandlers.HandleSecurityScan).Methods("POST")

	// AI Analysis endpoints
	apiV3.HandleFunc("/ai/analyze/{id}", fortressHandlers.HandleAIAnalysis).Methods("POST")
	apiV3.HandleFunc("/ai/status", fortressHandlers.HandleAIStatus).Methods("GET")

	// Ollama Integration endpoints
	apiV3.HandleFunc("/ollama/status", fortressHandlers.HandleOllamaStatus).Methods("GET")
	apiV3.HandleFunc("/ollama/models", fortressHandlers.HandleOllamaModels).Methods("GET")

	// Circuit Breaker and Performance Monitoring
	apiV3.HandleFunc("/circuit-breaker/metrics", fortressHandlers.HandleCircuitBreakerMetrics).Methods("GET")
	apiV3.HandleFunc("/storage/metrics", fortressHandlers.HandleStorageMetrics).Methods("GET")

	// WebSocket endpoint for real-time updates
	s.router.HandleFunc("/api/v1/events", wsHandlers.HandleWebSocket).Methods("GET")

	// Static file serving (UI compatibility) - register last to catch remaining routes
	if s.config.WebPath != "" {
		s.router.HandleFunc("/", middleware.StaticFileMiddleware()).Methods("GET")
		s.router.HandleFunc("/favicon.ico", middleware.StaticFileMiddleware()).Methods("GET")
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
        if err := s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile); err != nil && err != http.ErrServerClosed {
            return err
        }
        return nil
    }

    if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        return err
    }
    return nil
}

// Shutdown gracefully shuts down the fortress HTTP server
func (s *FortressHTTPServer) Shutdown() error {
    // Close rate limiter
    if s.rateLimiter != nil {
        s.rateLimiter.Close()
    }

    if s.server == nil {
        return nil
    }

    // Graceful shutdown with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    return s.server.Shutdown(ctx)
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
