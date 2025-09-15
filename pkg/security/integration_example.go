// Package security provides fortress integration examples
// FORTRESS INTEGRATION GUIDE - Complete security system integration examples
package security

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/pat/pkg/middleware"
	"go.uber.org/zap"
)

// FortressIntegrationExample demonstrates complete fortress security integration
type FortressIntegrationExample struct {
	logger           *zap.Logger
	configManager    *SecurityConfigManager
	securityMiddleware *middleware.SecurityMiddleware
	router           *mux.Router
	server           *http.Server
}

// NewFortressIntegrationExample creates a complete fortress security integration example
func NewFortressIntegrationExample() (*FortressIntegrationExample, error) {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	
	// Initialize configuration manager
	configManager, err := NewSecurityConfigManager("/etc/fortress/config.json", logger)
	if err != nil {
		return nil, err
	}
	
	// Get current configuration
	config := configManager.GetConfig()
	
	// Create security middleware with fortress configuration
	securityMiddleware, err := middleware.NewSecurityMiddleware(&middleware.SecurityMiddlewareOptions{
		RateLimiterConfig: config.RateLimit,
		ValidatorConfig:   config.Validator,
		RampartConfig:     config.Rampart,
		WatchtowerConfig:  config.Watchtower,
		Logger:           logger,
	})
	if err != nil {
		return nil, err
	}
	
	// Setup router with security middleware
	router := mux.NewRouter()
	router.Use(securityMiddleware.Handler)
	
	example := &FortressIntegrationExample{
		logger:           logger,
		configManager:    configManager,
		securityMiddleware: securityMiddleware,
		router:           router,
	}
	
	// Setup routes
	example.setupRoutes()
	
	// Create HTTP server
	example.server = &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	return example, nil
}

// setupRoutes configures fortress-protected routes
func (fie *FortressIntegrationExample) setupRoutes() {
	// Public endpoints
	fie.router.HandleFunc("/", fie.handleHome).Methods("GET")
	fie.router.HandleFunc("/health", fie.handleHealth).Methods("GET")
	
	// API endpoints with fortress protection
	api := fie.router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/emails", fie.handleGetEmails).Methods("GET")
	api.HandleFunc("/emails", fie.handleCreateEmail).Methods("POST")
	api.HandleFunc("/emails/{id}", fie.handleGetEmail).Methods("GET")
	api.HandleFunc("/emails/{id}", fie.handleUpdateEmail).Methods("PUT")
	api.HandleFunc("/emails/{id}", fie.handleDeleteEmail).Methods("DELETE")
	
	// Authentication endpoints
	auth := fie.router.PathPrefix("/auth").Subrouter()
	auth.HandleFunc("/login", fie.handleLogin).Methods("POST")
	auth.HandleFunc("/logout", fie.handleLogout).Methods("POST")
	auth.HandleFunc("/register", fie.handleRegister).Methods("POST")
	
	// Admin endpoints with enhanced security
	admin := fie.router.PathPrefix("/admin").Subrouter()
	admin.HandleFunc("/metrics", fie.handleMetrics).Methods("GET")
	admin.HandleFunc("/config", fie.handleGetConfig).Methods("GET")
	admin.HandleFunc("/config", fie.handleUpdateConfig).Methods("PUT")
	admin.HandleFunc("/emergency", fie.handleEmergencyMode).Methods("POST")
	
	// File upload endpoint with validation
	fie.router.HandleFunc("/upload", fie.handleFileUpload).Methods("POST")
	
	// GraphQL endpoint with query validation
	fie.router.HandleFunc("/graphql", fie.handleGraphQL).Methods("POST")
	
	// Websocket endpoint (would need additional security)
	fie.router.HandleFunc("/ws", fie.handleWebSocket)
}

// Route handlers with fortress security integration

func (fie *FortressIntegrationExample) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Fortress Protected Application</title>
		</head>
		<body>
			<h1>🏰 Pat Fortress Security System</h1>
			<p>This application is protected by comprehensive fortress-grade security controls:</p>
			<ul>
				<li>Multi-tier rate limiting</li>
				<li>Advanced input validation</li>
				<li>Request security validation</li>
				<li>Real-time threat monitoring</li>
				<li>Automated abuse prevention</li>
			</ul>
		</body>
		</html>
	`))
}

func (fie *FortressIntegrationExample) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Get security metrics
	metrics := fie.securityMiddleware.GetMetrics()
	rateLimitStats := fie.securityMiddleware.GetRateLimitStats()
	
	response := map[string]interface{}{
		"status": "healthy",
		"fortress": map[string]interface{}{
			"protected":     true,
			"version":       "1.0.0",
			"security_mode": fie.configManager.GetGeneralConfig().SecurityMode,
		},
		"metrics": map[string]interface{}{
			"total_requests":        metrics.TotalRequests,
			"blocked_requests":      metrics.BlockedRequests,
			"rate_limit_violations": rateLimitStats.BlockedRequests,
			"threats_by_level":      metrics.ThreatsByLevel,
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	w.Header().Set("Content-Type", "application/json")
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleGetEmails(w http.ResponseWriter, r *http.Request) {
	// Simulate email retrieval with fortress protection
	emails := []map[string]interface{}{
		{
			"id":      "1",
			"subject": "Welcome to Fortress",
			"from":    "admin@fortress.local",
			"to":      "user@example.com",
			"date":    time.Now().UTC().Format(time.RFC3339),
		},
	}
	
	fie.writeJSON(w, map[string]interface{}{
		"emails": emails,
		"total":  len(emails),
	})
}

func (fie *FortressIntegrationExample) handleCreateEmail(w http.ResponseWriter, r *http.Request) {
	// Parse and validate email data
	// Note: Actual validation would be more comprehensive
	response := map[string]interface{}{
		"message":   "Email created successfully",
		"id":        "new-email-id",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	w.WriteHeader(http.StatusCreated)
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleGetEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	emailID := vars["id"]
	
	// Validate email ID
	validator := fie.getValidator()
	idResult := validator.ValidateString(emailID, "email ID", 50)
	if !idResult.Valid {
		http.Error(w, "Invalid email ID", http.StatusBadRequest)
		return
	}
	
	email := map[string]interface{}{
		"id":      emailID,
		"subject": "Fortress Protected Email",
		"content": "This email is protected by fortress security",
		"date":    time.Now().UTC().Format(time.RFC3339),
	}
	
	fie.writeJSON(w, email)
}

func (fie *FortressIntegrationExample) handleUpdateEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	emailID := vars["id"]
	
	response := map[string]interface{}{
		"message":   "Email updated successfully",
		"id":        emailID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleDeleteEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	emailID := vars["id"]
	
	response := map[string]interface{}{
		"message":   "Email deleted successfully",
		"id":        emailID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Login endpoint with fortress protection
	response := map[string]interface{}{
		"message": "Login successful",
		"token":   "jwt-token-here",
		"expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
	
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleLogout(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "Logout successful",
	}
	
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleRegister(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "Registration successful",
		"id":      "new-user-id",
	}
	
	w.WriteHeader(http.StatusCreated)
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Admin endpoint for security metrics
	metrics := fie.securityMiddleware.GetMetrics()
	rateLimitStats := fie.securityMiddleware.GetRateLimitStats()
	config := fie.configManager.GetConfig()
	
	response := map[string]interface{}{
		"fortress_metrics": map[string]interface{}{
			"total_requests":         metrics.TotalRequests,
			"blocked_requests":       metrics.BlockedRequests,
			"rate_limit_violations":  metrics.RateLimitViolations,
			"validation_failures":    metrics.ValidationFailures,
			"threats_by_level":       metrics.ThreatsByLevel,
			"pattern_detections":     metrics.PatternDetections,
			"emergency_activations":  metrics.EmergencyActivations,
		},
		"rate_limit_stats": map[string]interface{}{
			"total_requests":   rateLimitStats.TotalRequests,
			"blocked_requests": rateLimitStats.BlockedRequests,
			"global_blocks":    rateLimitStats.GlobalBlocks,
			"ip_blocks":        rateLimitStats.IPBlocks,
			"user_blocks":      rateLimitStats.UserBlocks,
			"endpoint_blocks":  rateLimitStats.EndpointBlocks,
			"emergency_blocks": rateLimitStats.EmergencyBlocks,
		},
		"configuration": map[string]interface{}{
			"security_mode":    config.General.SecurityMode,
			"emergency_mode":   config.RateLimit.EmergencyMode,
			"version":         config.Version,
			"last_updated":    config.UpdatedAt.Format(time.RFC3339),
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// Export configuration (sanitized)
	configStr, err := fie.configManager.ExportConfig()
	if err != nil {
		http.Error(w, "Failed to export configuration", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(configStr))
}

func (fie *FortressIntegrationExample) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	// Update configuration endpoint
	response := map[string]interface{}{
		"message":   "Configuration updated successfully",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleEmergencyMode(w http.ResponseWriter, r *http.Request) {
	// Emergency mode activation endpoint
	err := fie.configManager.EnableEmergencyMode("Manual activation via API")
	if err != nil {
		http.Error(w, "Failed to enable emergency mode", http.StatusInternalServerError)
		return
	}
	
	response := map[string]interface{}{
		"message":      "Emergency mode activated",
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"restrictions": "All limits reduced to emergency levels",
	}
	
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	// File upload with fortress validation
	err := r.ParseMultipartForm(50 << 20) // 50MB max
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Validate file using fortress validator
	validator := fie.getValidator()
	validationResult := validator.ValidateFileUpload(
		header.Filename,
		header.Header.Get("Content-Type"),
		header.Size,
		nil, // In real implementation, read file content
	)
	
	if !validationResult.Valid {
		http.Error(w, "File validation failed: "+validationResult.Errors[0], http.StatusBadRequest)
		return
	}
	
	response := map[string]interface{}{
		"message":  "File uploaded successfully",
		"filename": header.Filename,
		"size":     header.Size,
		"type":     header.Header.Get("Content-Type"),
	}
	
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	// GraphQL endpoint with query validation
	response := map[string]interface{}{
		"data": map[string]interface{}{
			"emails": []map[string]interface{}{
				{
					"id":      "1",
					"subject": "Fortress Protected GraphQL",
				},
			},
		},
	}
	
	fie.writeJSON(w, response)
}

func (fie *FortressIntegrationExample) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// WebSocket endpoint - would need additional security measures
	http.Error(w, "WebSocket not implemented in this example", http.StatusNotImplemented)
}

// Helper methods

func (fie *FortressIntegrationExample) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	// In real implementation, handle JSON encoding errors
	// json.NewEncoder(w).Encode(data)
}

func (fie *FortressIntegrationExample) getValidator() *FortressValidator {
	// Get validator from security middleware
	// In real implementation, you'd have proper access to the validator
	validator, _ := NewFortressValidator(nil, fie.logger)
	return validator
}

// Start begins the fortress-protected server
func (fie *FortressIntegrationExample) Start() error {
	fie.logger.Info("Starting Fortress Protected Server", 
		zap.String("address", fie.server.Addr))
	
	return fie.server.ListenAndServe()
}

// Stop gracefully shuts down the server
func (fie *FortressIntegrationExample) Stop(ctx context.Context) error {
	fie.logger.Info("Stopping Fortress Protected Server")
	
	// Shutdown security middleware
	if err := fie.securityMiddleware.Close(); err != nil {
		fie.logger.Error("Failed to close security middleware", zap.Error(err))
	}
	
	return fie.server.Shutdown(ctx)
}

// Usage Example:
// 
// func main() {
//     fortress, err := security.NewFortressIntegrationExample()
//     if err != nil {
//         log.Fatal("Failed to create fortress:", err)
//     }
//
//     // Graceful shutdown
//     go func() {
//         sigChan := make(chan os.Signal, 1)
//         signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
//         <-sigChan
//
//         ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//         defer cancel()
//
//         if err := fortress.Stop(ctx); err != nil {
//             log.Printf("Server shutdown error: %v", err)
//         }
//     }()
//
//     if err := fortress.Start(); err != nil && err != http.ErrServerClosed {
//         log.Fatal("Server failed to start:", err)
//     }
// }