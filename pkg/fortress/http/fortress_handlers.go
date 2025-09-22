package http

import (
    "fmt"
    "net/http"
    "runtime"
    "time"

    "github.com/gorilla/mux"
    "github.com/pat-fortress/pkg/fortress/analyzer"
    "github.com/pat-fortress/pkg/fortress/legacy"
    "go.uber.org/zap"
)

// FortressHandlers contains HTTP handlers for Fortress-specific endpoints
type FortressHandlers struct {
	server *FortressHTTPServer
}

// NewFortressHandlers creates new fortress handlers
func NewFortressHandlers(server *FortressHTTPServer) *FortressHandlers {
	return &FortressHandlers{server: server}
}

// handleHealth provides fortress health check endpoint
func (h *FortressHandlers) HandleHealth(w http.ResponseWriter, r *http.Request) {
    mem := &runtime.MemStats{}
    runtime.ReadMemStats(mem)
    goroutines := runtime.NumGoroutine()

    health := map[string]interface{}{
        "status":       "healthy",
        "timestamp":    time.Now().UTC(),
        "version":      "fortress-2.0.0",
        "messages":     h.server.store.Count(),
        "uptime":       time.Since(h.server.startTime).String(),
        "memory_usage": int(mem.Alloc / 1024 / 1024),
        "goroutines":   goroutines,
    }

    h.server.writeJSON(w, health)
}

// handleMetrics provides fortress metrics endpoint
func (h *FortressHandlers) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	// Get rate limiting stats
	rateLimitStats := map[string]interface{}{
		"enabled": false,
	}
	if h.server.rateLimiter != nil {
		rateLimitStats = h.server.rateLimiter.GetStats()
	}

    uptime := time.Since(h.server.startTime)
    mem := &runtime.MemStats{}
    runtime.ReadMemStats(mem)
    goroutines := runtime.NumGoroutine()

    metrics := map[string]interface{}{
        "messages": map[string]interface{}{
            "total": h.server.store.Count(),
        },
        "fortress": map[string]interface{}{
            "version":        "2.0.0",
            "mode":           "standalone",
            "security":       h.server.config.EnableAuth,
            "uptime":         uptime.String(),
            "uptime_seconds": int64(uptime.Seconds()),
        },
        "rate_limiting": rateLimitStats,
        "http": map[string]interface{}{
            "cors_enabled":       h.server.config.EnableCORS,
            "tls_enabled":        h.server.config.EnableTLS,
            "auth_enabled":       h.server.config.EnableAuth,
            "rate_limit_enabled": h.server.config.EnableRateLimit,
        },
        "storage": map[string]interface{}{
            "type": "unknown", // Would be populated from storage adapter
        },
        "system": map[string]interface{}{
            "memory_mb":  int(mem.Alloc / 1024 / 1024),
            "goroutines": goroutines,
        },
        "timestamp": time.Now().UTC(),
    }

    h.server.writeJSON(w, metrics)
}

// handleSecurityScan provides fortress security scanning
func (h *FortressHandlers) HandleSecurityScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := legacy.MessageID(vars["id"])

	message, err := h.server.store.Load(id)
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

	h.server.writeJSON(w, scanResults)
}

// handleAIAnalysis provides AI-powered email analysis
func (h *FortressHandlers) HandleAIAnalysis(w http.ResponseWriter, r *http.Request) {
	// Check if AI analyzer is enabled
	if h.server.emailAnalyzer == nil {
		http.Error(w, "AI analysis not available - enable with PAT_AI_ENABLED=true", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	id := legacy.MessageID(vars["id"])

	// Load the message
	message, err := h.server.store.Load(id)
	if err != nil {
		if err == legacy.ErrMessageNotFound {
			http.Error(w, "Message not found", http.StatusNotFound)
		} else {
			h.server.logger.Error("Failed to load message for AI analysis", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Perform AI analysis
	analysis, err := h.server.emailAnalyzer.AnalyzeEmail(message)
	if err != nil {
		h.server.logger.Error("AI analysis failed",
			zap.Error(err),
			zap.String("message_id", string(id)))
		http.Error(w, "AI analysis failed", http.StatusInternalServerError)
		return
	}

	h.server.logger.Info("AI analysis completed",
		zap.String("message_id", string(id)),
		zap.Float64("confidence", analysis.Confidence),
		zap.String("spam_level", analysis.SpamRisk.Level))

	h.server.writeJSON(w, analysis)
}

// handleAIStatus provides status information about AI analysis capabilities
func (h *FortressHandlers) HandleAIStatus(w http.ResponseWriter, r *http.Request) {
    enabled := h.server.emailAnalyzer != nil
    status := map[string]interface{}{
        "enabled":             enabled,
        "ai_analysis_enabled": enabled, // backward compatibility
        "timestamp":           time.Now().UTC(),
    }

    // Provide simple stats structure expected by UI
    stats := map[string]interface{}{
        "total_analyses": 0,
        "avg_confidence": 0.0,
        "retry_rate":     0.0,
    }

    if enabled {
        status["status"] = "available"
        status["features"] = []string{
            "spam_detection",
            "content_analysis",
            "deliverability_check",
            "tone_analysis",
        }
        status["providers"] = []string{"openai", "fallback"}

        if aStats := h.server.emailAnalyzer.GetStats(); aStats != nil {
            if rs, ok := aStats["retry_stats"].(*analyzer.RetryStats); ok && rs != nil {
                totalOps := rs.SuccessfulRetries + rs.FailedRetries
                stats["total_analyses"] = totalOps
                if rs.TotalAttempts > 0 {
                    stats["retry_rate"] = float64(rs.TotalAttempts-totalOps) / float64(rs.TotalAttempts)
                }
            }
        }
    } else {
        status["status"] = "disabled"
        status["message"] = "Enable AI analysis with PAT_AI_ENABLED=true and PAT_OPENAI_API_KEY"
    }

    status["stats"] = stats

    h.server.writeJSON(w, status)
}

// handleJim handles MailHog's chaos engineering endpoint (Jim)
func (h *FortressHandlers) HandleJim(w http.ResponseWriter, r *http.Request) {
	// Simple Jim implementation for MailHog compatibility
	// (In practice, most people don't use chaos engineering for email testing)
	switch r.Method {
	case "GET":
		response := map[string]interface{}{
			"enabled": false,
			"message": "Jim chaos engineering available but disabled for email testing",
		}
		h.server.writeJSON(w, response)

	case "POST":
		// Accept but don't actually enable chaos (email testing doesn't need it)
		response := map[string]interface{}{
			"success": true,
			"message": "Jim chaos mode acknowledged but not enabled (email testing mode)",
		}
		h.server.writeJSON(w, response)

	case "DELETE":
		// Disable chaos mode (no-op)
		response := map[string]interface{}{
			"success": true,
			"message": "Jim chaos mode disabled",
		}
		h.server.writeJSON(w, response)
	}
}

// handleOllamaStatus checks if Ollama is available and returns status
func (h *FortressHandlers) HandleOllamaStatus(w http.ResponseWriter, r *http.Request) {
	baseURL := r.URL.Query().Get("baseURL")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	available := analyzer.CheckOllamaAvailability(baseURL)

	response := map[string]interface{}{
		"available": available,
		"baseURL":   baseURL,
		"timestamp": time.Now().UTC(),
	}

	if !available {
		response["message"] = "Ollama not detected. Make sure Ollama is installed and running."
	}

	h.server.writeJSON(w, response)
}

// handleOllamaModels returns the list of available Ollama models
func (h *FortressHandlers) HandleOllamaModels(w http.ResponseWriter, r *http.Request) {
	baseURL := r.URL.Query().Get("baseURL")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	models, err := analyzer.GetOllamaModels(baseURL)
	if err != nil {
		h.server.logger.Error("Failed to fetch Ollama models", zap.Error(err))
		http.Error(w, fmt.Sprintf("Failed to fetch Ollama models: %v", err), http.StatusServiceUnavailable)
		return
	}

	response := map[string]interface{}{
		"models":    models,
		"count":     len(models),
		"baseURL":   baseURL,
		"timestamp": time.Now().UTC(),
	}

	h.server.writeJSON(w, response)
}

// handleCircuitBreakerMetrics provides circuit breaker metrics for monitoring
func (h *FortressHandlers) HandleCircuitBreakerMetrics(w http.ResponseWriter, r *http.Request) {
	if h.server.emailAnalyzer == nil {
		http.Error(w, "Email analyzer not available", http.StatusServiceUnavailable)
		return
	}

	// Get connection pool metrics
	pool := analyzer.GetHTTPClientPool()
	poolMetrics := pool.GetMetrics()

	// TODO: Get circuit breaker metrics from AI providers
	// This would require exposing circuit breaker metrics from the providers
	response := map[string]interface{}{
		"timestamp": time.Now().UTC(),
		"connection_pool": map[string]interface{}{
			"total_requests":       poolMetrics.TotalRequests,
			"successful_requests":  poolMetrics.SuccessfulRequests,
			"failed_requests":      poolMetrics.FailedRequests,
			"success_rate":         float64(poolMetrics.SuccessfulRequests) / float64(poolMetrics.TotalRequests),
			"average_response_time": poolMetrics.AverageResponseTime.String(),
		},
		"circuit_breakers": map[string]interface{}{
			"openai": map[string]interface{}{
				"state":   "closed", // Placeholder - would need provider access
				"metrics": "not_implemented",
			},
			"ollama": map[string]interface{}{
				"state":   "closed", // Placeholder - would need provider access
				"metrics": "not_implemented",
			},
		},
		"message": "Circuit breaker individual metrics require provider interface extension",
	}

	h.server.writeJSON(w, response)
}

// handleStorageMetrics provides storage and search index metrics
func (h *FortressHandlers) HandleStorageMetrics(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"timestamp": time.Now().UTC(),
		"storage": map[string]interface{}{
			"type":          "memory", // Could be dynamic based on config
			"message_count": h.server.store.Count(),
		},
	}

	// Add index statistics if available
	if indexedStore, ok := h.server.store.(interface{ GetIndexStats() map[string]interface{} }); ok {
		response["search_indexes"] = indexedStore.GetIndexStats()
	} else {
		response["search_indexes"] = map[string]interface{}{
			"type": "basic",
			"note": "Using basic search without indexing",
		}
	}

	h.server.writeJSON(w, response)
}
