// Package middleware implements fortress-grade security middleware
// FORTRESS MIDDLEWARE SYSTEM - Integrated security middleware for HTTP requests
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pat/pkg/security"
	"go.uber.org/zap"
)

// SecurityMiddleware implements fortress-grade HTTP security middleware
type SecurityMiddleware struct {
	rateLimiter *security.RampartLimiter
	validator   *security.FortressValidator
	rampart     *security.FortressRampart
	watchtower  *security.FortressWatchtower
	logger      *zap.Logger
}

// SecurityMiddlewareOptions configures the security middleware
type SecurityMiddlewareOptions struct {
	RateLimiterConfig *security.RampartLimiterConfig
	ValidatorConfig   *security.FortressValidatorConfig
	RampartConfig     *security.RampartSecurityConfig
	WatchtowerConfig  *security.WatchtowerConfig
	Logger            *zap.Logger
}

// NewSecurityMiddleware creates a new fortress security middleware
func NewSecurityMiddleware(opts *SecurityMiddlewareOptions) (*SecurityMiddleware, error) {
	if opts == nil {
		return nil, fmt.Errorf("security middleware options are required")
	}
	
	if opts.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	
	// Initialize rate limiter
	rateLimiter, err := security.NewRampartLimiter(opts.RateLimiterConfig, opts.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter: %w", err)
	}
	
	// Initialize input validator
	validator, err := security.NewFortressValidator(opts.ValidatorConfig, opts.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}
	
	// Initialize request security (rampart)
	rampart := security.NewFortressRampart(opts.RampartConfig, nil, opts.Logger)
	
	// Initialize monitoring (watchtower)
	watchtower := security.NewFortressWatchtower(opts.WatchtowerConfig, opts.Logger)
	if err := watchtower.Start(); err != nil {
		return nil, fmt.Errorf("failed to start watchtower: %w", err)
	}
	
	return &SecurityMiddleware{
		rateLimiter: rateLimiter,
		validator:   validator,
		rampart:     rampart,
		watchtower:  watchtower,
		logger:      opts.Logger,
	}, nil
}

// Handler returns the fortress security middleware HTTP handler
func (sm *SecurityMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Start timing for performance metrics
		startTime := time.Now()
		
		// Create security context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "fortress_start_time", startTime)
		r = r.WithContext(ctx)
		
		// Phase 1: Request Security Validation (Rampart)
		rampartResult := sm.rampart.ValidateRequest(r)
		if !rampartResult.Allowed {
			sm.handleSecurityViolation(w, r, "rampart", rampartResult.BlockReason, rampartResult.ThreatLevel)
			return
		}
		
		// Apply security headers from rampart
		for key, value := range rampartResult.Headers {
			w.Header().Set(key, value)
		}
		
		// Phase 2: Rate Limiting
		rateLimitResult := sm.evaluateRateLimit(r)
		if !rateLimitResult.Allowed {
			sm.handleRateLimitViolation(w, r, rateLimitResult)
			return
		}
		
		// Phase 3: Input Validation (for POST/PUT/PATCH requests)
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			if validationErr := sm.validateRequestInput(r); validationErr != nil {
				sm.handleValidationFailure(w, r, validationErr)
				return
			}
		}
		
		// Phase 4: Content Security Policy and Headers
		sm.setSecurityHeaders(w, r)
		
		// Create wrapped response writer for monitoring
		wrappedWriter := &SecurityResponseWriter{
			ResponseWriter: w,
			statusCode:     200,
			bytesWritten:   0,
		}
		
		// Record security event for successful request
		sm.recordSecurityEvent(security.SecurityEvent{
			Type:        "request_allowed",
			Severity:    "INFO",
			Source:      "middleware",
			IP:          sm.getClientIP(r),
			UserAgent:   r.Header.Get("User-Agent"),
			Endpoint:    r.URL.Path,
			Method:      r.Method,
			ThreatLevel: rampartResult.ThreatLevel,
			Action:      "allowed",
			Details: map[string]interface{}{
				"rampart_score":      rampartResult.Score,
				"rate_limit_type":    rateLimitResult.LimitType,
				"processing_time_ms": time.Since(startTime).Milliseconds(),
			},
		})
		
		// Continue to next handler
		next.ServeHTTP(wrappedWriter, r)
		
		// Post-request monitoring
		sm.recordRequestMetrics(r, wrappedWriter, time.Since(startTime))
	})
}

// evaluateRateLimit evaluates request against rate limiting rules
func (sm *SecurityMiddleware) evaluateRateLimit(r *http.Request) *security.RampartResponse {
	// Create rate limit request
	rateLimitReq := &security.RampartRequest{
		IP:        sm.getClientIP(r),
		UserID:    sm.getUserID(r),
		Endpoint:  r.URL.Path,
		Headers:   sm.convertHeaders(r.Header),
		Timestamp: time.Now(),
		IsAuth:    sm.isAuthenticatedRequest(r),
	}
	
	return sm.rateLimiter.EvaluateRequest(rateLimitReq)
}

// validateRequestInput validates input for modification requests
func (sm *SecurityMiddleware) validateRequestInput(r *http.Request) error {
	// Validate Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "" {
		mediaType := strings.Split(contentType, ";")[0]
		urlResult := sm.validator.ValidateString(mediaType, "Content-Type", 100)
		if !urlResult.Valid {
			return fmt.Errorf("invalid content type: %s", strings.Join(urlResult.Errors, ", "))
		}
	}
	
	// Validate query parameters
	for key, values := range r.URL.Query() {
		keyResult := sm.validator.ValidateString(key, "query parameter key", 100)
		if !keyResult.Valid {
			return fmt.Errorf("invalid query parameter key '%s': %s", key, strings.Join(keyResult.Errors, ", "))
		}
		
		for _, value := range values {
			valueResult := sm.validator.ValidateString(value, "query parameter value", 1000)
			if !valueResult.Valid {
				return fmt.Errorf("invalid query parameter value for '%s': %s", key, strings.Join(valueResult.Errors, ", "))
			}
		}
	}
	
	// Validate headers for suspicious content
	for key, values := range r.Header {
		for _, value := range values {
			headerResult := sm.validator.ValidateString(value, "header value", 8192)
			if !headerResult.Valid {
				return fmt.Errorf("invalid header '%s': %s", key, strings.Join(headerResult.Errors, ", "))
			}
		}
	}
	
	return nil
}

// handleSecurityViolation handles security violations from rampart
func (sm *SecurityMiddleware) handleSecurityViolation(w http.ResponseWriter, r *http.Request, violationType, reason, threatLevel string) {
	// Record security event
	sm.recordSecurityEvent(security.SecurityEvent{
		Type:        "security_violation",
		Severity:    sm.mapThreatLevelToSeverity(threatLevel),
		Source:      violationType,
		IP:          sm.getClientIP(r),
		UserAgent:   r.Header.Get("User-Agent"),
		Endpoint:    r.URL.Path,
		Method:      r.Method,
		ThreatLevel: threatLevel,
		Action:      "blocked",
		Details: map[string]interface{}{
			"violation_type": violationType,
			"reason":        reason,
			"headers":       sm.getSafeHeaders(r),
		},
	})
	
	// Set appropriate status code based on threat level
	statusCode := sm.getStatusCodeForThreat(threatLevel)
	
	// Send error response
	sm.sendSecurityErrorResponse(w, statusCode, "Security violation detected", reason)
}

// handleRateLimitViolation handles rate limiting violations
func (sm *SecurityMiddleware) handleRateLimitViolation(w http.ResponseWriter, r *http.Request, result *security.RampartResponse) {
	// Record security event
	sm.recordSecurityEvent(security.SecurityEvent{
		Type:        "rate_limit_violation",
		Severity:    "MEDIUM",
		Source:      "rate_limiter",
		IP:          sm.getClientIP(r),
		UserAgent:   r.Header.Get("User-Agent"),
		Endpoint:    r.URL.Path,
		Method:      r.Method,
		ThreatLevel: result.ThreatLevel,
		Action:      "blocked",
		Details: map[string]interface{}{
			"limit_type":        result.LimitType,
			"remaining_requests": result.RemainingRequests,
			"reset_time":        result.ResetTime,
			"retry_after":       result.RetryAfter.Seconds(),
		},
	})
	
	// Set rate limiting headers
	w.Header().Set("X-RateLimit-Limit", "0") // Will be set based on limit type
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.RemainingRequests))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetTime.Unix(), 10))
	w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
	
	// Send rate limit error response
	sm.sendSecurityErrorResponse(w, http.StatusTooManyRequests, "Rate limit exceeded", result.BlockReason)
}

// handleValidationFailure handles input validation failures
func (sm *SecurityMiddleware) handleValidationFailure(w http.ResponseWriter, r *http.Request, validationErr error) {
	// Record security event
	sm.recordSecurityEvent(security.SecurityEvent{
		Type:        "validation_failure",
		Severity:    "MEDIUM",
		Source:      "validator",
		IP:          sm.getClientIP(r),
		UserAgent:   r.Header.Get("User-Agent"),
		Endpoint:    r.URL.Path,
		Method:      r.Method,
		ThreatLevel: "MEDIUM",
		Action:      "blocked",
		Details: map[string]interface{}{
			"validation_error": validationErr.Error(),
		},
	})
	
	// Send validation error response
	sm.sendSecurityErrorResponse(w, http.StatusBadRequest, "Invalid input detected", validationErr.Error())
}

// setSecurityHeaders sets fortress security headers
func (sm *SecurityMiddleware) setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	// Basic security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	
	// HSTS (for HTTPS)
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	}
	
	// CSP header
	csp := "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: https:; " +
		"font-src 'self' https:; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'"
	w.Header().Set("Content-Security-Policy", csp)
	
	// Fortress-specific headers
	w.Header().Set("X-Fortress-Protected", "true")
	w.Header().Set("X-Fortress-Version", "1.0.0")
}

// sendSecurityErrorResponse sends a standardized security error response
func (sm *SecurityMiddleware) sendSecurityErrorResponse(w http.ResponseWriter, statusCode int, title, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	errorResponse := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    statusCode,
			"title":   title,
			"message": message,
			"type":    "security_error",
		},
		"fortress": map[string]interface{}{
			"protected": true,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}
	
	json.NewEncoder(w).Encode(errorResponse)
}

// recordSecurityEvent records a security event with the watchtower
func (sm *SecurityMiddleware) recordSecurityEvent(event security.SecurityEvent) {
	sm.watchtower.RecordEvent(event)
}

// recordRequestMetrics records request metrics for monitoring
func (sm *SecurityMiddleware) recordRequestMetrics(r *http.Request, w *SecurityResponseWriter, duration time.Duration) {
	// Record metrics event
	sm.recordSecurityEvent(security.SecurityEvent{
		Type:        "request_metrics",
		Severity:    "INFO",
		Source:      "middleware",
		IP:          sm.getClientIP(r),
		Endpoint:    r.URL.Path,
		Method:      r.Method,
		ThreatLevel: "SAFE",
		Action:      "metrics",
		Details: map[string]interface{}{
			"status_code":        w.statusCode,
			"response_size":      w.bytesWritten,
			"processing_time_ms": duration.Milliseconds(),
			"user_agent":         r.Header.Get("User-Agent"),
		},
	})
}

// Helper methods

// getClientIP extracts the real client IP from the request
func (sm *SecurityMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	
	// Fall back to remote address
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	
	return r.RemoteAddr
}

// getUserID extracts user ID from the request (if authenticated)
func (sm *SecurityMiddleware) getUserID(r *http.Request) string {
	// Try to get user ID from context (set by auth middleware)
	if userID := r.Context().Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	
	// Try to get from Authorization header (JWT)
	if auth := r.Header.Get("Authorization"); auth != "" && strings.HasPrefix(auth, "Bearer ") {
		// In a real implementation, you'd decode the JWT here
		return "authenticated_user"
	}
	
	return ""
}

// isAuthenticatedRequest checks if the request is authenticated
func (sm *SecurityMiddleware) isAuthenticatedRequest(r *http.Request) bool {
	// Check for Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		return true
	}
	
	// Check for session cookie
	if cookie, err := r.Cookie("session"); err == nil && cookie.Value != "" {
		return true
	}
	
	// Check context for user information
	if userID := r.Context().Value("user_id"); userID != nil {
		return true
	}
	
	return false
}

// convertHeaders converts http.Header to map[string]string
func (sm *SecurityMiddleware) convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			result[key] = values[0] // Take first value
		}
	}
	return result
}

// getSafeHeaders returns headers safe for logging (excludes sensitive data)
func (sm *SecurityMiddleware) getSafeHeaders(r *http.Request) map[string]string {
	safeHeaders := make(map[string]string)
	
	// List of headers that are safe to log
	safeHeaderNames := []string{
		"User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
		"Content-Type", "Content-Length", "Host", "Referer",
	}
	
	for _, name := range safeHeaderNames {
		if value := r.Header.Get(name); value != "" {
			safeHeaders[name] = value
		}
	}
	
	return safeHeaders
}

// mapThreatLevelToSeverity maps threat levels to severity levels
func (sm *SecurityMiddleware) mapThreatLevelToSeverity(threatLevel string) string {
	switch threatLevel {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "INFO"
	}
}

// getStatusCodeForThreat returns appropriate HTTP status code for threat level
func (sm *SecurityMiddleware) getStatusCodeForThreat(threatLevel string) int {
	switch threatLevel {
	case "CRITICAL":
		return http.StatusForbidden
	case "HIGH":
		return http.StatusForbidden
	case "MEDIUM":
		return http.StatusBadRequest
	case "LOW":
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

// SecurityResponseWriter wraps http.ResponseWriter for monitoring
type SecurityResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

// WriteHeader captures the status code
func (srw *SecurityResponseWriter) WriteHeader(statusCode int) {
	srw.statusCode = statusCode
	srw.ResponseWriter.WriteHeader(statusCode)
}

// Write captures the bytes written
func (srw *SecurityResponseWriter) Write(data []byte) (int, error) {
	n, err := srw.ResponseWriter.Write(data)
	srw.bytesWritten += int64(n)
	return n, err
}

// Close gracefully shuts down the security middleware
func (sm *SecurityMiddleware) Close() error {
	sm.logger.Info("Shutting down fortress security middleware")
	
	if err := sm.watchtower.Stop(); err != nil {
		sm.logger.Error("Failed to stop watchtower", zap.Error(err))
	}
	
	if err := sm.rateLimiter.Close(); err != nil {
		sm.logger.Error("Failed to close rate limiter", zap.Error(err))
	}
	
	return nil
}

// GetMetrics returns current security metrics
func (sm *SecurityMiddleware) GetMetrics() *security.SecurityMetrics {
	return sm.watchtower.GetMetrics()
}

// GetRateLimitStats returns rate limiting statistics
func (sm *SecurityMiddleware) GetRateLimitStats() *security.RampartStats {
	return sm.rateLimiter.GetStats()
}