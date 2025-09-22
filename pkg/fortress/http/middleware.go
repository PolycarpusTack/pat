package http

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pat-fortress/pkg/fortress/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// MiddlewareHandlers contains HTTP middleware functions
type MiddlewareHandlers struct {
	server *FortressHTTPServer
}

// NewMiddlewareHandlers creates new middleware handlers
func NewMiddlewareHandlers(server *FortressHTTPServer) *MiddlewareHandlers {
	return &MiddlewareHandlers{server: server}
}

// corsMiddleware handles CORS headers
func (m *MiddlewareHandlers) CORSMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if m.server.config.EnableCORS {
            // Compute allowed origin
            allowedOrigin := m.server.config.CORSOrigin
            if allowedOrigin == "" {
                // Wildcard: do not allow credentials with '*'
                allowedOrigin = "*"
            }

            w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
            if allowedOrigin != "*" {
                w.Header().Set("Access-Control-Allow-Credentials", "true")
                w.Header().Add("Vary", "Origin")
            }
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

// loggingMiddleware logs HTTP requests with structured logging
func (m *MiddlewareHandlers) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Generate request ID for tracing
		requestID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
		w.Header().Set("X-Request-ID", requestID)

		// Create contextual logger
		contextLogger := logging.NewContextualLogger(m.server.logger,
			zap.String("request_id", requestID),
			zap.String("component", "http_server"),
		)

		// Create a response recorder to capture status code and size
		recorder := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		// Log request start
		contextLogger.Logger().Info("HTTP request started",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("query", r.URL.RawQuery),
			zap.String("remote_addr", getClientIP(r)),
			zap.String("user_agent", r.UserAgent()),
			zap.String("referer", r.Referer()),
			zap.Int64("content_length", r.ContentLength),
		)

		next.ServeHTTP(recorder, r)

		duration := time.Since(start)

		// Determine log level based on status code
		logLevel := getLogLevelForStatus(recorder.statusCode)

		// Log request completion with enhanced details
		logEvent := contextLogger.Logger().Check(logLevel, "HTTP request completed")
		if logEvent != nil {
			logEvent.Write(
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", getClientIP(r)),
				zap.Int("status_code", recorder.statusCode),
				zap.Duration("duration", duration),
				zap.Int64("response_size", recorder.size),
				zap.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
				zap.Bool("slow_request", duration > 5*time.Second),
			)
		}

		// Log security events for suspicious activity
		if recorder.statusCode == 401 || recorder.statusCode == 403 {
			securityLogger := logging.NewSecurityLogger(m.server.logger)
			securityLogger.LogSecurityEvent("authentication_failure",
				"Authentication or authorization failed",
				zap.String("request_id", requestID),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", getClientIP(r)),
				zap.Int("status_code", recorder.statusCode),
			)
		}

		// Log performance metrics for slow requests
		if duration > 1*time.Second {
			metricsLogger := logging.NewMetricsLogger(m.server.logger)
			metricsLogger.LogMetric("slow_request_duration", duration.Milliseconds(), map[string]string{
				"endpoint":    r.URL.Path,
				"method":      r.Method,
				"status_code": fmt.Sprintf("%d", recorder.statusCode),
			})
		}
	})
}

// authMiddleware provides basic API key authentication
func (m *MiddlewareHandlers) AuthMiddleware(next http.Handler) http.Handler {
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
			m.server.logger.Warn("Authentication failed - missing API key",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("path", r.URL.Path),
			)

			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "Authentication required - provide X-API-Key header or Authorization: Bearer token", http.StatusUnauthorized)
			return
		}

		// Log successful authentication
		m.server.logger.Debug("Authentication successful",
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("path", r.URL.Path),
		)

		next.ServeHTTP(w, r)
	})
}

// requestSizeLimitMiddleware prevents memory exhaustion attacks
func (m *MiddlewareHandlers) RequestSizeLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply size limit based on content type and endpoint
		var maxSize int64 = 1024 * 1024 // 1MB default

		// Higher limits for email content endpoints
		if strings.HasPrefix(r.URL.Path, "/api/v1/messages") ||
		   strings.HasPrefix(r.URL.Path, "/api/v2/messages") {
			maxSize = 10 * 1024 * 1024 // 10MB for email messages
		}

		// Lower limits for configuration endpoints
		if strings.HasPrefix(r.URL.Path, "/api/v3/") {
			maxSize = 64 * 1024 // 64KB for API calls
		}

		// Apply the limit
		r.Body = http.MaxBytesReader(w, r.Body, maxSize)

		// Set security headers for large uploads
		w.Header().Set("X-Content-Length-Limit", fmt.Sprintf("%d", maxSize))

		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds comprehensive security headers
func (m *MiddlewareHandlers) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fortress security headers (enhanced)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Fortress-Protected", "true")
		w.Header().Set("X-Fortress-Version", "2.0.0")

		// Content Security Policy for web interface
		if strings.HasSuffix(r.URL.Path, ".html") || r.URL.Path == "/" {
			csp := "default-src 'self'; " +
				"script-src 'self' 'unsafe-inline'; " +
				"style-src 'self' 'unsafe-inline'; " +
				"connect-src 'self' ws: wss:; " +
				"img-src 'self' data:; " +
				"font-src 'self'"
			w.Header().Set("Content-Security-Policy", csp)
		}

		next.ServeHTTP(w, r)
	})
}

// csrfProtectionMiddleware prevents cross-site request forgery
func (m *MiddlewareHandlers) CSRFProtectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF for safe methods and specific endpoints
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" ||
		   r.URL.Path == "/api/v3/health" || strings.HasPrefix(r.URL.Path, "/api/v3/ollama/") {
			next.ServeHTTP(w, r)
			return
		}

		// Require CSRF protection for destructive operations
		if r.Method == "DELETE" || r.Method == "POST" || r.Method == "PUT" {
			// Check for required headers
			if r.Header.Get("X-Requested-With") != "XMLHttpRequest" &&
			   r.Header.Get("Content-Type") != "application/json" {
				m.server.logger.Warn("CSRF protection triggered",
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
					zap.String("remote_addr", r.RemoteAddr),
				)
				http.Error(w, "CSRF protection required. Include X-Requested-With: XMLHttpRequest header.", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// staticFileMiddleware handles static file serving
func (m *MiddlewareHandlers) StaticFileMiddleware() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m.server.config.WebPath == "" {
			http.NotFound(w, r)
			return
		}

		// Serve index.html at root path
		if r.URL.Path == "/" {
			indexPath := m.server.config.WebPath + "/index.html"
			m.server.logger.Debug("Serving index.html", zap.String("path", indexPath))

			// Check if file exists and serve it
			if _, err := os.Stat(indexPath); err == nil {
				http.ServeFile(w, r, indexPath)
			} else {
				m.server.logger.Error("Index file not found", zap.String("path", indexPath), zap.Error(err))
				http.NotFound(w, r)
			}
			return
		}

		// Handle favicon.ico specifically to avoid 404s
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}

		// For other paths, try to serve from web directory
		filePath := m.server.config.WebPath + r.URL.Path
		if _, err := os.Stat(filePath); err == nil {
			http.ServeFile(w, r, filePath)
		} else {
			http.NotFound(w, r)
		}
	}
}

// responseRecorder captures the status code and response size for logging
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	size, err := r.ResponseWriter.Write(data)
	r.size += int64(size)
	return size, err
}

// getClientIP extracts the real client IP from request headers
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (load balancers, proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (client IP before proxies)
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (nginx reverse proxy)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Check X-Client-IP header (some proxies)
	if xci := r.Header.Get("X-Client-IP"); xci != "" {
		return xci
	}

	// Fall back to RemoteAddr
	if ip := strings.Split(r.RemoteAddr, ":"); len(ip) > 0 {
		return ip[0]
	}

	return r.RemoteAddr
}

// getLogLevelForStatus determines appropriate log level based on HTTP status code
func getLogLevelForStatus(statusCode int) zapcore.Level {
	switch {
	case statusCode >= 500:
		return zapcore.ErrorLevel
	case statusCode >= 400:
		return zapcore.WarnLevel
	default:
		return zapcore.InfoLevel
	}
}
