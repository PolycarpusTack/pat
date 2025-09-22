package logging

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogLevel represents logging levels
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
	LevelFatal LogLevel = "fatal"
)

// LogFormat represents log output formats
type LogFormat string

const (
	FormatJSON    LogFormat = "json"
	FormatConsole LogFormat = "console"
	FormatPlain   LogFormat = "plain"
)

// LoggerConfig defines configuration for structured logging
type LoggerConfig struct {
	Level           LogLevel  `json:"level"`
	Format          LogFormat `json:"format"`
	OutputPath      string    `json:"output_path"`
	ErrorOutputPath string    `json:"error_output_path"`
	EnableCaller    bool      `json:"enable_caller"`
	EnableStacktrace bool     `json:"enable_stacktrace"`
	SamplingEnabled bool      `json:"sampling_enabled"`
	SamplingRate    int       `json:"sampling_rate"`

	// Fortress-specific fields
	ServiceName    string `json:"service_name"`
	ServiceVersion string `json:"service_version"`
	Environment    string `json:"environment"`
	NodeID         string `json:"node_id"`
}

// DefaultLoggerConfig returns production-ready logger configuration
func DefaultLoggerConfig() *LoggerConfig {
	hostname, _ := os.Hostname()

	return &LoggerConfig{
		Level:           LevelInfo,
		Format:          FormatJSON,
		OutputPath:      "stdout",
		ErrorOutputPath: "stderr",
		EnableCaller:    true,
		EnableStacktrace: true,
		SamplingEnabled: true,
		SamplingRate:    100, // Sample 1 in 100 similar messages
		ServiceName:    "pat-fortress",
		ServiceVersion: "2.0.0",
		Environment:    getEnvironment(),
		NodeID:         hostname,
	}
}

// NewLogger creates a production-ready structured logger
func NewLogger(config *LoggerConfig) (*zap.Logger, error) {
	if config == nil {
		config = DefaultLoggerConfig()
	}

	// Build zap config
	zapConfig := zap.Config{
		Level:             zap.NewAtomicLevelAt(mapLogLevel(config.Level)),
		Development:       config.Environment == "development",
		DisableCaller:     !config.EnableCaller,
		DisableStacktrace: !config.EnableStacktrace,
		Sampling: &zap.SamplingConfig{
			Initial:    config.SamplingRate,
			Thereafter: config.SamplingRate,
		},
		Encoding: string(config.Format),
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.RFC3339TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{config.OutputPath},
		ErrorOutputPaths: []string{config.ErrorOutputPath},
		InitialFields: map[string]interface{}{
			"service":         config.ServiceName,
			"version":         config.ServiceVersion,
			"environment":     config.Environment,
			"node_id":        config.NodeID,
			"process_id":     os.Getpid(),
		},
	}

	// Disable sampling in development
	if config.Environment == "development" {
		zapConfig.Sampling = nil
	}

	// Use console format for development
	if config.Environment == "development" && config.Format == FormatJSON {
		zapConfig.Encoding = "console"
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		zapConfig.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
	}

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	return logger, nil
}

// mapLogLevel converts our LogLevel to zap level
func mapLogLevel(level LogLevel) zapcore.Level {
	switch level {
	case LevelDebug:
		return zapcore.DebugLevel
	case LevelInfo:
		return zapcore.InfoLevel
	case LevelWarn:
		return zapcore.WarnLevel
	case LevelError:
		return zapcore.ErrorLevel
	case LevelFatal:
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// getEnvironment determines current environment
func getEnvironment() string {
	if env := os.Getenv("FORTRESS_ENV"); env != "" {
		return env
	}
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		return env
	}
	if env := os.Getenv("NODE_ENV"); env != "" {
		return env
	}
	return "production"
}

// ContextualLogger provides request-scoped logging
type ContextualLogger struct {
	logger *zap.Logger
	fields []zap.Field
}

// NewContextualLogger creates a logger with persistent context fields
func NewContextualLogger(logger *zap.Logger, fields ...zap.Field) *ContextualLogger {
	return &ContextualLogger{
		logger: logger.With(fields...),
		fields: fields,
	}
}

// WithContext adds context-specific fields
func (cl *ContextualLogger) WithContext(ctx context.Context) *zap.Logger {
	fields := []zap.Field{}

	// Extract request ID if available
	if requestID := extractFromContext(ctx, "request_id"); requestID != "" {
		fields = append(fields, zap.String("request_id", requestID))
	}

	// Extract user ID if available
	if userID := extractFromContext(ctx, "user_id"); userID != "" {
		fields = append(fields, zap.String("user_id", userID))
	}

	// Extract trace ID if available
	if traceID := extractFromContext(ctx, "trace_id"); traceID != "" {
		fields = append(fields, zap.String("trace_id", traceID))
	}

	return cl.logger.With(fields...)
}

// WithRequestID adds request ID to logger context
func (cl *ContextualLogger) WithRequestID(requestID string) *ContextualLogger {
	return &ContextualLogger{
		logger: cl.logger.With(zap.String("request_id", requestID)),
		fields: append(cl.fields, zap.String("request_id", requestID)),
	}
}

// WithComponent adds component context
func (cl *ContextualLogger) WithComponent(component string) *ContextualLogger {
	return &ContextualLogger{
		logger: cl.logger.With(zap.String("component", component)),
		fields: append(cl.fields, zap.String("component", component)),
	}
}

// Logger returns the underlying zap logger
func (cl *ContextualLogger) Logger() *zap.Logger {
	return cl.logger
}

// LoggerMiddleware creates HTTP middleware for request logging
func LoggerMiddleware(logger *zap.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Generate request ID
			requestID := generateRequestID()

			// Create contextual logger
			contextLogger := logger.With(
				zap.String("request_id", requestID),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("user_agent", r.UserAgent()),
			)

			// Add request ID to response headers
			w.Header().Set("X-Request-ID", requestID)

			// Log request start
			contextLogger.Info("HTTP request started")

			// Create response recorder
			recorder := &responseRecorder{ResponseWriter: w, statusCode: 200}

			// Process request
			next.ServeHTTP(recorder, r)

			// Log request completion
			duration := time.Since(start)
			contextLogger.Info("HTTP request completed",
				zap.Int("status_code", recorder.statusCode),
				zap.Duration("duration", duration),
				zap.Int64("response_size", recorder.size),
			)
		})
	}
}

// ErrorLogger provides structured error logging
type ErrorLogger struct {
	logger *zap.Logger
}

// NewErrorLogger creates a new error logger
func NewErrorLogger(logger *zap.Logger) *ErrorLogger {
	return &ErrorLogger{logger: logger}
}

// LogError logs an error with context
func (el *ErrorLogger) LogError(err error, message string, fields ...zap.Field) {
	allFields := append(fields,
		zap.Error(err),
		zap.String("error_type", fmt.Sprintf("%T", err)),
		zap.Stack("stack_trace"),
	)

	// Add caller information
	if pc, file, line, ok := runtime.Caller(1); ok {
		function := runtime.FuncForPC(pc)
		allFields = append(allFields,
			zap.String("caller_file", filepath.Base(file)),
			zap.Int("caller_line", line),
			zap.String("caller_function", function.Name()),
		)
	}

	el.logger.Error(message, allFields...)
}

// MetricsLogger provides structured metrics logging
type MetricsLogger struct {
	logger *zap.Logger
}

// NewMetricsLogger creates a new metrics logger
func NewMetricsLogger(logger *zap.Logger) *MetricsLogger {
	return &MetricsLogger{
		logger: logger.With(zap.String("log_type", "metrics")),
	}
}

// LogMetric logs a metric event
func (ml *MetricsLogger) LogMetric(name string, value interface{}, tags map[string]string) {
	fields := []zap.Field{
		zap.String("metric_name", name),
		zap.Any("metric_value", value),
		zap.Time("metric_timestamp", time.Now()),
	}

	for key, val := range tags {
		fields = append(fields, zap.String("tag_"+key, val))
	}

	ml.logger.Info("metric recorded", fields...)
}

// SecurityLogger provides security event logging
type SecurityLogger struct {
	logger *zap.Logger
}

// NewSecurityLogger creates a new security logger
func NewSecurityLogger(logger *zap.Logger) *SecurityLogger {
	return &SecurityLogger{
		logger: logger.With(zap.String("log_type", "security")),
	}
}

// LogSecurityEvent logs a security-related event
func (sl *SecurityLogger) LogSecurityEvent(eventType, description string, fields ...zap.Field) {
	allFields := append(fields,
		zap.String("security_event_type", eventType),
		zap.String("description", description),
		zap.Time("event_timestamp", time.Now()),
	)

	sl.logger.Warn("security event", allFields...)
}

// Helper functions

func extractFromContext(ctx context.Context, key string) string {
	if value := ctx.Value(key); value != nil {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

func generateRequestID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

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