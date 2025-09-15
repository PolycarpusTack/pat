package watchtower

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"go.uber.org/zap"
)

// WatchtowerService implements the Watchtower interface - fortress monitoring and observability
type WatchtowerService struct {
	config *Config
	logger *zap.Logger

	// Monitoring components
	metrics     *MetricsCollector
	tracer      *TracingCollector
	alerter     *AlertManager
	healthMgr   *HealthManager

	// Service state
	mu         sync.RWMutex
	started    bool
	monitoring bool
	startTime  time.Time

	// Health checks registry
	healthChecks map[string]interfaces.HealthCheckFunc
	
	// Alert handlers registry
	alertHandlers []interfaces.AlertHandler

	// System stats tracking
	systemStats *interfaces.SystemStats
	statsTicker *time.Ticker
}

// Config contains Watchtower service configuration
type Config struct {
	MetricsEnabled    bool     `json:"metricsEnabled"`
	TracingEnabled    bool     `json:"tracingEnabled"`
	LogLevel          string   `json:"logLevel"`
	MetricsPort       int      `json:"metricsPort"`
	AlertingEnabled   bool     `json:"alertingEnabled"`
	HealthCheckInterval time.Duration `json:"healthCheckInterval"`
	RetentionDays     int      `json:"retentionDays"`
	ExternalEndpoints []string `json:"externalEndpoints"`
}

// NewWatchtowerService creates a new Watchtower service instance
func NewWatchtowerService(ctx context.Context, config *Config, logger *zap.Logger) (*WatchtowerService, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	service := &WatchtowerService{
		config:        config,
		logger:        logger.Named("watchtower"),
		healthChecks:  make(map[string]interfaces.HealthCheckFunc),
		alertHandlers: make([]interfaces.AlertHandler, 0),
		systemStats:   &interfaces.SystemStats{},
		startTime:     time.Now(),
	}

	// Initialize components
	if err := service.initializeComponents(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	logger.Info("Watchtower service created successfully")
	return service, nil
}

// RecordMetric records a metric value with labels
func (w *WatchtowerService) RecordMetric(name string, value float64, labels map[string]string) {
	if !w.config.MetricsEnabled || w.metrics == nil {
		return
	}

	w.metrics.RecordMetric(name, value, labels)
	
	w.logger.Debug("Metric recorded",
		zap.String("name", name),
		zap.Float64("value", value),
		zap.Any("labels", labels))
}

// IncrementCounter increments a counter metric
func (w *WatchtowerService) IncrementCounter(name string, labels map[string]string) {
	if !w.config.MetricsEnabled || w.metrics == nil {
		return
	}

	w.metrics.IncrementCounter(name, labels)
}

// RecordHistogram records a histogram metric
func (w *WatchtowerService) RecordHistogram(name string, value float64, labels map[string]string) {
	if !w.config.MetricsEnabled || w.metrics == nil {
		return
	}

	w.metrics.RecordHistogram(name, value, labels)
}

// SetGauge sets a gauge metric value
func (w *WatchtowerService) SetGauge(name string, value float64, labels map[string]string) {
	if !w.config.MetricsEnabled || w.metrics == nil {
		return
	}

	w.metrics.SetGauge(name, value, labels)
}

// LogEvent logs an event with the specified level and fields
func (w *WatchtowerService) LogEvent(level interfaces.LogLevel, message string, fields map[string]interface{}) {
	switch level {
	case interfaces.LogLevelDebug:
		w.logger.Debug(message, w.fieldsToZapFields(fields)...)
	case interfaces.LogLevelInfo:
		w.logger.Info(message, w.fieldsToZapFields(fields)...)
	case interfaces.LogLevelWarn:
		w.logger.Warn(message, w.fieldsToZapFields(fields)...)
	case interfaces.LogLevelError:
		w.logger.Error(message, w.fieldsToZapFields(fields)...)
	case interfaces.LogLevelFatal:
		w.logger.Fatal(message, w.fieldsToZapFields(fields)...)
	default:
		w.logger.Info(message, w.fieldsToZapFields(fields)...)
	}
}

// LogEmail logs email-specific events
func (w *WatchtowerService) LogEmail(email *interfaces.Email, action string, metadata map[string]interface{}) {
	fields := map[string]interface{}{
		"email_id":    email.ID,
		"message_id":  email.MessageID,
		"from":        email.From,
		"to_count":    len(email.To),
		"subject":     email.Subject,
		"size":        email.Size,
		"action":      action,
		"received_at": email.ReceivedAt,
	}

	// Merge additional metadata
	for k, v := range metadata {
		fields[k] = v
	}

	w.LogEvent(interfaces.LogLevelInfo, "Email event", fields)

	// Record email metrics
	w.IncrementCounter("watchtower.email.events", map[string]string{
		"action":      action,
		"from_domain": extractDomain(email.From),
	})
}

// LogError logs error events with context
func (w *WatchtowerService) LogError(err error, context map[string]interface{}) {
	fields := map[string]interface{}{
		"error": err.Error(),
	}

	// Merge context
	for k, v := range context {
		fields[k] = v
	}

	w.LogEvent(interfaces.LogLevelError, "Error occurred", fields)

	// Record error metrics
	w.IncrementCounter("watchtower.errors", map[string]string{
		"error_type": fmt.Sprintf("%T", err),
	})
}

// StartTrace starts a new trace span
func (w *WatchtowerService) StartTrace(ctx context.Context, operation string) (context.Context, interfaces.TraceSpan) {
	if !w.config.TracingEnabled || w.tracer == nil {
		// Return a no-op span if tracing is disabled
		return ctx, &NoOpSpan{}
	}

	return w.tracer.StartTrace(ctx, operation)
}

// RecordSpan records span information
func (w *WatchtowerService) RecordSpan(span interfaces.TraceSpan, status string, attributes map[string]interface{}) {
	if !w.config.TracingEnabled || span == nil {
		return
	}

	// Set span attributes
	for key, value := range attributes {
		span.SetTag(key, value)
	}

	if status == "error" {
		span.SetError(fmt.Errorf("operation failed"))
	}
}

// HealthCheck performs a health check and returns status
func (w *WatchtowerService) HealthCheck(ctx context.Context) *interfaces.HealthStatus {
	w.mu.RLock()
	defer w.mu.RUnlock()

	status := &interfaces.HealthStatus{
		Service:   "watchtower",
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	if !w.started {
		status.Status = interfaces.HealthStatusUnhealthy
		status.Message = "Service not started"
		return status
	}

	// Check component health
	componentHealth := make(map[string]string)
	
	if w.metrics != nil {
		if metricsHealth := w.metrics.Health(); metricsHealth {
			componentHealth["metrics"] = "healthy"
		} else {
			componentHealth["metrics"] = "unhealthy"
			status.Status = interfaces.HealthStatusDegraded
		}
	}

	if w.tracer != nil {
		if tracerHealth := w.tracer.Health(); tracerHealth {
			componentHealth["tracing"] = "healthy"
		} else {
			componentHealth["tracing"] = "unhealthy"
			status.Status = interfaces.HealthStatusDegraded
		}
	}

	if w.alerter != nil {
		if alerterHealth := w.alerter.Health(); alerterHealth {
			componentHealth["alerting"] = "healthy"
		} else {
			componentHealth["alerting"] = "unhealthy"
			status.Status = interfaces.HealthStatusDegraded
		}
	}

	status.Details["components"] = componentHealth
	status.Details["uptime"] = time.Since(w.startTime).String()
	status.Details["monitoring"] = w.monitoring

	if status.Status == "" {
		status.Status = interfaces.HealthStatusHealthy
		status.Message = "All monitoring systems operational"
	}

	return status
}

// RegisterHealthCheck registers a custom health check
func (w *WatchtowerService) RegisterHealthCheck(name string, check interfaces.HealthCheckFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	w.healthChecks[name] = check
	w.logger.Info("Health check registered", zap.String("name", name))
}

// GetSystemStats returns current system statistics
func (w *WatchtowerService) GetSystemStats(ctx context.Context) (*interfaces.SystemStats, error) {
	w.mu.RLock()
	stats := *w.systemStats // Copy current stats
	w.mu.RUnlock()

	// Update with real-time data
	w.updateSystemStats(&stats)

	return &stats, nil
}

// TriggerAlert triggers an alert with the specified level and details
func (w *WatchtowerService) TriggerAlert(level interfaces.AlertLevel, message string, details map[string]interface{}) {
	if !w.config.AlertingEnabled || w.alerter == nil {
		return
	}

	alert := &Alert{
		Level:     level,
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
		Source:    "watchtower",
	}

	w.alerter.TriggerAlert(alert)

	// Log the alert
	w.LogEvent(interfaces.LogLevelWarn, "Alert triggered", map[string]interface{}{
		"alert_level": string(level),
		"message":     message,
		"details":     details,
	})

	// Notify registered handlers
	for _, handler := range w.alertHandlers {
		go handler(level, message, details)
	}
}

// RegisterAlertHandler registers an alert handler
func (w *WatchtowerService) RegisterAlertHandler(handler interfaces.AlertHandler) {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	w.alertHandlers = append(w.alertHandlers, handler)
	w.logger.Info("Alert handler registered")
}

// StartMonitoring starts the monitoring service
func (w *WatchtowerService) StartMonitoring(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.started {
		return fmt.Errorf("watchtower service already started")
	}

	w.logger.Info("Starting Watchtower monitoring service")

	// Start metrics collection
	if w.config.MetricsEnabled && w.metrics != nil {
		if err := w.metrics.Start(ctx); err != nil {
			return fmt.Errorf("failed to start metrics collector: %w", err)
		}
	}

	// Start tracing
	if w.config.TracingEnabled && w.tracer != nil {
		if err := w.tracer.Start(ctx); err != nil {
			return fmt.Errorf("failed to start tracer: %w", err)
		}
	}

	// Start alerting
	if w.config.AlertingEnabled && w.alerter != nil {
		if err := w.alerter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start alerter: %w", err)
		}
	}

	// Start health monitoring
	if err := w.healthMgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start health manager: %w", err)
	}

	// Start system stats collection
	w.statsTicker = time.NewTicker(30 * time.Second)
	go w.runSystemStatsCollection(ctx)

	// Start periodic health checks
	go w.runPeriodicHealthChecks(ctx)

	w.started = true
	w.monitoring = true

	w.logger.Info("Watchtower monitoring service started successfully")
	return nil
}

// StopMonitoring stops the monitoring service
func (w *WatchtowerService) StopMonitoring(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.started {
		return fmt.Errorf("watchtower service not started")
	}

	w.logger.Info("Stopping Watchtower monitoring service")

	// Stop system stats collection
	if w.statsTicker != nil {
		w.statsTicker.Stop()
	}

	// Stop components
	if w.metrics != nil {
		w.metrics.Stop(ctx)
	}

	if w.tracer != nil {
		w.tracer.Stop(ctx)
	}

	if w.alerter != nil {
		w.alerter.Stop(ctx)
	}

	if w.healthMgr != nil {
		w.healthMgr.Stop(ctx)
	}

	w.started = false
	w.monitoring = false

	w.logger.Info("Watchtower monitoring service stopped")
	return nil
}

// Private helper methods

func (w *WatchtowerService) initializeComponents(ctx context.Context) error {
	var err error

	// Initialize metrics collector
	if w.config.MetricsEnabled {
		w.metrics, err = NewMetricsCollector(w.config, w.logger)
		if err != nil {
			return fmt.Errorf("failed to create metrics collector: %w", err)
		}
	}

	// Initialize tracing collector
	if w.config.TracingEnabled {
		w.tracer, err = NewTracingCollector(w.config, w.logger)
		if err != nil {
			return fmt.Errorf("failed to create tracing collector: %w", err)
		}
	}

	// Initialize alert manager
	if w.config.AlertingEnabled {
		w.alerter, err = NewAlertManager(w.config, w.logger)
		if err != nil {
			return fmt.Errorf("failed to create alert manager: %w", err)
		}
	}

	// Initialize health manager
	w.healthMgr, err = NewHealthManager(w.config, w.logger)
	if err != nil {
		return fmt.Errorf("failed to create health manager: %w", err)
	}

	return nil
}

func (w *WatchtowerService) fieldsToZapFields(fields map[string]interface{}) []zap.Field {
	zapFields := make([]zap.Field, 0, len(fields))
	
	for key, value := range fields {
		switch v := value.(type) {
		case string:
			zapFields = append(zapFields, zap.String(key, v))
		case int:
			zapFields = append(zapFields, zap.Int(key, v))
		case int64:
			zapFields = append(zapFields, zap.Int64(key, v))
		case float64:
			zapFields = append(zapFields, zap.Float64(key, v))
		case bool:
			zapFields = append(zapFields, zap.Bool(key, v))
		case time.Time:
			zapFields = append(zapFields, zap.Time(key, v))
		case time.Duration:
			zapFields = append(zapFields, zap.Duration(key, v))
		case error:
			zapFields = append(zapFields, zap.Error(v))
		default:
			zapFields = append(zapFields, zap.Any(key, v))
		}
	}
	
	return zapFields
}

func (w *WatchtowerService) updateSystemStats(stats *interfaces.SystemStats) {
	stats.Uptime = time.Since(w.startTime)
	stats.Version = "fortress-2.0.0"
	stats.LastHealthCheck = time.Now()
	
	// Update service status
	if stats.Services == nil {
		stats.Services = make(map[string]string)
	}
	
	stats.Services["watchtower"] = "running"
	
	// Get system metrics (simplified - would use proper system monitoring)
	stats.CPU = w.getCPUUsage()
	stats.Memory = w.getMemoryStats()
	stats.Disk = w.getDiskStats()
	stats.Network = w.getNetworkStats()
	stats.Goroutines = w.getGoroutineCount()
}

func (w *WatchtowerService) runSystemStatsCollection(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.statsTicker.C:
			w.mu.Lock()
			w.updateSystemStats(w.systemStats)
			w.mu.Unlock()

			// Record system metrics
			w.RecordMetric("watchtower.system.cpu", w.systemStats.CPU, nil)
			w.RecordMetric("watchtower.system.goroutines", float64(w.systemStats.Goroutines), nil)
			
			if w.systemStats.Memory != nil {
				w.RecordMetric("watchtower.system.memory.usage", w.systemStats.Memory.UsagePercent, nil)
			}
		}
	}
}

func (w *WatchtowerService) runPeriodicHealthChecks(ctx context.Context) {
	ticker := time.NewTicker(w.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.performHealthChecks(ctx)
		}
	}
}

func (w *WatchtowerService) performHealthChecks(ctx context.Context) {
	w.mu.RLock()
	checks := make(map[string]interfaces.HealthCheckFunc)
	for name, check := range w.healthChecks {
		checks[name] = check
	}
	w.mu.RUnlock()

	for name, check := range checks {
		go func(checkName string, checkFunc interfaces.HealthCheckFunc) {
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			status := checkFunc(checkCtx)
			if status != nil && status.Status == interfaces.HealthStatusUnhealthy {
				w.TriggerAlert(interfaces.AlertLevelWarning, 
					fmt.Sprintf("Health check failed: %s", checkName), 
					map[string]interface{}{
						"check_name": checkName,
						"status":     status,
					})
			}
		}(name, check)
	}
}

// System monitoring helper methods (simplified implementations)

func (w *WatchtowerService) getCPUUsage() float64 {
	// Placeholder - implement proper CPU monitoring
	return 25.5
}

func (w *WatchtowerService) getMemoryStats() *interfaces.MemoryStats {
	// Placeholder - implement proper memory monitoring
	return &interfaces.MemoryStats{
		Allocated:    1024 * 1024 * 50, // 50MB
		TotalAlloc:   1024 * 1024 * 100, // 100MB
		Sys:          1024 * 1024 * 75,  // 75MB
		NumGC:        10,
		UsagePercent: 66.7,
	}
}

func (w *WatchtowerService) getDiskStats() *interfaces.DiskStats {
	// Placeholder - implement proper disk monitoring
	return &interfaces.DiskStats{
		Total:        1024 * 1024 * 1024 * 100, // 100GB
		Used:         1024 * 1024 * 1024 * 25,  // 25GB
		Available:    1024 * 1024 * 1024 * 75,  // 75GB
		UsagePercent: 25.0,
	}
}

func (w *WatchtowerService) getNetworkStats() *interfaces.NetworkStats {
	// Placeholder - implement proper network monitoring
	return &interfaces.NetworkStats{
		BytesReceived: 1024 * 1024 * 10, // 10MB
		BytesSent:     1024 * 1024 * 5,  // 5MB
		PacketsReceived: 1000,
		PacketsSent:     500,
		Connections:     25,
	}
}

func (w *WatchtowerService) getGoroutineCount() int {
	// Placeholder - implement proper goroutine monitoring
	return 50
}

// Helper functions

func extractDomain(email string) string {
	// Extract domain from email address
	if email == "" {
		return "unknown"
	}
	
	atIndex := -1
	for i, c := range email {
		if c == '@' {
			atIndex = i
			break
		}
	}
	
	if atIndex >= 0 && atIndex < len(email)-1 {
		return email[atIndex+1:]
	}
	
	return "unknown"
}

// NoOpSpan is a no-operation span for when tracing is disabled
type NoOpSpan struct{}

func (s *NoOpSpan) End()                               {}
func (s *NoOpSpan) SetTag(key string, value interface{}) {}
func (s *NoOpSpan) SetError(err error)                 {}
func (s *NoOpSpan) GetTraceID() string                 { return "noop" }
func (s *NoOpSpan) GetSpanID() string                  { return "noop" }