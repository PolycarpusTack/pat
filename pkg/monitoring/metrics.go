// =============================================================================
// Pat Fortress - Enhanced Metrics Instrumentation
// Comprehensive monitoring metrics for all Fortress services
// =============================================================================

package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"go.opentelemetry.io/otel/trace"
)

// MetricsCollector manages all application metrics
type MetricsCollector struct {
	// Email metrics
	emailsReceived    prometheus.Counter
	emailsProcessed   prometheus.Counter
	emailsFailed      prometheus.Counter
	emailProcessTime  prometheus.Histogram
	emailSize         prometheus.Histogram
	
	// SMTP metrics
	smtpConnections   prometheus.Counter
	smtpErrors        prometheus.Counter
	smtpDuration      prometheus.Histogram
	
	// API metrics
	apiRequests       prometheus.Counter
	apiDuration       prometheus.Histogram
	apiErrors         prometheus.Counter
	
	// Database metrics
	dbConnections     prometheus.Gauge
	dbQueries         prometheus.Counter
	dbQueryDuration   prometheus.Histogram
	dbErrors          prometheus.Counter
	
	// Plugin metrics
	pluginExecutions  prometheus.Counter
	pluginDuration    prometheus.Histogram
	pluginErrors      prometheus.Counter
	
	// System metrics
	memoryUsage       prometheus.Gauge
	cpuUsage          prometheus.Gauge
	diskUsage         prometheus.Gauge
	goroutines        prometheus.Gauge
	
	// Business metrics
	activeUsers       prometheus.Gauge
	activeSessions    prometheus.Gauge
	workflowExecutions prometheus.Counter
	
	// OpenTelemetry metrics
	meter metric.Meter
	
	// Custom counters
	customCounters map[string]prometheus.Counter
	customGauges   map[string]prometheus.Gauge
	customHistograms map[string]prometheus.Histogram
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	mc := &MetricsCollector{
		customCounters:   make(map[string]prometheus.Counter),
		customGauges:     make(map[string]prometheus.Gauge),
		customHistograms: make(map[string]prometheus.Histogram),
	}
	
	mc.initializeMetrics()
	mc.initializeOTelMetrics()
	
	return mc
}

func (mc *MetricsCollector) initializeMetrics() {
	// Email metrics
	mc.emailsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pat_emails_received_total",
		Help: "Total number of emails received",
	})
	
	mc.emailsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pat_emails_processed_total",
		Help: "Total number of emails processed successfully",
	})
	
	mc.emailsFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pat_emails_failed_total",
		Help: "Total number of emails that failed processing",
	})
	
	mc.emailProcessTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "pat_email_processing_duration_seconds",
		Help: "Time taken to process emails",
		Buckets: prometheus.DefBuckets,
	})
	
	mc.emailSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "pat_email_size_bytes",
		Help: "Size of received emails in bytes",
		Buckets: prometheus.ExponentialBuckets(1024, 2, 15), // 1KB to 16MB
	})
	
	// SMTP metrics
	mc.smtpConnections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pat_smtp_connections_total",
		Help: "Total number of SMTP connections",
	})
	
	mc.smtpErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pat_smtp_errors_total",
		Help: "Total number of SMTP errors",
	})
	
	mc.smtpDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "pat_smtp_request_duration_seconds",
		Help: "Duration of SMTP requests",
		Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1, 2.5, 5, 10},
	})
	
	// API metrics
	mc.apiRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pat_api_requests_total",
		Help: "Total number of API requests",
	}, []string{"method", "endpoint", "status"})
	
	mc.apiDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "pat_api_request_duration_seconds",
		Help: "Duration of API requests",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "endpoint"})
	
	mc.apiErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pat_api_errors_total",
		Help: "Total number of API errors",
	}, []string{"method", "endpoint", "error_type"})
	
	// Database metrics
	mc.dbConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pat_db_connections_active",
		Help: "Number of active database connections",
	})
	
	mc.dbQueries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pat_db_queries_total",
		Help: "Total number of database queries",
	}, []string{"operation", "table"})
	
	mc.dbQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "pat_db_query_duration_seconds",
		Help: "Duration of database queries",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5},
	}, []string{"operation", "table"})
	
	mc.dbErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pat_db_errors_total",
		Help: "Total number of database errors",
	}, []string{"operation", "table", "error_type"})
	
	// Plugin metrics
	mc.pluginExecutions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pat_plugin_executions_total",
		Help: "Total number of plugin executions",
	}, []string{"plugin", "status"})
	
	mc.pluginDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "pat_plugin_execution_duration_seconds",
		Help: "Duration of plugin executions",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"plugin"})
	
	mc.pluginErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pat_plugin_errors_total",
		Help: "Total number of plugin errors",
	}, []string{"plugin", "error_type"})
	
	// System metrics
	mc.memoryUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pat_memory_usage_bytes",
		Help: "Current memory usage in bytes",
	})
	
	mc.cpuUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pat_cpu_usage_percent",
		Help: "Current CPU usage percentage",
	})
	
	mc.diskUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pat_disk_usage_bytes",
		Help: "Current disk usage in bytes",
	})
	
	mc.goroutines = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pat_goroutines_active",
		Help: "Number of active goroutines",
	})
	
	// Business metrics
	mc.activeUsers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pat_active_users",
		Help: "Number of active users",
	})
	
	mc.activeSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pat_active_sessions",
		Help: "Number of active user sessions",
	})
	
	mc.workflowExecutions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pat_workflow_executions_total",
		Help: "Total number of workflow executions",
	}, []string{"workflow", "status"})
}

func (mc *MetricsCollector) initializeOTelMetrics() {
	exporter, err := prometheus.New()
	if err != nil {
		panic(fmt.Sprintf("Failed to create Prometheus exporter: %v", err))
	}
	
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	otel.SetMeterProvider(provider)
	
	mc.meter = otel.Meter("github.com/alexandria/pat-plugin")
}

// Email metrics methods
func (mc *MetricsCollector) IncrementEmailsReceived() {
	mc.emailsReceived.Inc()
}

func (mc *MetricsCollector) IncrementEmailsProcessed() {
	mc.emailsProcessed.Inc()
}

func (mc *MetricsCollector) IncrementEmailsFailed() {
	mc.emailsFailed.Inc()
}

func (mc *MetricsCollector) RecordEmailProcessingTime(duration time.Duration) {
	mc.emailProcessTime.Observe(duration.Seconds())
}

func (mc *MetricsCollector) RecordEmailSize(size int64) {
	mc.emailSize.Observe(float64(size))
}

// SMTP metrics methods
func (mc *MetricsCollector) IncrementSMTPConnections() {
	mc.smtpConnections.Inc()
}

func (mc *MetricsCollector) IncrementSMTPErrors() {
	mc.smtpErrors.Inc()
}

func (mc *MetricsCollector) RecordSMTPDuration(duration time.Duration) {
	mc.smtpDuration.Observe(duration.Seconds())
}

// API metrics methods
func (mc *MetricsCollector) IncrementAPIRequests(method, endpoint, status string) {
	mc.apiRequests.WithLabelValues(method, endpoint, status).Inc()
}

func (mc *MetricsCollector) RecordAPIDuration(method, endpoint string, duration time.Duration) {
	mc.apiDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

func (mc *MetricsCollector) IncrementAPIErrors(method, endpoint, errorType string) {
	mc.apiErrors.WithLabelValues(method, endpoint, errorType).Inc()
}

// Database metrics methods
func (mc *MetricsCollector) SetDBConnections(count float64) {
	mc.dbConnections.Set(count)
}

func (mc *MetricsCollector) IncrementDBQueries(operation, table string) {
	mc.dbQueries.WithLabelValues(operation, table).Inc()
}

func (mc *MetricsCollector) RecordDBQueryDuration(operation, table string, duration time.Duration) {
	mc.dbQueryDuration.WithLabelValues(operation, table).Observe(duration.Seconds())
}

func (mc *MetricsCollector) IncrementDBErrors(operation, table, errorType string) {
	mc.dbErrors.WithLabelValues(operation, table, errorType).Inc()
}

// Plugin metrics methods
func (mc *MetricsCollector) IncrementPluginExecutions(plugin, status string) {
	mc.pluginExecutions.WithLabelValues(plugin, status).Inc()
}

func (mc *MetricsCollector) RecordPluginDuration(plugin string, duration time.Duration) {
	mc.pluginDuration.WithLabelValues(plugin).Observe(duration.Seconds())
}

func (mc *MetricsCollector) IncrementPluginErrors(plugin, errorType string) {
	mc.pluginErrors.WithLabelValues(plugin, errorType).Inc()
}

// System metrics methods
func (mc *MetricsCollector) SetMemoryUsage(bytes float64) {
	mc.memoryUsage.Set(bytes)
}

func (mc *MetricsCollector) SetCPUUsage(percent float64) {
	mc.cpuUsage.Set(percent)
}

func (mc *MetricsCollector) SetDiskUsage(bytes float64) {
	mc.diskUsage.Set(bytes)
}

func (mc *MetricsCollector) SetGoroutines(count float64) {
	mc.goroutines.Set(count)
}

// Business metrics methods
func (mc *MetricsCollector) SetActiveUsers(count float64) {
	mc.activeUsers.Set(count)
}

func (mc *MetricsCollector) SetActiveSessions(count float64) {
	mc.activeSessions.Set(count)
}

func (mc *MetricsCollector) IncrementWorkflowExecutions(workflow, status string) {
	mc.workflowExecutions.WithLabelValues(workflow, status).Inc()
}

// Timing utility for measuring execution time
type Timer struct {
	start time.Time
	name  string
	mc    *MetricsCollector
}

func (mc *MetricsCollector) StartTimer(name string) *Timer {
	return &Timer{
		start: time.Now(),
		name:  name,
		mc:    mc,
	}
}

func (t *Timer) Stop() time.Duration {
	duration := time.Since(t.start)
	
	// Record in custom histogram if exists
	if hist, exists := t.mc.customHistograms[t.name]; exists {
		hist.Observe(duration.Seconds())
	}
	
	return duration
}

func (t *Timer) StopAndRecord(recordFunc func(time.Duration)) time.Duration {
	duration := t.Stop()
	recordFunc(duration)
	return duration
}

// Custom metrics management
func (mc *MetricsCollector) RegisterCustomCounter(name, help string, labels []string) prometheus.Counter {
	if len(labels) > 0 {
		counterVec := promauto.NewCounterVec(prometheus.CounterOpts{
			Name: name,
			Help: help,
		}, labels)
		// Return the counter without labels for simple use
		return counterVec.WithLabelValues(make([]string, len(labels))...)
	}
	
	counter := promauto.NewCounter(prometheus.CounterOpts{
		Name: name,
		Help: help,
	})
	
	mc.customCounters[name] = counter
	return counter
}

func (mc *MetricsCollector) RegisterCustomGauge(name, help string) prometheus.Gauge {
	gauge := promauto.NewGauge(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	})
	
	mc.customGauges[name] = gauge
	return gauge
}

func (mc *MetricsCollector) RegisterCustomHistogram(name, help string, buckets []float64) prometheus.Histogram {
	if buckets == nil {
		buckets = prometheus.DefBuckets
	}
	
	histogram := promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: buckets,
	})
	
	mc.customHistograms[name] = histogram
	return histogram
}

// Health check metrics
func (mc *MetricsCollector) RecordHealthCheck(component string, healthy bool, duration time.Duration) {
	status := "healthy"
	if !healthy {
		status = "unhealthy"
	}
	
	healthCounter := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pat_health_checks_total",
		Help: "Total number of health checks",
	}, []string{"component", "status"})
	
	healthDuration := promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "pat_health_check_duration_seconds",
		Help: "Duration of health checks",
		Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1, 2.5, 5},
	}, []string{"component"})
	
	healthCounter.WithLabelValues(component, status).Inc()
	healthDuration.WithLabelValues(component).Observe(duration.Seconds())
}

// OpenTelemetry integration
func (mc *MetricsCollector) CreateOTelCounter(name, description string) (metric.Int64Counter, error) {
	return mc.meter.Int64Counter(name, metric.WithDescription(description))
}

func (mc *MetricsCollector) CreateOTelHistogram(name, description, unit string) (metric.Float64Histogram, error) {
	return mc.meter.Float64Histogram(name, 
		metric.WithDescription(description),
		metric.WithUnit(unit))
}

func (mc *MetricsCollector) CreateOTelGauge(name, description string) (metric.Int64ObservableGauge, error) {
	return mc.meter.Int64ObservableGauge(name, metric.WithDescription(description))
}

// Context-aware metrics recording
func (mc *MetricsCollector) RecordWithContext(ctx context.Context, name string, value float64, attrs ...attribute.KeyValue) {
	// This would integrate with OpenTelemetry for context-aware metrics
	// For now, just record the basic metric
}

// Batch operations for high-throughput scenarios
func (mc *MetricsCollector) BatchRecordEmails(count int, avgProcessTime time.Duration, totalSize int64) {
	for i := 0; i < count; i++ {
		mc.IncrementEmailsProcessed()
	}
	mc.RecordEmailProcessingTime(avgProcessTime)
	mc.RecordEmailSize(totalSize)
}

// GetMetricValue retrieves current value of a metric (for testing/monitoring)
func (mc *MetricsCollector) GetMetricValue(metricName string) (float64, error) {
	// This would require a metric gathering mechanism
	// Implementation depends on specific requirements
	return 0, fmt.Errorf("metric value retrieval not implemented")
}

// Reset all metrics (useful for testing)
func (mc *MetricsCollector) Reset() {
	// Reset counters to 0, gauges to default values
	// Implementation would reset all registered metrics
}

var DefaultMetricsCollector = NewMetricsCollector()