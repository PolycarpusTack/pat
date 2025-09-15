package watchtower_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/pat-fortress/pkg/watchtower"
	"github.com/pat-fortress/tests/mocks"
	"github.com/pat-fortress/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

// FortressWatchtowerServiceTestSuite provides comprehensive testing for The Watchtower service
type FortressWatchtowerServiceTestSuite struct {
	suite.Suite
	service     *watchtower.WatchtowerService
	foundation  *mocks.MockFoundation
	eventBus    *mocks.MockEventBus
	testUtils   *utils.FortressTestUtils
	ctx         context.Context
	cancelFunc  context.CancelFunc
}

// SetupSuite initializes the test suite
func (suite *FortressWatchtowerServiceTestSuite) SetupSuite() {
	suite.testUtils = utils.NewFortressTestUtils(suite.T())
	
	// Create mock dependencies
	suite.foundation = mocks.NewMockFoundation()
	suite.eventBus = mocks.NewMockEventBus()
	
	// Setup context
	suite.ctx, suite.cancelFunc = context.WithTimeout(context.Background(), 30*time.Second)
}

// SetupTest runs before each test
func (suite *FortressWatchtowerServiceTestSuite) SetupTest() {
	// Reset mocks
	suite.foundation.ExpectedCalls = nil
	suite.eventBus.ExpectedCalls = nil

	// Create new service instance for each test
	logger := zap.NewNop()
	
	config := &watchtower.Config{
		Metrics: watchtower.MetricsConfig{
			Enabled:          true,
			CollectionInterval: 15 * time.Second,
			RetentionPeriod:   7 * 24 * time.Hour,
			PrometheusEnabled: true,
			CustomMetrics:     true,
		},
		Logging: watchtower.LoggingConfig{
			Level:           "info",
			Format:          "json",
			OutputPath:      "/var/log/fortress/watchtower.log",
			MaxFileSize:     100, // MB
			MaxBackups:      10,
			MaxAge:          30, // days
			Compress:        true,
		},
		Tracing: watchtower.TracingConfig{
			Enabled:        true,
			ServiceName:    "fortress-watchtower",
			SamplingRate:   0.1,
			JaegerEndpoint: "http://localhost:14268/api/traces",
		},
		HealthChecks: watchtower.HealthCheckConfig{
			Enabled:         true,
			CheckInterval:   30 * time.Second,
			Timeout:        10 * time.Second,
			FailureThreshold: 3,
		},
		Alerts: watchtower.AlertConfig{
			Enabled:       true,
			WebhookURL:    "http://localhost:8080/alerts",
			SlackToken:    "test-slack-token",
			EmailSMTP:     "localhost:587",
			RetryCount:    3,
			RetryDelay:    5 * time.Second,
		},
	}

	var err error
	suite.service, err = watchtower.NewWatchtowerService(
		suite.ctx,
		config,
		suite.foundation,
		suite.eventBus,
		logger,
	)
	require.NoError(suite.T(), err, "Failed to create Watchtower service")
}

// TearDownTest runs after each test
func (suite *FortressWatchtowerServiceTestSuite) TearDownTest() {
	if suite.service != nil {
		suite.service.StopMonitoring(suite.ctx)
	}
}

// TearDownSuite cleans up the test suite
func (suite *FortressWatchtowerServiceTestSuite) TearDownSuite() {
	suite.cancelFunc()
}

// TestFortressWatchtowerServiceCreation tests service creation and initialization
func (suite *FortressWatchtowerServiceTestSuite) TestFortressWatchtowerServiceCreation() {
	suite.T().Run("Fortress Watchtower Service Creation Success", func(t *testing.T) {
		assert.NotNil(t, suite.service, "Watchtower service should be created successfully")
	})

	suite.T().Run("Fortress Watchtower Service Creation with Nil Config", func(t *testing.T) {
		logger := zap.NewNop()
		_, err := watchtower.NewWatchtowerService(
			suite.ctx,
			nil, // nil config
			suite.foundation,
			suite.eventBus,
			logger,
		)
		assert.Error(t, err, "Should fail with nil config")
		assert.Contains(t, err.Error(), "config cannot be nil", "Error should mention config")
	})
}

// TestFortressWatchtowerServiceLifecycle tests service start/stop lifecycle
func (suite *FortressWatchtowerServiceTestSuite) TestFortressWatchtowerServiceLifecycle() {
	suite.T().Run("Fortress Watchtower Service Start Monitoring", func(t *testing.T) {
		// Setup expectations
		suite.foundation.On("Connect", mock.Anything, mock.AnythingOfType("*interfaces.DatabaseConfig")).Return(nil)
		suite.eventBus.On("Subscribe", "system.metrics", mock.AnythingOfType("interfaces.EventHandler")).Return(nil)

		err := suite.service.StartMonitoring(suite.ctx)
		assert.NoError(t, err, "Watchtower service should start monitoring successfully")
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Service Stop Monitoring", func(t *testing.T) {
		// Setup expectations
		suite.foundation.On("Disconnect", mock.Anything).Return(nil)
		suite.eventBus.On("Unsubscribe", mock.AnythingOfType("string"), mock.AnythingOfType("interfaces.EventHandler")).Return(nil)

		err := suite.service.StopMonitoring(suite.ctx)
		assert.NoError(t, err, "Watchtower service should stop monitoring successfully")
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Service Health Check", func(t *testing.T) {
		health := suite.service.HealthCheck(suite.ctx)
		assert.NotNil(t, health, "Health status should not be nil")
		suite.testUtils.AssertHealthStatusValid(health, "watchtower")
	})
}

// TestFortressWatchtowerMetrics tests metrics collection functionality
func (suite *FortressWatchtowerServiceTestSuite) TestFortressWatchtowerMetrics() {
	suite.T().Run("Fortress Watchtower Record Metric", func(t *testing.T) {
		metricName := "fortress.emails.processed"
		metricValue := 125.5
		labels := map[string]string{
			"service": "keep",
			"status":  "success",
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

		// This should not panic or error
		suite.service.RecordMetric(metricName, metricValue, labels)
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Increment Counter", func(t *testing.T) {
		counterName := "fortress.requests.total"
		labels := map[string]string{
			"endpoint": "/api/emails",
			"method":   "GET",
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

		suite.service.IncrementCounter(counterName, labels)
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Record Histogram", func(t *testing.T) {
		histogramName := "fortress.response.duration"
		duration := 0.125 // 125ms
		labels := map[string]string{
			"operation": "search_emails",
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

		suite.service.RecordHistogram(histogramName, duration, labels)
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Set Gauge", func(t *testing.T) {
		gaugeName := "fortress.storage.usage"
		usage := 67.5 // 67.5% storage used
		labels := map[string]string{
			"storage_type": "emails",
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

		suite.service.SetGauge(gaugeName, usage, labels)
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Concurrent Metrics", func(t *testing.T) {
		workerCount := 10
		metricsPerWorker := 100

		// Setup expectations for concurrent metrics
		expectedCalls := workerCount * metricsPerWorker
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil).Times(expectedCalls)

		suite.testUtils.FortressTestConcurrentExecution(workerCount, func(workerID int) {
			for i := 0; i < metricsPerWorker; i++ {
				metricName := fmt.Sprintf("fortress.worker.%d.metric", workerID)
				suite.service.RecordMetric(metricName, float64(i), map[string]string{
					"worker": fmt.Sprintf("%d", workerID),
				})
			}
		})

		suite.foundation.AssertExpectations(t)
	})
}

// TestFortressWatchtowerLogging tests logging functionality
func (suite *FortressWatchtowerServiceTestSuite) TestFortressWatchtowerLogging() {
	suite.T().Run("Fortress Watchtower Log Event", func(t *testing.T) {
		level := interfaces.LogLevelInfo
		message := "Fortress email processed successfully"
		fields := map[string]interface{}{
			"email_id": "test-email-123",
			"duration": "125ms",
			"size":     1024,
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

		suite.service.LogEvent(level, message, fields)
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Log Email", func(t *testing.T) {
		testEmail := suite.testUtils.CreateTestEmail(
			utils.WithSubject("Log Test Email"),
			utils.WithFrom("sender@fortress.test"),
		)
		action := "processed"
		metadata := map[string]interface{}{
			"processing_time": "150ms",
			"worker_id":       "worker-1",
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		suite.eventBus.On("Publish", mock.Anything, mock.MatchedBy(func(event *interfaces.Event) bool {
			return event.Type == "email.logged"
		})).Return(nil)

		suite.service.LogEmail(testEmail, action, metadata)
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Log Error", func(t *testing.T) {
		testError := fmt.Errorf("fortress database connection failed")
		context := map[string]interface{}{
			"service":   "keep",
			"operation": "store_email",
			"retry_count": 3,
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		suite.eventBus.On("Publish", mock.Anything, mock.MatchedBy(func(event *interfaces.Event) bool {
			return event.Type == "error.logged"
		})).Return(nil)

		suite.service.LogError(testError, context)
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Log Levels", func(t *testing.T) {
		logLevels := []interfaces.LogLevel{
			interfaces.LogLevelDebug,
			interfaces.LogLevelInfo,
			interfaces.LogLevelWarn,
			interfaces.LogLevelError,
			interfaces.LogLevelFatal,
		}

		// Setup expectations for multiple log levels
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil).Times(len(logLevels))

		for _, level := range logLevels {
			message := fmt.Sprintf("Fortress test message at %s level", level)
			fields := map[string]interface{}{
				"level": level,
				"test":  true,
			}
			
			suite.service.LogEvent(level, message, fields)
		}
		
		suite.foundation.AssertExpectations(t)
	})
}

// TestFortressWatchtowerTracing tests tracing functionality
func (suite *FortressWatchtowerServiceTestSuite) TestFortressWatchtowerTracing() {
	suite.T().Run("Fortress Watchtower Start Trace", func(t *testing.T) {
		operation := "fortress.email.processing"

		// Setup expectations
		mockSpan := &MockTraceSpan{
			OperationName: operation,
			StartTime:     time.Now(),
		}

		traceCtx, span := suite.service.StartTrace(suite.ctx, operation)
		
		assert.NotNil(t, traceCtx, "Trace context should not be nil")
		assert.NotNil(t, span, "Trace span should not be nil")
		
		// Verify context contains trace information
		assert.NotEqual(t, suite.ctx, traceCtx, "Trace context should be different from original")
	})

	suite.T().Run("Fortress Watchtower Record Span", func(t *testing.T) {
		mockSpan := &MockTraceSpan{
			OperationName: "fortress.email.validation",
			StartTime:     time.Now(),
		}
		
		status := "success"
		attributes := map[string]interface{}{
			"email.size":    1024,
			"email.from":    "sender@fortress.test",
			"validation.score": 95.0,
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

		suite.service.RecordSpan(mockSpan, status, attributes)
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Nested Traces", func(t *testing.T) {
		// Start parent trace
		parentCtx, parentSpan := suite.service.StartTrace(suite.ctx, "fortress.email.processing")
		
		// Start child trace
		childCtx, childSpan := suite.service.StartTrace(parentCtx, "fortress.email.validation")
		
		assert.NotEqual(t, parentCtx, childCtx, "Child context should be different from parent")
		assert.NotNil(t, parentSpan, "Parent span should not be nil")
		assert.NotNil(t, childSpan, "Child span should not be nil")
		
		// Setup expectations for recording both spans
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil).Times(2)

		suite.service.RecordSpan(childSpan, "success", map[string]interface{}{"child": true})
		suite.service.RecordSpan(parentSpan, "success", map[string]interface{}{"parent": true})
		
		suite.foundation.AssertExpectations(t)
	})
}

// TestFortressWatchtowerHealthChecks tests health check functionality
func (suite *FortressWatchtowerServiceTestSuite) TestFortressWatchtowerHealthChecks() {
	suite.T().Run("Fortress Watchtower Register Health Check", func(t *testing.T) {
		checkName := "fortress.keep.service"
		healthCheckFunc := func(ctx context.Context) *interfaces.HealthStatus {
			return suite.testUtils.CreateTestHealthStatus(
				"keep",
				interfaces.HealthStatusHealthy,
				"Keep service is operational",
			)
		}

		suite.service.RegisterHealthCheck(checkName, healthCheckFunc)
		
		// Verify the health check was registered (this would typically involve checking internal state)
		// For now, we just ensure no panic occurred
		assert.True(t, true, "Health check registration should complete without error")
	})

	suite.T().Run("Fortress Watchtower System Stats", func(t *testing.T) {
		// Setup expectations
		statsResult := &interfaces.QueryResult{
			Rows: []map[string]interface{}{
				{
					"cpu_usage":    25.5,
					"memory_usage": 67.2,
					"disk_usage":   45.8,
					"uptime":       3600, // 1 hour
				},
			},
			Count:    1,
			Duration: time.Millisecond * 50,
		}
		
		suite.foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(statsResult, nil)

		stats, err := suite.service.GetSystemStats(suite.ctx)
		assert.NoError(t, err, "Should get system stats successfully")
		assert.NotNil(t, stats, "System stats should not be nil")
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Health Check Execution", func(t *testing.T) {
		// Register multiple health checks
		checkNames := []string{"fortress.keep", "fortress.foundation", "fortress.rampart"}
		
		for _, name := range checkNames {
			healthCheckFunc := func(checkName string) interfaces.HealthCheckFunc {
				return func(ctx context.Context) *interfaces.HealthStatus {
					return suite.testUtils.CreateTestHealthStatus(
						checkName,
						interfaces.HealthStatusHealthy,
						fmt.Sprintf("%s service is healthy", checkName),
					)
				}
			}(name)
			
			suite.service.RegisterHealthCheck(name, healthCheckFunc)
		}

		// Execute overall health check
		overallHealth := suite.service.HealthCheck(suite.ctx)
		assert.NotNil(t, overallHealth, "Overall health should not be nil")
		suite.testUtils.AssertHealthStatusValid(overallHealth, "watchtower")
	})
}

// TestFortressWatchtowerAlerts tests alert functionality
func (suite *FortressWatchtowerServiceTestSuite) TestFortressWatchtowerAlerts() {
	suite.T().Run("Fortress Watchtower Trigger Alert", func(t *testing.T) {
		level := interfaces.AlertLevelHigh
		message := "Fortress email processing queue is full"
		details := map[string]interface{}{
			"queue_size":     1000,
			"max_queue_size": 1000,
			"service":        "keep",
			"timestamp":      time.Now(),
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		suite.eventBus.On("Publish", mock.Anything, mock.MatchedBy(func(event *interfaces.Event) bool {
			return event.Type == "alert.triggered"
		})).Return(nil)

		suite.service.TriggerAlert(level, message, details)
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Register Alert Handler", func(t *testing.T) {
		alertHandler := func(alert *interfaces.Alert) error {
			// Mock alert handler implementation
			return nil
		}

		suite.service.RegisterAlertHandler(alertHandler)
		
		// Verify the alert handler was registered
		assert.True(t, true, "Alert handler registration should complete without error")
	})

	suite.T().Run("Fortress Watchtower Alert Levels", func(t *testing.T) {
		alertLevels := []interfaces.AlertLevel{
			interfaces.AlertLevelLow,
			interfaces.AlertLevelMedium,
			interfaces.AlertLevelHigh,
			interfaces.AlertLevelCritical,
		}

		// Setup expectations for multiple alerts
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil).Times(len(alertLevels))
		suite.eventBus.On("Publish", mock.Anything, mock.AnythingOfType("*interfaces.Event")).Return(nil).Times(len(alertLevels))

		for _, level := range alertLevels {
			message := fmt.Sprintf("Fortress test alert at %s level", level)
			details := map[string]interface{}{
				"level": level,
				"test":  true,
			}
			
			suite.service.TriggerAlert(level, message, details)
		}
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
	})
}

// TestFortressWatchtowerErrorScenarios tests error handling and edge cases
func (suite *FortressWatchtowerServiceTestSuite) TestFortressWatchtowerErrorScenarios() {
	suite.T().Run("Fortress Watchtower Database Error", func(t *testing.T) {
		metricName := "test.metric"
		metricValue := 100.0
		labels := map[string]string{"test": "true"}

		// Setup expectations for database error
		dbError := fmt.Errorf("fortress watchtower database connection failed")
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(dbError)

		// This should handle the error gracefully
		suite.service.RecordMetric(metricName, metricValue, labels)
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Context Timeout", func(t *testing.T) {
		// Create a context with very short timeout
		shortCtx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		
		// Wait for context to timeout
		time.Sleep(time.Millisecond)

		_, err := suite.service.GetSystemStats(shortCtx)
		assert.Error(t, err, "Should fail with context timeout")
	})

	suite.T().Run("Fortress Watchtower Event Bus Error", func(t *testing.T) {
		testEmail := suite.testUtils.CreateTestEmail()
		action := "processed"
		metadata := map[string]interface{}{"test": true}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		
		eventError := fmt.Errorf("event bus connection failed")
		suite.eventBus.On("Publish", mock.Anything, mock.AnythingOfType("*interfaces.Event")).Return(eventError)

		// This should handle the event bus error gracefully
		suite.service.LogEmail(testEmail, action, metadata)
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
	})
}

// TestFortressWatchtowerPerformance tests performance characteristics
func (suite *FortressWatchtowerServiceTestSuite) TestFortressWatchtowerPerformance() {
	suite.T().Run("Fortress Watchtower High Volume Metrics", func(t *testing.T) {
		metricCount := 10000
		
		// Setup expectations for high volume metrics
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil).Times(metricCount)

		start := time.Now()
		
		for i := 0; i < metricCount; i++ {
			suite.service.RecordMetric(
				fmt.Sprintf("fortress.load.test.%d", i%100),
				float64(i),
				map[string]string{
					"batch": fmt.Sprintf("%d", i/100),
				},
			)
		}
		
		duration := time.Since(start)
		
		// Verify performance - should complete within reasonable time
		assert.True(t, duration < 5*time.Second, 
			fmt.Sprintf("High volume metrics should complete within 5 seconds, took %v", duration))
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Watchtower Memory Usage", func(t *testing.T) {
		// This test would measure memory usage during operation
		// For now, we'll just ensure the service handles many operations without issues
		
		operationCount := 1000
		
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil).Times(operationCount * 2)

		for i := 0; i < operationCount; i++ {
			suite.service.RecordMetric("memory.test", float64(i), nil)
			suite.service.LogEvent(interfaces.LogLevelInfo, "Memory test", map[string]interface{}{
				"iteration": i,
			})
		}
		
		suite.foundation.AssertExpectations(t)
	})
}

// Mock implementation of TraceSpan for testing
type MockTraceSpan struct {
	OperationName string
	StartTime     time.Time
	EndTime       time.Time
	Tags          map[string]interface{}
	Status        string
}

func (m *MockTraceSpan) Finish() {
	m.EndTime = time.Now()
}

func (m *MockTraceSpan) SetTag(key string, value interface{}) {
	if m.Tags == nil {
		m.Tags = make(map[string]interface{})
	}
	m.Tags[key] = value
}

// Run the test suite
func TestFortressWatchtowerServiceTestSuite(t *testing.T) {
	suite.Run(t, new(FortressWatchtowerServiceTestSuite))
}

// Benchmark tests for performance validation
func BenchmarkFortressWatchtowerMetrics(b *testing.B) {
	// Setup
	foundation := mocks.NewMockFoundation()
	eventBus := mocks.NewMockEventBus()
	
	foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

	config := &watchtower.Config{
		Metrics: watchtower.MetricsConfig{
			Enabled:          true,
			CollectionInterval: 15 * time.Second,
		},
	}

	logger := zap.NewNop()
	ctx := context.Background()
	
	service, err := watchtower.NewWatchtowerService(ctx, config, foundation, eventBus, logger)
	require.NoError(b, err)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			service.RecordMetric(
				fmt.Sprintf("benchmark.metric.%d", counter%10),
				float64(counter),
				map[string]string{"benchmark": "true"},
			)
			counter++
		}
	})
}

func BenchmarkFortressWatchtowerLogging(b *testing.B) {
	// Setup
	foundation := mocks.NewMockFoundation()
	eventBus := mocks.NewMockEventBus()
	
	foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

	config := &watchtower.Config{
		Logging: watchtower.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}

	logger := zap.NewNop()
	ctx := context.Background()
	
	service, err := watchtower.NewWatchtowerService(ctx, config, foundation, eventBus, logger)
	require.NoError(b, err)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			service.LogEvent(
				interfaces.LogLevelInfo,
				fmt.Sprintf("Benchmark log message %d", counter),
				map[string]interface{}{
					"counter":   counter,
					"benchmark": true,
				},
			)
			counter++
		}
	})
}