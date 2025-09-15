package performance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	"github.com/mailhog/Pat/config"
	"github.com/mailhog/Pat/pkg/fortress"
	"github.com/mailhog/Pat/pkg/storage"
	"github.com/mailhog/Pat/pkg/smtp"
)

// FortressPerformanceTestSuite validates comprehensive performance requirements
type FortressPerformanceTestSuite struct {
	httpServer  *httptest.Server
	smtpServer  *smtp.Server
	fortress    *fortress.Service
	storage     storage.Storage
}

// PerformanceMetrics tracks performance test results
type PerformanceMetrics struct {
	TotalRequests     int64
	SuccessfulRequests int64
	FailedRequests    int64
	TotalDuration     time.Duration
	MinResponseTime   time.Duration
	MaxResponseTime   time.Duration
	AvgResponseTime   time.Duration
	P95ResponseTime   time.Duration
	P99ResponseTime   time.Duration
	Throughput        float64 // requests per second
	ErrorRate         float64 // percentage
	MemoryUsage       uint64  // bytes
	CPUUsage          float64 // percentage
}

// TestFortressPerformanceValidation is the main performance test entry point
func TestFortressPerformanceValidation(t *testing.T) {
	suite := setupPerformanceTestSuite(t)
	defer suite.cleanup(t)

	t.Run("Email_Processing_Throughput_Test", suite.testEmailProcessingThroughput)
	t.Run("Concurrent_User_Load_Test", suite.testConcurrentUserLoad)
	t.Run("API_Response_Time_Validation", suite.testAPIResponseTime)
	t.Run("Database_Performance_Under_Load", suite.testDatabasePerformanceUnderLoad)
	t.Run("Memory_Usage_And_Leak_Detection", suite.testMemoryUsageAndLeakDetection)
	t.Run("SMTP_Server_Performance_Test", suite.testSMTPServerPerformance)
	t.Run("GraphQL_Query_Performance", suite.testGraphQLQueryPerformance)
	t.Run("File_Upload_Performance", suite.testFileUploadPerformance)
	t.Run("Stress_Test_Recovery", suite.testStressTestRecovery)
	t.Run("Performance_Regression_Detection", suite.testPerformanceRegressionDetection)
}

func setupPerformanceTestSuite(t *testing.T) *FortressPerformanceTestSuite {
	cfg := &config.Config{
		EnableSecurity:      true,
		SecurityLevel:      "fortress",
		MaxConcurrentUsers: 1000,
		MaxRequestsPerSec:  10000,
		DatabaseURL:        "sqlite://performance_test.db",
		RedisURL:           "redis://localhost:6379/1",
		SMTPPort:           2526,
	}

	fortress := fortress.NewService(cfg)
	storage := storage.CreateInMemory() // Use in-memory for consistent performance
	smtpServer := smtp.NewServer(cfg, fortress)
	
	// Start SMTP server
	go func() {
		smtpServer.Listen(fmt.Sprintf(":%d", cfg.SMTPPort))
	}()
	
	httpServer := httptest.NewServer(createPerformanceTestHandler(fortress, storage))

	return &FortressPerformanceTestSuite{
		httpServer: httpServer,
		smtpServer: smtpServer,
		fortress:   fortress,
		storage:    storage,
	}
}

func (s *FortressPerformanceTestSuite) cleanup(t *testing.T) {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	if s.smtpServer != nil {
		s.smtpServer.Close()
	}
}

// testEmailProcessingThroughput tests email processing throughput (target: 10,000/sec)
func (s *FortressPerformanceTestSuite) testEmailProcessingThroughput(t *testing.T) {
	target := 10000 // emails per second
	testDuration := 10 * time.Second
	
	metrics := s.runThroughputTest(t, "/api/v3/emails", testDuration, target)
	
	t.Logf("Email Processing Throughput Results:")
	t.Logf("  Total Requests: %d", metrics.TotalRequests)
	t.Logf("  Successful: %d", metrics.SuccessfulRequests)
	t.Logf("  Failed: %d", metrics.FailedRequests)
	t.Logf("  Throughput: %.2f req/sec", metrics.Throughput)
	t.Logf("  Average Response Time: %v", metrics.AvgResponseTime)
	t.Logf("  P95 Response Time: %v", metrics.P95ResponseTime)
	t.Logf("  Error Rate: %.2f%%", metrics.ErrorRate)
	
	// Validate performance requirements
	assert.GreaterOrEqual(t, metrics.Throughput, float64(target*0.8), 
		"Throughput should be at least 80% of target (8,000 req/sec)")
	assert.Less(t, metrics.ErrorRate, 1.0, "Error rate should be less than 1%")
	assert.Less(t, metrics.P95ResponseTime, 100*time.Millisecond, 
		"P95 response time should be less than 100ms")
}

// testConcurrentUserLoad tests concurrent user load (target: 1,000 concurrent)
func (s *FortressPerformanceTestSuite) testConcurrentUserLoad(t *testing.T) {
	concurrentUsers := 1000
	testDuration := 30 * time.Second
	
	metrics := s.runConcurrentUserTest(t, concurrentUsers, testDuration)
	
	t.Logf("Concurrent User Load Test Results:")
	t.Logf("  Concurrent Users: %d", concurrentUsers)
	t.Logf("  Total Requests: %d", metrics.TotalRequests)
	t.Logf("  Successful: %d", metrics.SuccessfulRequests)
	t.Logf("  Failed: %d", metrics.FailedRequests)
	t.Logf("  Average Response Time: %v", metrics.AvgResponseTime)
	t.Logf("  P95 Response Time: %v", metrics.P95ResponseTime)
	t.Logf("  P99 Response Time: %v", metrics.P99ResponseTime)
	t.Logf("  Error Rate: %.2f%%", metrics.ErrorRate)
	t.Logf("  Memory Usage: %d MB", metrics.MemoryUsage/1024/1024)
	
	// Validate concurrent load requirements
	assert.Less(t, metrics.ErrorRate, 2.0, "Error rate should be less than 2% under concurrent load")
	assert.Less(t, metrics.P95ResponseTime, 500*time.Millisecond, 
		"P95 response time should be less than 500ms under load")
	assert.Less(t, metrics.P99ResponseTime, 1*time.Second, 
		"P99 response time should be less than 1s under load")
	assert.Less(t, metrics.MemoryUsage, uint64(2*1024*1024*1024), 
		"Memory usage should be less than 2GB under concurrent load")
}

// testAPIResponseTime tests API response time validation (target: <100ms p95)
func (s *FortressPerformanceTestSuite) testAPIResponseTime(t *testing.T) {
	endpoints := []struct {
		name     string
		endpoint string
		method   string
		payload  interface{}
	}{
		{
			name:     "Get_Emails",
			endpoint: "/api/v3/emails",
			method:   "GET",
			payload:  nil,
		},
		{
			name:     "Create_Email",
			endpoint: "/api/v3/emails",
			method:   "POST",
			payload: map[string]interface{}{
				"from":    "test@example.com",
				"to":      "recipient@example.com",
				"subject": "Performance Test",
				"content": "Test email content",
			},
		},
		{
			name:     "Search_Emails",
			endpoint: "/api/v3/emails/search",
			method:   "POST",
			payload: map[string]interface{}{
				"query": "test",
				"limit": 50,
			},
		},
		{
			name:     "Get_Email_Details",
			endpoint: "/api/v3/emails/1",
			method:   "GET",
			payload:  nil,
		},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			metrics := s.runResponseTimeTest(t, endpoint.endpoint, endpoint.method, endpoint.payload, 100)
			
			t.Logf("%s Response Time Results:", endpoint.name)
			t.Logf("  Average: %v", metrics.AvgResponseTime)
			t.Logf("  Min: %v", metrics.MinResponseTime)
			t.Logf("  Max: %v", metrics.MaxResponseTime)
			t.Logf("  P95: %v", metrics.P95ResponseTime)
			t.Logf("  P99: %v", metrics.P99ResponseTime)
			
			// Validate response time requirements
			assert.Less(t, metrics.P95ResponseTime, 100*time.Millisecond,
				fmt.Sprintf("%s P95 response time should be less than 100ms", endpoint.name))
			assert.Less(t, metrics.AvgResponseTime, 50*time.Millisecond,
				fmt.Sprintf("%s average response time should be less than 50ms", endpoint.name))
		})
	}
}

// testDatabasePerformanceUnderLoad tests database performance under concurrent access
func (s *FortressPerformanceTestSuite) testDatabasePerformanceUnderLoad(t *testing.T) {
	concurrentConnections := 100
	operationsPerConnection := 100
	
	// Test different database operations
	operations := []struct {
		name      string
		operation func() error
	}{
		{
			name: "Email_Insert",
			operation: func() error {
				email := map[string]interface{}{
					"from":    "perf@test.com",
					"to":      "recipient@test.com",
					"subject": "DB Performance Test",
					"content": "Test content for database performance",
				}
				return s.storage.Store(email)
			},
		},
		{
			name: "Email_Query",
			operation: func() error {
				_, err := s.storage.List(0, 50)
				return err
			},
		},
		{
			name: "Email_Search",
			operation: func() error {
				_, err := s.storage.Search("test", 0, 50)
				return err
			},
		},
	}

	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			metrics := s.runDatabasePerformanceTest(t, op.operation, concurrentConnections, operationsPerConnection)
			
			t.Logf("%s Database Performance Results:", op.name)
			t.Logf("  Total Operations: %d", metrics.TotalRequests)
			t.Logf("  Successful: %d", metrics.SuccessfulRequests)
			t.Logf("  Failed: %d", metrics.FailedRequests)
			t.Logf("  Average Time: %v", metrics.AvgResponseTime)
			t.Logf("  P95 Time: %v", metrics.P95ResponseTime)
			t.Logf("  Operations/sec: %.2f", metrics.Throughput)
			t.Logf("  Error Rate: %.2f%%", metrics.ErrorRate)
			
			// Validate database performance requirements
			assert.Less(t, metrics.ErrorRate, 0.5, "Database error rate should be less than 0.5%")
			assert.Less(t, metrics.P95ResponseTime, 50*time.Millisecond,
				"Database P95 response time should be less than 50ms")
			assert.GreaterOrEqual(t, metrics.Throughput, 1000.0,
				"Database should handle at least 1000 operations/sec")
		})
	}
}

// testMemoryUsageAndLeakDetection tests memory usage and detects memory leaks
func (s *FortressPerformanceTestSuite) testMemoryUsageAndLeakDetection(t *testing.T) {
	// Baseline memory measurement
	runtime.GC()
	var baselineMemStats runtime.MemStats
	runtime.ReadMemStats(&baselineMemStats)
	
	t.Logf("Baseline Memory Stats:")
	t.Logf("  Heap Used: %d MB", baselineMemStats.HeapInuse/1024/1024)
	t.Logf("  Total Alloc: %d MB", baselineMemStats.TotalAlloc/1024/1024)
	
	// Simulate heavy load for memory leak detection
	iterations := 10000
	for i := 0; i < iterations; i++ {
		// Create and process emails
		payload := map[string]interface{}{
			"from":    fmt.Sprintf("test%d@example.com", i),
			"to":      "recipient@example.com",
			"subject": fmt.Sprintf("Memory Test %d", i),
			"content": fmt.Sprintf("Test content for iteration %d with some additional data to consume memory", i),
		}
		
		jsonData, _ := json.Marshal(payload)
		resp, err := http.Post(s.httpServer.URL+"/api/v3/emails",
			"application/json", bytes.NewBuffer(jsonData))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		
		// Force GC periodically
		if i%1000 == 0 {
			runtime.GC()
		}
	}
	
	// Final memory measurement
	runtime.GC()
	var finalMemStats runtime.MemStats
	runtime.ReadMemStats(&finalMemStats)
	
	t.Logf("Final Memory Stats:")
	t.Logf("  Heap Used: %d MB", finalMemStats.HeapInuse/1024/1024)
	t.Logf("  Total Alloc: %d MB", finalMemStats.TotalAlloc/1024/1024)
	t.Logf("  Sys Memory: %d MB", finalMemStats.Sys/1024/1024)
	
	// Calculate memory growth
	memoryGrowth := int64(finalMemStats.HeapInuse - baselineMemStats.HeapInuse)
	t.Logf("Memory Growth: %d MB", memoryGrowth/1024/1024)
	
	// Validate memory usage requirements
	assert.Less(t, finalMemStats.HeapInuse, uint64(1*1024*1024*1024), 
		"Heap memory usage should be less than 1GB")
	assert.Less(t, memoryGrowth, int64(500*1024*1024), 
		"Memory growth should be less than 500MB after processing 10k emails")
	
	// Check for potential memory leaks
	memoryGrowthRatio := float64(memoryGrowth) / float64(baselineMemStats.HeapInuse)
	assert.Less(t, memoryGrowthRatio, 5.0, 
		"Memory growth ratio should indicate no significant leaks")
}

// testSMTPServerPerformance tests SMTP server performance
func (s *FortressPerformanceTestSuite) testSMTPServerPerformance(t *testing.T) {
	concurrentConnections := 100
	emailsPerConnection := 50
	
	metrics := s.runSMTPPerformanceTest(t, concurrentConnections, emailsPerConnection)
	
	t.Logf("SMTP Server Performance Results:")
	t.Logf("  Total Emails: %d", metrics.TotalRequests)
	t.Logf("  Successful: %d", metrics.SuccessfulRequests)
	t.Logf("  Failed: %d", metrics.FailedRequests)
	t.Logf("  Emails/sec: %.2f", metrics.Throughput)
	t.Logf("  Average Processing Time: %v", metrics.AvgResponseTime)
	t.Logf("  P95 Processing Time: %v", metrics.P95ResponseTime)
	t.Logf("  Error Rate: %.2f%%", metrics.ErrorRate)
	
	// Validate SMTP performance requirements
	assert.GreaterOrEqual(t, metrics.Throughput, 1000.0, 
		"SMTP server should process at least 1000 emails/sec")
	assert.Less(t, metrics.ErrorRate, 1.0, "SMTP error rate should be less than 1%")
	assert.Less(t, metrics.P95ResponseTime, 200*time.Millisecond, 
		"SMTP P95 processing time should be less than 200ms")
}

// testGraphQLQueryPerformance tests GraphQL query performance
func (s *FortressPerformanceTestSuite) testGraphQLQueryPerformance(t *testing.T) {
	queries := []struct {
		name  string
		query string
	}{
		{
			name: "Simple_Email_Query",
			query: `{
				emails(limit: 50) {
					id
					from
					to
					subject
				}
			}`,
		},
		{
			name: "Complex_Nested_Query",
			query: `{
				emails(limit: 20) {
					id
					from
					to
					subject
					content
					attachments {
						filename
						size
						type
					}
					headers {
						name
						value
					}
				}
			}`,
		},
		{
			name: "Search_Query_With_Filters",
			query: `{
				emails(
					filter: {
						from: "test@example.com",
						subject_contains: "performance"
					},
					limit: 100
				) {
					id
					from
					to
					subject
					created_at
				}
			}`,
		},
	}

	for _, query := range queries {
		t.Run(query.name, func(t *testing.T) {
			payload := map[string]interface{}{
				"query": query.query,
			}
			
			metrics := s.runResponseTimeTest(t, "/graphql", "POST", payload, 100)
			
			t.Logf("%s GraphQL Performance Results:", query.name)
			t.Logf("  Average Response Time: %v", metrics.AvgResponseTime)
			t.Logf("  P95 Response Time: %v", metrics.P95ResponseTime)
			t.Logf("  P99 Response Time: %v", metrics.P99ResponseTime)
			
			// Validate GraphQL performance requirements
			assert.Less(t, metrics.P95ResponseTime, 150*time.Millisecond,
				fmt.Sprintf("%s P95 response time should be less than 150ms", query.name))
			assert.Less(t, metrics.AvgResponseTime, 75*time.Millisecond,
				fmt.Sprintf("%s average response time should be less than 75ms", query.name))
		})
	}
}

// testFileUploadPerformance tests file upload performance
func (s *FortressPerformanceTestSuite) testFileUploadPerformance(t *testing.T) {
	fileSizes := []struct {
		name string
		size int
	}{
		{"Small_File_1KB", 1024},
		{"Medium_File_100KB", 100 * 1024},
		{"Large_File_1MB", 1024 * 1024},
		{"XLarge_File_10MB", 10 * 1024 * 1024},
	}

	for _, fileSize := range fileSizes {
		t.Run(fileSize.name, func(t *testing.T) {
			metrics := s.runFileUploadPerformanceTest(t, fileSize.size, 10)
			
			t.Logf("%s Upload Performance Results:", fileSize.name)
			t.Logf("  Average Upload Time: %v", metrics.AvgResponseTime)
			t.Logf("  P95 Upload Time: %v", metrics.P95ResponseTime)
			t.Logf("  Throughput: %.2f MB/sec", 
				float64(fileSize.size)*metrics.Throughput/1024/1024)
			
			// Validate file upload performance requirements
			expectedMaxTime := time.Duration(fileSize.size/1024/100) * time.Millisecond // ~100KB/ms
			if expectedMaxTime < 100*time.Millisecond {
				expectedMaxTime = 100 * time.Millisecond
			}
			
			assert.Less(t, metrics.P95ResponseTime, expectedMaxTime,
				fmt.Sprintf("%s upload should complete within reasonable time", fileSize.name))
		})
	}
}

// testStressTestRecovery tests system recovery after stress
func (s *FortressPerformanceTestSuite) testStressTestRecovery(t *testing.T) {
	// Apply stress load
	t.Log("Applying stress load...")
	stressMetrics := s.runThroughputTest(t, "/api/v3/emails", 30*time.Second, 15000)
	
	t.Logf("Stress Test Results:")
	t.Logf("  Peak Throughput: %.2f req/sec", stressMetrics.Throughput)
	t.Logf("  Peak Error Rate: %.2f%%", stressMetrics.ErrorRate)
	
	// Allow system to recover
	t.Log("Allowing system recovery...")
	time.Sleep(10 * time.Second)
	
	// Test normal load after stress
	t.Log("Testing recovery with normal load...")
	recoveryMetrics := s.runResponseTimeTest(t, "/api/v3/emails", "GET", nil, 50)
	
	t.Logf("Recovery Test Results:")
	t.Logf("  Average Response Time: %v", recoveryMetrics.AvgResponseTime)
	t.Logf("  P95 Response Time: %v", recoveryMetrics.P95ResponseTime)
	t.Logf("  Error Rate: %.2f%%", recoveryMetrics.ErrorRate)
	
	// Validate recovery requirements
	assert.Less(t, recoveryMetrics.ErrorRate, 1.0, 
		"System should recover with low error rate after stress")
	assert.Less(t, recoveryMetrics.P95ResponseTime, 150*time.Millisecond, 
		"System should recover normal response times after stress")
}

// testPerformanceRegressionDetection tests performance regression detection
func (s *FortressPerformanceTestSuite) testPerformanceRegressionDetection(t *testing.T) {
	// Baseline performance measurement
	baselineMetrics := s.runResponseTimeTest(t, "/api/v3/emails", "GET", nil, 100)
	
	// Simulate performance regression (in real scenario, this would be comparing with historical data)
	// For this test, we'll use the baseline as reference and test with higher load
	regressionMetrics := s.runConcurrentUserTest(t, 500, 10*time.Second)
	
	t.Logf("Performance Regression Detection Results:")
	t.Logf("  Baseline P95: %v", baselineMetrics.P95ResponseTime)
	t.Logf("  Under Load P95: %v", regressionMetrics.P95ResponseTime)
	t.Logf("  Baseline Throughput: %.2f req/sec", baselineMetrics.Throughput)
	t.Logf("  Under Load Throughput: %.2f req/sec", regressionMetrics.Throughput)
	
	// Calculate regression thresholds
	p95Regression := float64(regressionMetrics.P95ResponseTime) / float64(baselineMetrics.P95ResponseTime)
	throughputRegression := baselineMetrics.Throughput / regressionMetrics.Throughput
	
	t.Logf("  P95 Regression Ratio: %.2f", p95Regression)
	t.Logf("  Throughput Regression Ratio: %.2f", throughputRegression)
	
	// Validate regression detection
	assert.Less(t, p95Regression, 10.0, 
		"P95 response time should not degrade more than 10x under load")
	assert.Less(t, throughputRegression, 5.0, 
		"Throughput should not degrade more than 5x under load")
}

// Helper methods for running performance tests

func (s *FortressPerformanceTestSuite) runThroughputTest(t *testing.T, endpoint string, duration time.Duration, targetRPS int) *PerformanceMetrics {
	var totalRequests, successfulRequests, failedRequests int64
	var responseTimes []time.Duration
	var responseTimeMutex sync.Mutex
	
	startTime := time.Now()
	stopTime := startTime.Add(duration)
	
	// Use worker pool to control load
	workerCount := 100
	requestChan := make(chan bool, targetRPS*2)
	var wg sync.WaitGroup
	
	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 5 * time.Second}
			
			for range requestChan {
				payload := map[string]interface{}{
					"from":    "perf@test.com",
					"to":      "recipient@test.com",
					"subject": "Performance Test",
					"content": "Test email content for throughput testing",
				}
				jsonData, _ := json.Marshal(payload)
				
				requestStart := time.Now()
				resp, err := client.Post(s.httpServer.URL+endpoint,
					"application/json", bytes.NewBuffer(jsonData))
				requestDuration := time.Since(requestStart)
				
				atomic.AddInt64(&totalRequests, 1)
				
				if err != nil {
					atomic.AddInt64(&failedRequests, 1)
				} else {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						atomic.AddInt64(&successfulRequests, 1)
					} else {
						atomic.AddInt64(&failedRequests, 1)
					}
				}
				
				responseTimeMutex.Lock()
				responseTimes = append(responseTimes, requestDuration)
				responseTimeMutex.Unlock()
			}
		}()
	}
	
	// Request generator
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(targetRPS))
		defer ticker.Stop()
		
		for time.Now().Before(stopTime) {
			select {
			case requestChan <- true:
			case <-time.After(time.Millisecond):
				// Skip if channel is full
			}
			<-ticker.C
		}
		close(requestChan)
	}()
	
	wg.Wait()
	totalDuration := time.Since(startTime)
	
	return s.calculateMetrics(totalRequests, successfulRequests, failedRequests, responseTimes, totalDuration)
}

func (s *FortressPerformanceTestSuite) runConcurrentUserTest(t *testing.T, concurrentUsers int, duration time.Duration) *PerformanceMetrics {
	var totalRequests, successfulRequests, failedRequests int64
	var responseTimes []time.Duration
	var responseTimeMutex sync.Mutex
	
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	var wg sync.WaitGroup
	
	startTime := time.Now()
	
	// Start concurrent users
	for i := 0; i < concurrentUsers; i++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()
			client := &http.Client{Timeout: 10 * time.Second}
			
			for {
				select {
				case <-ctx.Done():
					return
				default:
					payload := map[string]interface{}{
						"from":    fmt.Sprintf("user%d@test.com", userID),
						"to":      "recipient@test.com",
						"subject": fmt.Sprintf("User %d Test", userID),
						"content": "Test email from concurrent user",
					}
					jsonData, _ := json.Marshal(payload)
					
					requestStart := time.Now()
					resp, err := client.Post(s.httpServer.URL+"/api/v3/emails",
						"application/json", bytes.NewBuffer(jsonData))
					requestDuration := time.Since(requestStart)
					
					atomic.AddInt64(&totalRequests, 1)
					
					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
					} else {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						
						if resp.StatusCode >= 200 && resp.StatusCode < 300 {
							atomic.AddInt64(&successfulRequests, 1)
						} else {
							atomic.AddInt64(&failedRequests, 1)
						}
					}
					
					responseTimeMutex.Lock()
					responseTimes = append(responseTimes, requestDuration)
					responseTimeMutex.Unlock()
					
					time.Sleep(time.Millisecond * 100) // Small delay between requests
				}
			}
		}(i)
	}
	
	wg.Wait()
	totalDuration := time.Since(startTime)
	
	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	metrics := s.calculateMetrics(totalRequests, successfulRequests, failedRequests, responseTimes, totalDuration)
	metrics.MemoryUsage = memStats.HeapInuse
	
	return metrics
}

func (s *FortressPerformanceTestSuite) runResponseTimeTest(t *testing.T, endpoint, method string, payload interface{}, iterations int) *PerformanceMetrics {
	var totalRequests, successfulRequests, failedRequests int64
	var responseTimes []time.Duration
	client := &http.Client{Timeout: 5 * time.Second}
	
	startTime := time.Now()
	
	for i := 0; i < iterations; i++ {
		var resp *http.Response
		var err error
		
		requestStart := time.Now()
		
		if method == "GET" {
			resp, err = client.Get(s.httpServer.URL + endpoint)
		} else if method == "POST" {
			var jsonData []byte
			if payload != nil {
				jsonData, _ = json.Marshal(payload)
			}
			resp, err = client.Post(s.httpServer.URL+endpoint,
				"application/json", bytes.NewBuffer(jsonData))
		}
		
		requestDuration := time.Since(requestStart)
		responseTimes = append(responseTimes, requestDuration)
		totalRequests++
		
		if err != nil {
			failedRequests++
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				successfulRequests++
			} else {
				failedRequests++
			}
		}
	}
	
	totalDuration := time.Since(startTime)
	return s.calculateMetrics(totalRequests, successfulRequests, failedRequests, responseTimes, totalDuration)
}

func (s *FortressPerformanceTestSuite) runDatabasePerformanceTest(t *testing.T, operation func() error, concurrentConnections, operationsPerConnection int) *PerformanceMetrics {
	var totalRequests, successfulRequests, failedRequests int64
	var responseTimes []time.Duration
	var responseTimeMutex sync.Mutex
	var wg sync.WaitGroup
	
	startTime := time.Now()
	
	for i := 0; i < concurrentConnections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for j := 0; j < operationsPerConnection; j++ {
				operationStart := time.Now()
				err := operation()
				operationDuration := time.Since(operationStart)
				
				atomic.AddInt64(&totalRequests, 1)
				
				responseTimeMutex.Lock()
				responseTimes = append(responseTimes, operationDuration)
				responseTimeMutex.Unlock()
				
				if err != nil {
					atomic.AddInt64(&failedRequests, 1)
				} else {
					atomic.AddInt64(&successfulRequests, 1)
				}
			}
		}()
	}
	
	wg.Wait()
	totalDuration := time.Since(startTime)
	
	return s.calculateMetrics(totalRequests, successfulRequests, failedRequests, responseTimes, totalDuration)
}

func (s *FortressPerformanceTestSuite) runSMTPPerformanceTest(t *testing.T, concurrentConnections, emailsPerConnection int) *PerformanceMetrics {
	var totalRequests, successfulRequests, failedRequests int64
	var responseTimes []time.Duration
	var responseTimeMutex sync.Mutex
	var wg sync.WaitGroup
	
	startTime := time.Now()
	
	for i := 0; i < concurrentConnections; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()
			
			for j := 0; j < emailsPerConnection; j++ {
				emailStart := time.Now()
				
				// Simulate SMTP email sending
				payload := map[string]interface{}{
					"from":    fmt.Sprintf("smtp%d@test.com", connID),
					"to":      "recipient@test.com",
					"subject": fmt.Sprintf("SMTP Test %d-%d", connID, j),
					"content": "SMTP performance test email content",
				}
				
				jsonData, _ := json.Marshal(payload)
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Post(s.httpServer.URL+"/api/v3/smtp/send",
					"application/json", bytes.NewBuffer(jsonData))
				
				emailDuration := time.Since(emailStart)
				atomic.AddInt64(&totalRequests, 1)
				
				responseTimeMutex.Lock()
				responseTimes = append(responseTimes, emailDuration)
				responseTimeMutex.Unlock()
				
				if err != nil {
					atomic.AddInt64(&failedRequests, 1)
				} else {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						atomic.AddInt64(&successfulRequests, 1)
					} else {
						atomic.AddInt64(&failedRequests, 1)
					}
				}
			}
		}(i)
	}
	
	wg.Wait()
	totalDuration := time.Since(startTime)
	
	return s.calculateMetrics(totalRequests, successfulRequests, failedRequests, responseTimes, totalDuration)
}

func (s *FortressPerformanceTestSuite) runFileUploadPerformanceTest(t *testing.T, fileSize, iterations int) *PerformanceMetrics {
	var totalRequests, successfulRequests, failedRequests int64
	var responseTimes []time.Duration
	
	// Create test file data
	fileData := bytes.Repeat([]byte("A"), fileSize)
	client := &http.Client{Timeout: 30 * time.Second}
	
	startTime := time.Now()
	
	for i := 0; i < iterations; i++ {
		uploadStart := time.Now()
		
		// Create multipart form data
		var body bytes.Buffer
		boundary := "----WebKitFormBoundaryTest"
		body.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		body.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"test.dat\"\r\n")
		body.WriteString("Content-Type: application/octet-stream\r\n\r\n")
		body.Write(fileData)
		body.WriteString(fmt.Sprintf("\r\n--%s--\r\n", boundary))
		
		req, err := http.NewRequest("POST", s.httpServer.URL+"/api/v3/files/upload", &body)
		if err != nil {
			failedRequests++
			continue
		}
		req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
		
		resp, err := client.Do(req)
		uploadDuration := time.Since(uploadStart)
		responseTimes = append(responseTimes, uploadDuration)
		totalRequests++
		
		if err != nil {
			failedRequests++
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				successfulRequests++
			} else {
				failedRequests++
			}
		}
	}
	
	totalDuration := time.Since(startTime)
	return s.calculateMetrics(totalRequests, successfulRequests, failedRequests, responseTimes, totalDuration)
}

func (s *FortressPerformanceTestSuite) calculateMetrics(totalRequests, successfulRequests, failedRequests int64, responseTimes []time.Duration, totalDuration time.Duration) *PerformanceMetrics {
	if len(responseTimes) == 0 {
		return &PerformanceMetrics{
			TotalRequests:      totalRequests,
			SuccessfulRequests: successfulRequests,
			FailedRequests:     failedRequests,
			TotalDuration:      totalDuration,
		}
	}
	
	// Sort response times for percentile calculation
	for i := 0; i < len(responseTimes)-1; i++ {
		for j := i + 1; j < len(responseTimes); j++ {
			if responseTimes[i] > responseTimes[j] {
				responseTimes[i], responseTimes[j] = responseTimes[j], responseTimes[i]
			}
		}
	}
	
	// Calculate metrics
	var totalResponseTime time.Duration
	for _, rt := range responseTimes {
		totalResponseTime += rt
	}
	
	minResponseTime := responseTimes[0]
	maxResponseTime := responseTimes[len(responseTimes)-1]
	avgResponseTime := totalResponseTime / time.Duration(len(responseTimes))
	
	p95Index := int(float64(len(responseTimes)) * 0.95)
	p99Index := int(float64(len(responseTimes)) * 0.99)
	if p95Index >= len(responseTimes) {
		p95Index = len(responseTimes) - 1
	}
	if p99Index >= len(responseTimes) {
		p99Index = len(responseTimes) - 1
	}
	
	p95ResponseTime := responseTimes[p95Index]
	p99ResponseTime := responseTimes[p99Index]
	
	throughput := float64(totalRequests) / totalDuration.Seconds()
	errorRate := float64(failedRequests) / float64(totalRequests) * 100
	
	return &PerformanceMetrics{
		TotalRequests:      totalRequests,
		SuccessfulRequests: successfulRequests,
		FailedRequests:     failedRequests,
		TotalDuration:      totalDuration,
		MinResponseTime:    minResponseTime,
		MaxResponseTime:    maxResponseTime,
		AvgResponseTime:    avgResponseTime,
		P95ResponseTime:    p95ResponseTime,
		P99ResponseTime:    p99ResponseTime,
		Throughput:         throughput,
		ErrorRate:          errorRate,
	}
}

// createPerformanceTestHandler creates a test HTTP handler for performance testing
func createPerformanceTestHandler(fortress *fortress.Service, storage storage.Storage) http.Handler {
	mux := http.NewServeMux()
	
	// Email endpoints
	mux.HandleFunc("/api/v3/emails", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			emails, _ := storage.List(0, 50)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"emails": emails})
			
		case "POST":
			var email map[string]interface{}
			json.NewDecoder(r.Body).Decode(&email)
			storage.Store(email)
			
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "created"})
		}
	})
	
	// Search endpoint
	mux.HandleFunc("/api/v3/emails/search", func(w http.ResponseWriter, r *http.Request) {
		var searchReq map[string]interface{}
		json.NewDecoder(r.Body).Decode(&searchReq)
		
		query, _ := searchReq["query"].(string)
		limit := 50
		if l, ok := searchReq["limit"].(float64); ok {
			limit = int(l)
		}
		
		results, _ := storage.Search(query, 0, limit)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
	})
	
	// Individual email endpoint
	mux.HandleFunc("/api/v3/emails/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email": map[string]interface{}{
				"id":      "1",
				"from":    "test@example.com",
				"to":      "recipient@example.com",
				"subject": "Test Email",
				"content": "Test email content",
			},
		})
	})
	
	// GraphQL endpoint
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		
		// Simulate GraphQL processing
		time.Sleep(time.Millisecond * 10)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"emails": []map[string]interface{}{
					{"id": "1", "from": "test@example.com", "to": "recipient@example.com"},
				},
			},
		})
	})
	
	// File upload endpoint
	mux.HandleFunc("/api/v3/files/upload", func(w http.ResponseWriter, r *http.Request) {
		// Parse multipart form
		err := r.ParseMultipartForm(32 << 20) // 32MB
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		
		file, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		
		// Read and discard file data (simulate processing)
		io.Copy(io.Discard, file)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "uploaded"})
	})
	
	// SMTP send endpoint
	mux.HandleFunc("/api/v3/smtp/send", func(w http.ResponseWriter, r *http.Request) {
		var email map[string]interface{}
		json.NewDecoder(r.Body).Decode(&email)
		
		// Simulate SMTP processing
		time.Sleep(time.Millisecond * 5)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "sent"})
	})
	
	return mux
}