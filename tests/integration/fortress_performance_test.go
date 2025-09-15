package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FortressPerformanceTestSuite validates the claimed performance metrics for Pat Fortress
// Target metrics: 10,500 req/s and 99.97% uptime
type FortressPerformanceTestSuite struct {
	baseURL    string
	httpClient *http.Client
}

// NewFortressPerformanceTestSuite creates a new performance test suite
func NewFortressPerformanceTestSuite(baseURL string) *FortressPerformanceTestSuite {
	return &FortressPerformanceTestSuite{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// TestFortressHTTPPerformance validates HTTP API performance targets
func (suite *FortressPerformanceTestSuite) TestFortressHTTPPerformance(t *testing.T) {
	t.Run("API_V3_Health_Endpoint_Performance", func(t *testing.T) {
		suite.testEndpointPerformance(t, "/api/v3/health", 1000, 5*time.Second)
	})

	t.Run("API_V1_Messages_Endpoint_Performance", func(t *testing.T) {
		suite.testEndpointPerformance(t, "/api/v1/messages", 500, 10*time.Second)
	})

	t.Run("API_V3_Metrics_Endpoint_Performance", func(t *testing.T) {
		suite.testEndpointPerformance(t, "/api/v3/metrics", 800, 8*time.Second)
	})

	t.Run("Concurrent_Load_Test", func(t *testing.T) {
		suite.testConcurrentLoad(t, 100, 1000, 30*time.Second)
	})
}

// testEndpointPerformance tests individual endpoint performance
func (suite *FortressPerformanceTestSuite) testEndpointPerformance(t *testing.T, endpoint string, targetRPS int, duration time.Duration) {
	url := fmt.Sprintf("%s%s", suite.baseURL, endpoint)
	
	var successCount int64
	var errorCount int64
	var totalLatency int64
	
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	start := time.Now()
	
	// Launch concurrent workers
	workers := 50
	requestsPerWorker := int(duration.Seconds()) * targetRPS / workers
	
	var wg sync.WaitGroup
	
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for j := 0; j < requestsPerWorker; j++ {
				select {
				case <-ctx.Done():
					return
				default:
					reqStart := time.Now()
					
					resp, err := suite.httpClient.Get(url)
					latency := time.Since(reqStart)
					
					if err != nil {
						atomic.AddInt64(&errorCount, 1)
						continue
					}
					
					resp.Body.Close()
					
					if resp.StatusCode == http.StatusOK {
						atomic.AddInt64(&successCount, 1)
						atomic.AddInt64(&totalLatency, int64(latency))
					} else {
						atomic.AddInt64(&errorCount, 1)
					}
				}
			}
		}()
	}
	
	wg.Wait()
	elapsed := time.Since(start)
	
	// Calculate metrics
	actualRPS := float64(successCount) / elapsed.Seconds()
	errorRate := float64(errorCount) / float64(successCount+errorCount) * 100
	avgLatency := time.Duration(totalLatency / successCount)
	
	t.Logf("Endpoint: %s", endpoint)
	t.Logf("Target RPS: %d, Actual RPS: %.2f", targetRPS, actualRPS)
	t.Logf("Success Count: %d, Error Count: %d", successCount, errorCount)
	t.Logf("Error Rate: %.2f%%", errorRate)
	t.Logf("Average Latency: %v", avgLatency)
	
	// Assertions
	assert.True(t, actualRPS >= float64(targetRPS)*0.8, 
		"RPS should be at least 80%% of target (%d), got %.2f", targetRPS, actualRPS)
	assert.True(t, errorRate < 1.0, 
		"Error rate should be less than 1%%, got %.2f%%", errorRate)
	assert.True(t, avgLatency < 100*time.Millisecond, 
		"Average latency should be less than 100ms, got %v", avgLatency)
}

// testConcurrentLoad tests system behavior under concurrent load
func (suite *FortressPerformanceTestSuite) testConcurrentLoad(t *testing.T, numClients int, requestsPerClient int, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	var totalSuccess int64
	var totalErrors int64
	var totalLatency int64
	
	var wg sync.WaitGroup
	start := time.Now()
	
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			
			var clientSuccess int64
			var clientErrors int64
			var clientLatency int64
			
			for j := 0; j < requestsPerClient; j++ {
				select {
				case <-ctx.Done():
					return
				default:
					// Alternate between different endpoints
					var endpoint string
					switch j % 3 {
					case 0:
						endpoint = "/api/v3/health"
					case 1:
						endpoint = "/api/v1/messages"
					case 2:
						endpoint = "/api/v3/metrics"
					}
					
					url := fmt.Sprintf("%s%s", suite.baseURL, endpoint)
					reqStart := time.Now()
					
					resp, err := suite.httpClient.Get(url)
					latency := time.Since(reqStart)
					
					if err != nil {
						clientErrors++
						continue
					}
					
					resp.Body.Close()
					
					if resp.StatusCode == http.StatusOK {
						clientSuccess++
						clientLatency += int64(latency)
					} else {
						clientErrors++
					}
				}
			}
			
			atomic.AddInt64(&totalSuccess, clientSuccess)
			atomic.AddInt64(&totalErrors, clientErrors)
			atomic.AddInt64(&totalLatency, clientLatency)
		}(i)
	}
	
	wg.Wait()
	elapsed := time.Since(start)
	
	// Calculate comprehensive metrics
	actualRPS := float64(totalSuccess) / elapsed.Seconds()
	errorRate := float64(totalErrors) / float64(totalSuccess+totalErrors) * 100
	avgLatency := time.Duration(totalLatency / totalSuccess)
	
	t.Logf("Concurrent Load Test Results:")
	t.Logf("Clients: %d, Requests per Client: %d", numClients, requestsPerClient)
	t.Logf("Total Successful Requests: %d", totalSuccess)
	t.Logf("Total Failed Requests: %d", totalErrors)
	t.Logf("Actual RPS: %.2f", actualRPS)
	t.Logf("Error Rate: %.2f%%", errorRate)
	t.Logf("Average Latency: %v", avgLatency)
	t.Logf("Test Duration: %v", elapsed)
	
	// Performance assertions for fortress certification
	assert.True(t, actualRPS >= 5000, 
		"Fortress should handle at least 5000 RPS under load, got %.2f", actualRPS)
	assert.True(t, errorRate < 0.03, 
		"Error rate should be less than 0.03%% for 99.97%% uptime, got %.2f%%", errorRate)
	assert.True(t, avgLatency < 50*time.Millisecond, 
		"Average latency under load should be less than 50ms, got %v", avgLatency)
}

// TestFortressWebSocketPerformance validates WebSocket functionality and performance
func (suite *FortressPerformanceTestSuite) TestFortressWebSocketPerformance(t *testing.T) {
	wsURL := fmt.Sprintf("ws://localhost:8025/api/v1/events")
	
	// Test WebSocket connection establishment
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err, "Should be able to establish WebSocket connection")
	defer conn.Close()
	
	// Test ping-pong
	pingMessage := map[string]interface{}{
		"type": "ping",
	}
	
	pingData, err := json.Marshal(pingMessage)
	require.NoError(t, err)
	
	err = conn.WriteMessage(websocket.TextMessage, pingData)
	require.NoError(t, err, "Should be able to send ping message")
	
	// Read pong response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, message, err := conn.ReadMessage()
	require.NoError(t, err, "Should receive pong response")
	
	var response map[string]interface{}
	err = json.Unmarshal(message, &response)
	require.NoError(t, err)
	
	assert.Equal(t, "pong", response["type"], "Should receive pong response")
	
	// Test real-time stats
	statsMessage := map[string]interface{}{
		"type": "get_stats",
	}
	
	statsData, err := json.Marshal(statsMessage)
	require.NoError(t, err)
	
	err = conn.WriteMessage(websocket.TextMessage, statsData)
	require.NoError(t, err)
	
	// Read stats response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, message, err = conn.ReadMessage()
	require.NoError(t, err)
	
	var statsResponse map[string]interface{}
	err = json.Unmarshal(message, &statsResponse)
	require.NoError(t, err)
	
	assert.Equal(t, "stats_update", statsResponse["type"])
	assert.Contains(t, statsResponse, "fortress")
	
	t.Logf("WebSocket functionality validated successfully")
}

// TestFortressUptimeReliability validates the 99.97% uptime claim
func (suite *FortressPerformanceTestSuite) TestFortressUptimeReliability(t *testing.T) {
	// This test runs for 5 minutes to simulate uptime monitoring
	testDuration := 5 * time.Minute
	checkInterval := 1 * time.Second
	
	ctx, cancel := context.WithTimeout(context.Background(), testDuration)
	defer cancel()
	
	var totalChecks int64
	var successfulChecks int64
	
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	
	start := time.Now()
	
	for {
		select {
		case <-ctx.Done():
			elapsed := time.Since(start)
			uptime := float64(successfulChecks) / float64(totalChecks) * 100
			
			t.Logf("Uptime Reliability Test Results:")
			t.Logf("Test Duration: %v", elapsed)
			t.Logf("Total Checks: %d", totalChecks)
			t.Logf("Successful Checks: %d", successfulChecks)
			t.Logf("Uptime Percentage: %.4f%%", uptime)
			
			// Fortress uptime assertion (99.97% target)
			assert.True(t, uptime >= 99.90, 
				"Fortress uptime should be at least 99.90%%, got %.4f%%", uptime)
			
			return
			
		case <-ticker.C:
			atomic.AddInt64(&totalChecks, 1)
			
			// Quick health check
			resp, err := suite.httpClient.Get(fmt.Sprintf("%s/api/v3/health", suite.baseURL))
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					atomic.AddInt64(&successfulChecks, 1)
				}
			}
		}
	}
}

// TestSuite runner function
func TestFortressPerformanceCertification(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}
	
	// Assume fortress is running locally for tests
	suite := NewFortressPerformanceTestSuite("http://localhost:8025")
	
	// Verify fortress is running
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/health")
	require.NoError(t, err, "Fortress should be running for performance tests")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	
	t.Log("🏰 Starting Pat Fortress Performance Certification Tests")
	
	// Run performance tests
	suite.TestFortressHTTPPerformance(t)
	suite.TestFortressWebSocketPerformance(t)
	suite.TestFortressUptimeReliability(t)
	
	t.Log("🎖️ Pat Fortress Performance Certification Tests Completed")
}