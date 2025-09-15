package protocol_compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/pat-fortress/tests/integration/testdata/fixtures"
	"github.com/pat-fortress/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// FortressHTTPAPIComplianceSuite tests HTTP API compliance and REST standards
type FortressHTTPAPIComplianceSuite struct {
	suite.Suite
	testUtils      *utils.FortressTestUtils
	configFixtures *fixtures.ConfigFixtures
	emailFixtures  *fixtures.EmailFixtures
	
	// HTTP server and client setup
	httpServer interfaces.Gates
	httpConfig *interfaces.HTTPServerConfig
	baseURL    string
	client     *http.Client
	
	// Test context
	ctx    context.Context
	cancel context.CancelFunc
}

// SetupSuite initializes the HTTP API compliance test environment
func (s *FortressHTTPAPIComplianceSuite) SetupSuite() {
	s.testUtils = utils.NewFortressTestUtils(s.T())
	s.configFixtures = fixtures.NewConfigFixtures()
	s.emailFixtures = fixtures.NewEmailFixtures()
	
	s.ctx, s.cancel = context.WithTimeout(context.Background(), time.Minute*15)
	
	// Get HTTP server configuration
	s.httpConfig = s.configFixtures.TestHTTPServerConfig()
	s.baseURL = fmt.Sprintf("http://%s:%d", s.httpConfig.Host, s.httpConfig.Port)
	
	// Create HTTP client
	s.client = &http.Client{
		Timeout: time.Second * 30,
	}
	
	// Initialize and start HTTP server
	s.httpServer = s.createHTTPServer()
	err := s.httpServer.StartHTTPServer(s.ctx, s.httpConfig)
	require.NoError(s.T(), err)
	
	// Wait for server to be ready
	s.waitForServerReady()
}

// TearDownSuite cleans up the HTTP API compliance test environment
func (s *FortressHTTPAPIComplianceSuite) TearDownSuite() {
	if s.httpServer != nil {
		s.httpServer.StopHTTPServer(s.ctx)
	}
	
	if s.cancel != nil {
		s.cancel()
	}
}

// TestHTTPBasicConnectivity tests basic HTTP connectivity and health endpoints
func (s *FortressHTTPAPIComplianceSuite) TestHTTPBasicConnectivity() {
	s.T().Run("HTTP_Health_Endpoint", func(t *testing.T) {
		resp, err := s.client.Get(s.baseURL + s.httpConfig.HealthEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Verify response status
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		// Verify content type
		contentType := resp.Header.Get("Content-Type")
		assert.Contains(t, contentType, "application/json")
		
		// Parse response body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		
		var health map[string]interface{}
		err = json.Unmarshal(body, &health)
		require.NoError(t, err)
		
		// Verify health response structure
		assert.Contains(t, health, "status")
		assert.Contains(t, health, "timestamp")
		assert.Equal(t, "healthy", health["status"])
		
		t.Logf("Health response: %+v", health)
	})
	
	s.T().Run("HTTP_Metrics_Endpoint", func(t *testing.T) {
		if !s.httpConfig.EnableMetrics {
			t.Skip("Metrics endpoint not enabled")
		}
		
		resp, err := s.client.Get(s.baseURL + s.httpConfig.MetricsEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Verify response status
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		// Verify prometheus metrics format
		contentType := resp.Header.Get("Content-Type")
		assert.Contains(t, contentType, "text/plain")
		
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		
		metricsText := string(body)
		assert.Contains(t, metricsText, "# HELP")
		assert.Contains(t, metricsText, "# TYPE")
		
		t.Logf("Metrics endpoint accessible, content length: %d", len(metricsText))
	})
}

// TestRESTAPICompliance tests REST API compliance
func (s *FortressHTTPAPIComplianceSuite) TestRESTAPICompliance() {
	s.T().Run("REST_API_Endpoints", func(t *testing.T) {
		apiBase := s.baseURL + s.httpConfig.APIPrefix
		
		// Test emails endpoint structure
		emailsEndpoint := apiBase + "/emails"
		
		// GET /api/v3/emails (list emails)
		resp, err := s.client.Get(emailsEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Should return 200 for list operation
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		// Should return JSON
		contentType := resp.Header.Get("Content-Type")
		assert.Contains(t, contentType, "application/json")
		
		// Parse response
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		
		var emailsList map[string]interface{}
		err = json.Unmarshal(body, &emailsList)
		require.NoError(t, err)
		
		// Verify response structure
		assert.Contains(t, emailsList, "data")
		assert.Contains(t, emailsList, "meta")
		
		// Test pagination parameters
		paginatedURL := emailsEndpoint + "?page=1&limit=10"
		resp, err = s.client.Get(paginatedURL)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		t.Log("REST API endpoints comply with expected structure")
	})
	
	s.T().Run("HTTP_Method_Compliance", func(t *testing.T) {
		apiBase := s.baseURL + s.httpConfig.APIPrefix
		emailsEndpoint := apiBase + "/emails"
		
		// Test OPTIONS method (CORS preflight)
		req, err := http.NewRequest("OPTIONS", emailsEndpoint, nil)
		require.NoError(t, err)
		
		resp, err := s.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		if s.httpConfig.EnableCORS {
			// Should return allowed methods
			allowedMethods := resp.Header.Get("Access-Control-Allow-Methods")
			assert.NotEmpty(t, allowedMethods)
			assert.Contains(t, allowedMethods, "GET")
			assert.Contains(t, allowedMethods, "POST")
		}
		
		// Test HEAD method
		resp, err = s.client.Head(emailsEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// HEAD should return same headers as GET but no body
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		
		// Test unsupported method
		req, err = http.NewRequest("PATCH", emailsEndpoint, nil)
		require.NoError(t, err)
		
		resp, err = s.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Should return 405 Method Not Allowed
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		
		// Should include Allow header
		allowHeader := resp.Header.Get("Allow")
		assert.NotEmpty(t, allowHeader)
	})
}

// TestHTTPHeaders tests HTTP header compliance
func (s *FortressHTTPAPIComplianceSuite) TestHTTPHeaders() {
	s.T().Run("Security_Headers", func(t *testing.T) {
		resp, err := s.client.Get(s.baseURL + s.httpConfig.APIPrefix + "/emails")
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Check security headers
		headers := resp.Header
		
		// X-Content-Type-Options
		assert.Equal(t, "nosniff", headers.Get("X-Content-Type-Options"))
		
		// X-Frame-Options
		frameOptions := headers.Get("X-Frame-Options")
		assert.True(t, frameOptions == "DENY" || frameOptions == "SAMEORIGIN")
		
		// X-XSS-Protection
		xssProtection := headers.Get("X-XSS-Protection")
		assert.Contains(t, xssProtection, "1")
		
		// Content-Security-Policy (if configured)
		csp := headers.Get("Content-Security-Policy")
		if csp != "" {
			assert.Contains(t, csp, "default-src")
		}
		
		t.Logf("Security headers present: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection")
	})
	
	s.T().Run("CORS_Headers", func(t *testing.T) {
		if !s.httpConfig.EnableCORS {
			t.Skip("CORS not enabled")
		}
		
		// Test CORS preflight request
		req, err := http.NewRequest("OPTIONS", s.baseURL+s.httpConfig.APIPrefix+"/emails", nil)
		require.NoError(t, err)
		
		req.Header.Set("Origin", "https://fortress-client.test")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
		
		resp, err := s.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Verify CORS headers
		headers := resp.Header
		
		allowOrigin := headers.Get("Access-Control-Allow-Origin")
		assert.True(t, allowOrigin == "*" || allowOrigin == "https://fortress-client.test")
		
		allowMethods := headers.Get("Access-Control-Allow-Methods")
		assert.NotEmpty(t, allowMethods)
		
		allowHeaders := headers.Get("Access-Control-Allow-Headers")
		assert.NotEmpty(t, allowHeaders)
		
		t.Logf("CORS headers: Origin=%s, Methods=%s, Headers=%s", 
			allowOrigin, allowMethods, allowHeaders)
	})
	
	s.T().Run("Content_Encoding", func(t *testing.T) {
		if !s.httpConfig.EnableGzip {
			t.Skip("Gzip compression not enabled")
		}
		
		// Request with gzip acceptance
		req, err := http.NewRequest("GET", s.baseURL+s.httpConfig.APIPrefix+"/emails", nil)
		require.NoError(t, err)
		
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		
		resp, err := s.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Check if response is compressed
		encoding := resp.Header.Get("Content-Encoding")
		if encoding == "gzip" {
			t.Log("Response properly compressed with gzip")
		} else {
			t.Log("Response not compressed (may be too small)")
		}
	})
}

// TestAPIRateLimiting tests HTTP API rate limiting
func (s *FortressHTTPAPIComplianceSuite) TestAPIRateLimiting() {
	s.T().Run("Rate_Limit_Headers", func(t *testing.T) {
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails"
		
		// Make initial request
		resp, err := s.client.Get(endpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Check for rate limit headers
		headers := resp.Header
		
		rateLimitHeaders := []string{
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining", 
			"X-RateLimit-Reset",
			"X-RateLimit-Retry-After",
		}
		
		foundHeaders := 0
		for _, headerName := range rateLimitHeaders {
			if headers.Get(headerName) != "" {
				foundHeaders++
				t.Logf("Found rate limit header: %s = %s", 
					headerName, headers.Get(headerName))
			}
		}
		
		if foundHeaders > 0 {
			t.Logf("Rate limiting headers present (%d/4)", foundHeaders)
		} else {
			t.Log("No rate limiting headers found (may not be enabled)")
		}
	})
	
	s.T().Run("Rate_Limit_Enforcement", func(t *testing.T) {
		if s.httpConfig.RateLimitRPS == 0 {
			t.Skip("Rate limiting not configured")
		}
		
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails"
		
		// Make requests rapidly to trigger rate limit
		var rateLimitedResponse *http.Response
		requestCount := int(s.httpConfig.RateLimitRPS) + 10
		
		for i := 0; i < requestCount; i++ {
			resp, err := s.client.Get(endpoint)
			require.NoError(t, err)
			
			if resp.StatusCode == http.StatusTooManyRequests {
				rateLimitedResponse = resp
				break
			}
			
			resp.Body.Close()
			
			// Small delay to prevent overwhelming the server
			time.Sleep(time.Millisecond * 10)
		}
		
		if rateLimitedResponse != nil {
			defer rateLimitedResponse.Body.Close()
			
			// Verify 429 response
			assert.Equal(t, http.StatusTooManyRequests, rateLimitedResponse.StatusCode)
			
			// Verify Retry-After header
			retryAfter := rateLimitedResponse.Header.Get("Retry-After")
			assert.NotEmpty(t, retryAfter)
			
			t.Logf("Rate limiting enforced after multiple requests, Retry-After: %s", retryAfter)
		} else {
			t.Log("Rate limiting not triggered (may need more requests or higher rate)")
		}
	})
}

// TestAPIContentNegotiation tests content type handling
func (s *FortressHTTPAPIComplianceSuite) TestAPIContentNegotiation() {
	s.T().Run("JSON_Content_Type", func(t *testing.T) {
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails"
		
		// Request JSON explicitly
		req, err := http.NewRequest("GET", endpoint, nil)
		require.NoError(t, err)
		
		req.Header.Set("Accept", "application/json")
		
		resp, err := s.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Verify JSON response
		contentType := resp.Header.Get("Content-Type")
		assert.Contains(t, contentType, "application/json")
		
		// Verify valid JSON body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		
		var jsonResponse map[string]interface{}
		err = json.Unmarshal(body, &jsonResponse)
		require.NoError(t, err, "Response should be valid JSON")
	})
	
	s.T().Run("Unsupported_Media_Type", func(t *testing.T) {
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails"
		
		// Request unsupported content type
		req, err := http.NewRequest("GET", endpoint, nil)
		require.NoError(t, err)
		
		req.Header.Set("Accept", "application/xml")
		
		resp, err := s.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Should either return JSON anyway or 406 Not Acceptable
		if resp.StatusCode == http.StatusNotAcceptable {
			t.Log("Server correctly returns 406 for unsupported media type")
		} else {
			// Many APIs default to JSON even if XML is requested
			contentType := resp.Header.Get("Content-Type")
			assert.Contains(t, contentType, "application/json",
				"Server should default to JSON for unsupported media type")
		}
	})
}

// TestHTTPStatusCodes tests proper HTTP status code usage
func (s *FortressHTTPAPIComplianceSuite) TestHTTPStatusCodes() {
	s.T().Run("Resource_Not_Found", func(t *testing.T) {
		// Request non-existent email
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails/non-existent-id"
		
		resp, err := s.client.Get(endpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Should return 404 Not Found
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		
		// Should include error details
		contentType := resp.Header.Get("Content-Type")
		assert.Contains(t, contentType, "application/json")
		
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		
		var errorResponse map[string]interface{}
		err = json.Unmarshal(body, &errorResponse)
		require.NoError(t, err)
		
		// Common error response fields
		expectedFields := []string{"error", "message", "code"}
		for _, field := range expectedFields {
			if _, exists := errorResponse[field]; exists {
				t.Logf("Found error field: %s", field)
				break
			}
		}
	})
	
	s.T().Run("Bad_Request", func(t *testing.T) {
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails"
		
		// Send invalid query parameters
		invalidURL := endpoint + "?limit=invalid&page=-1"
		
		resp, err := s.client.Get(invalidURL)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Should return 400 Bad Request or handle gracefully with 200
		if resp.StatusCode == http.StatusBadRequest {
			t.Log("Server correctly validates query parameters")
			
			// Check error response
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			
			var errorResponse map[string]interface{}
			err = json.Unmarshal(body, &errorResponse)
			require.NoError(t, err)
			
			assert.Contains(t, fmt.Sprintf("%v", errorResponse), "invalid",
				"Error response should mention validation issue")
		} else {
			t.Log("Server handles invalid parameters gracefully")
		}
	})
	
	s.T().Run("Method_Not_Allowed", func(t *testing.T) {
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails"
		
		// Try unsupported method
		req, err := http.NewRequest("DELETE", endpoint, nil)
		require.NoError(t, err)
		
		resp, err := s.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Should return 405 Method Not Allowed
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		
		// Should include Allow header
		allowHeader := resp.Header.Get("Allow")
		assert.NotEmpty(t, allowHeader,
			"405 response should include Allow header with supported methods")
		
		t.Logf("Allowed methods: %s", allowHeader)
	})
}

// TestAPIErrorHandling tests error response consistency
func (s *FortressHTTPAPIComplianceSuite) TestAPIErrorHandling() {
	s.T().Run("Error_Response_Format", func(t *testing.T) {
		// Test various error scenarios
		errorTests := []struct {
			name     string
			endpoint string
			method   string
			expected int
		}{
			{"Not Found", "/emails/invalid-id", "GET", http.StatusNotFound},
			{"Method Not Allowed", "/emails", "DELETE", http.StatusMethodNotAllowed},
			{"Invalid Endpoint", "/invalid-endpoint", "GET", http.StatusNotFound},
		}
		
		for _, test := range errorTests {
			t.Run(test.name, func(t *testing.T) {
				endpoint := s.baseURL + s.httpConfig.APIPrefix + test.endpoint
				
				req, err := http.NewRequest(test.method, endpoint, nil)
				require.NoError(t, err)
				
				resp, err := s.client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
				
				assert.Equal(t, test.expected, resp.StatusCode)
				
				// Verify error response is JSON
				contentType := resp.Header.Get("Content-Type")
				if strings.Contains(contentType, "application/json") {
					body, err := io.ReadAll(resp.Body)
					require.NoError(t, err)
					
					var errorResponse map[string]interface{}
					err = json.Unmarshal(body, &errorResponse)
					require.NoError(t, err, "Error response should be valid JSON")
					
					t.Logf("%s error response: %+v", test.name, errorResponse)
				}
			})
		}
	})
}

// TestAPIValidation tests request validation
func (s *FortressHTTPAPIComplianceSuite) TestAPIValidation() {
	s.T().Run("POST_Request_Validation", func(t *testing.T) {
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails"
		
		// Test with invalid JSON
		invalidJSON := `{"invalid": json}`
		
		req, err := http.NewRequest("POST", endpoint, strings.NewReader(invalidJSON))
		require.NoError(t, err)
		
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := s.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Should return 400 Bad Request for invalid JSON
		if resp.StatusCode == http.StatusBadRequest {
			t.Log("Server correctly validates JSON syntax")
		}
		
		// Test with missing required fields
		validJSONInvalidData := `{"subject": "test"}`
		
		req, err = http.NewRequest("POST", endpoint, strings.NewReader(validJSONInvalidData))
		require.NoError(t, err)
		
		req.Header.Set("Content-Type", "application/json")
		
		resp, err = s.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		// Should return 400 Bad Request or 422 Unprocessable Entity
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == 422 {
			t.Log("Server correctly validates required fields")
			
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			
			var errorResponse map[string]interface{}
			err = json.Unmarshal(body, &errorResponse)
			if err == nil {
				t.Logf("Validation error response: %+v", errorResponse)
			}
		}
	})
}

// TestAPIPerformance tests API performance characteristics
func (s *FortressHTTPAPIComplianceSuite) TestAPIPerformance() {
	s.T().Run("Response_Time", func(t *testing.T) {
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails"
		
		// Measure response time
		start := time.Now()
		
		resp, err := s.client.Get(endpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		
		responseTime := time.Since(start)
		
		// API should respond within reasonable time
		assert.Less(t, responseTime, time.Second*2,
			"API response should be under 2 seconds")
		
		t.Logf("API response time: %v", responseTime)
	})
	
	s.T().Run("Concurrent_Requests", func(t *testing.T) {
		endpoint := s.baseURL + s.httpConfig.APIPrefix + "/emails"
		concurrency := 10
		
		// Test concurrent API requests
		s.testUtils.FortressTestConcurrentExecution(concurrency, func(workerID int) {
			resp, err := s.client.Get(endpoint)
			assert.NoError(s.T(), err, "Worker %d should get successful response", workerID)
			
			if err == nil {
				assert.Equal(s.T(), http.StatusOK, resp.StatusCode,
					"Worker %d should get 200 OK", workerID)
				resp.Body.Close()
			}
		})
		
		t.Logf("Concurrent API requests test completed with %d workers", concurrency)
	})
}

// Helper methods

func (s *FortressHTTPAPIComplianceSuite) createHTTPServer() interfaces.Gates {
	return &HTTPGatesService{
		config: s.httpConfig,
	}
}

func (s *FortressHTTPAPIComplianceSuite) waitForServerReady() {
	s.testUtils.WaitForCondition(func() bool {
		resp, err := s.client.Get(s.baseURL + s.httpConfig.HealthEndpoint)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, time.Second*30, "HTTP server should be ready")
}

// HTTPGatesService is a test implementation of Gates interface for HTTP
type HTTPGatesService struct {
	config *interfaces.HTTPServerConfig
}

func (h *HTTPGatesService) StartHTTPServer(ctx context.Context, config *interfaces.HTTPServerConfig) error {
	// In a real implementation, this would start the actual HTTP server
	// For testing, we simulate a running server
	return nil
}

func (h *HTTPGatesService) StopHTTPServer(ctx context.Context) error {
	return nil
}

// Implement other Gates interface methods with stubs
func (h *HTTPGatesService) RegisterRoute(method, path string, handler interfaces.HandlerFunc) {}
func (h *HTTPGatesService) RegisterMiddleware(middleware interfaces.MiddlewareFunc) {}
func (h *HTTPGatesService) StartSMTPServer(ctx context.Context, config *interfaces.SMTPServerConfig) error { return nil }
func (h *HTTPGatesService) StopSMTPServer(ctx context.Context) error { return nil }
func (h *HTTPGatesService) HandleSMTPConnection(ctx context.Context, conn net.Conn) error { return nil }
func (h *HTTPGatesService) RegisterGraphQLSchema(schema string) error { return nil }
func (h *HTTPGatesService) HandleGraphQL(ctx context.Context, query string, variables map[string]interface{}) (*interfaces.GraphQLResult, error) { return &interfaces.GraphQLResult{}, nil }
func (h *HTTPGatesService) RegisterWebSocketHandler(path string, handler interfaces.WebSocketHandler) {}
func (h *HTTPGatesService) BroadcastMessage(ctx context.Context, message *interfaces.WebSocketMessage) error { return nil }
func (h *HTTPGatesService) RegisterAPIVersion(version string, routes map[string]interfaces.HandlerFunc) {}
func (h *HTTPGatesService) GenerateOpenAPISpec() ([]byte, error) {
	return []byte(`{"openapi": "3.0.0", "info": {"title": "Fortress API", "version": "3.0"}}`), nil
}
func (h *HTTPGatesService) Start(ctx context.Context) error { return nil }
func (h *HTTPGatesService) Stop(ctx context.Context) error { return nil }
func (h *HTTPGatesService) Health(ctx context.Context) *interfaces.HealthStatus {
	return &interfaces.HealthStatus{Service: "gates", Status: interfaces.HealthStatusHealthy}
}

// TestFortressHTTPAPICompliance runs the HTTP API compliance test suite
func TestFortressHTTPAPICompliance(t *testing.T) {
	// This test requires an actual HTTP server implementation
	// Skip if running in CI without HTTP server
	if testing.Short() {
		t.Skip("Skipping HTTP API compliance tests in short mode")
	}
	
	suite.Run(t, new(FortressHTTPAPIComplianceSuite))
}