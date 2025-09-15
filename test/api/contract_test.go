package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// APIContractTestSuite provides comprehensive API contract testing
type APIContractTestSuite struct {
	suite.Suite
	server     *httptest.Server
	baseURL    string
	httpClient *http.Client
}

// API Response structures for contract validation
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
	Meta    *APIMeta    `json:"meta,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

type APIMeta struct {
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	Total     int       `json:"total,omitempty"`
	Page      int       `json:"page,omitempty"`
	Limit     int       `json:"limit,omitempty"`
}

type EmailMessage struct {
	ID          string            `json:"id"`
	From        *EmailAddress     `json:"from"`
	To          []*EmailAddress   `json:"to"`
	Subject     string            `json:"subject"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers"`
	CreatedAt   time.Time         `json:"created_at"`
	TenantID    string            `json:"tenant_id,omitempty"`
	Status      string            `json:"status"`
	Attachments []EmailAttachment `json:"attachments,omitempty"`
}

type EmailAddress struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

type EmailAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Content     string `json:"content,omitempty"`
}

type PluginInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	TenantID    string            `json:"tenant_id"`
	Status      string            `json:"status"`
	Config      map[string]string `json:"config,omitempty"`
	Hooks       []string          `json:"hooks"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// SetupSuite initializes the test environment
func (suite *APIContractTestSuite) SetupSuite() {
	// Create a test server with our API routes
	mux := http.NewServeMux()
	
	// Email API endpoints
	mux.HandleFunc("/api/v3/emails", suite.handleEmails)
	mux.HandleFunc("/api/v3/emails/", suite.handleEmailByID)
	mux.HandleFunc("/api/v3/emails/search", suite.handleEmailSearch)
	
	// Plugin API endpoints
	mux.HandleFunc("/api/v3/plugins", suite.handlePlugins)
	mux.HandleFunc("/api/v3/plugins/", suite.handlePluginByID)
	
	// Health and status endpoints
	mux.HandleFunc("/api/v3/health", suite.handleHealth)
	mux.HandleFunc("/api/v3/status", suite.handleStatus)
	
	suite.server = httptest.NewServer(mux)
	suite.baseURL = suite.server.URL
	suite.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
}

// TearDownSuite cleans up after all tests
func (suite *APIContractTestSuite) TearDownSuite() {
	if suite.server != nil {
		suite.server.Close()
	}
}

// Test Email API Contracts
func (suite *APIContractTestSuite) TestEmailAPI_GetEmails_Success() {
	t := suite.T()
	
	// Act
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/emails")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.Status)
	
	// Verify response structure
	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)
	
	assert.True(t, apiResp.Success)
	assert.NotNil(t, apiResp.Meta)
	assert.NotEmpty(t, apiResp.Meta.RequestID)
	assert.NotZero(t, apiResp.Meta.Timestamp)
	assert.Equal(t, "v3", apiResp.Meta.Version)
	
	// Verify emails structure if data exists
	if apiResp.Data != nil {
		emails, ok := apiResp.Data.([]interface{})
		if ok && len(emails) > 0 {
			// Verify first email structure
			emailMap := emails[0].(map[string]interface{})
			suite.validateEmailStructure(t, emailMap)
		}
	}
}

func (suite *APIContractTestSuite) TestEmailAPI_GetEmails_WithPagination() {
	t := suite.T()
	
	// Act
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/emails?page=1&limit=10")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.Status)
	
	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)
	
	assert.True(t, apiResp.Success)
	assert.NotNil(t, apiResp.Meta)
	assert.Equal(t, 1, apiResp.Meta.Page)
	assert.Equal(t, 10, apiResp.Meta.Limit)
	assert.GreaterOrEqual(t, apiResp.Meta.Total, 0)
}

func (suite *APIContractTestSuite) TestEmailAPI_GetEmailByID_Success() {
	t := suite.T()
	
	// Act
	emailID := "test-email-123"
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/emails/" + emailID)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.Status)
	
	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)
	
	if apiResp.Success {
		// Validate email structure
		emailMap := apiResp.Data.(map[string]interface{})
		suite.validateEmailStructure(t, emailMap)
		assert.Equal(t, emailID, emailMap["id"])
	}
}

func (suite *APIContractTestSuite) TestEmailAPI_GetEmailByID_NotFound() {
	t := suite.T()
	
	// Act
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/emails/non-existent-id")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusNotFound, resp.Status)
	
	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)
	
	assert.False(t, apiResp.Success)
	assert.NotNil(t, apiResp.Error)
	assert.Equal(t, "NOT_FOUND", apiResp.Error.Code)
	assert.Contains(t, apiResp.Error.Message, "not found")
}

func (suite *APIContractTestSuite) TestEmailAPI_SearchEmails_Success() {
	t := suite.T()
	
	// Act
	searchQuery := "from:test@example.com"
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/emails/search?q=" + searchQuery)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.Status)
	
	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)
	
	assert.True(t, apiResp.Success)
	assert.NotNil(t, apiResp.Meta)
	
	// Validate search results
	if apiResp.Data != nil {
		emails := apiResp.Data.([]interface{})
		for _, email := range emails {
			emailMap := email.(map[string]interface{})
			suite.validateEmailStructure(t, emailMap)
		}
	}
}

func (suite *APIContractTestSuite) TestEmailAPI_DeleteEmail_Success() {
	t := suite.T()
	
	// Arrange
	emailID := "test-email-to-delete"
	
	// Act
	req, err := http.NewRequest("DELETE", suite.baseURL+"/api/v3/emails/"+emailID, nil)
	require.NoError(t, err)
	
	resp, err := suite.httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.Status)
	
	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)
	
	assert.True(t, apiResp.Success)
	assert.NotNil(t, apiResp.Meta)
}

// Test Plugin API Contracts
func (suite *APIContractTestSuite) TestPluginAPI_GetPlugins_Success() {
	t := suite.T()
	
	// Act
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/plugins")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.Status)
	
	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)
	
	assert.True(t, apiResp.Success)
	assert.NotNil(t, apiResp.Meta)
	
	// Validate plugin structure if data exists
	if apiResp.Data != nil {
		plugins := apiResp.Data.([]interface{})
		for _, plugin := range plugins {
			pluginMap := plugin.(map[string]interface{})
			suite.validatePluginStructure(t, pluginMap)
		}
	}
}

func (suite *APIContractTestSuite) TestPluginAPI_CreatePlugin_Success() {
	t := suite.T()
	
	// Arrange
	pluginData := map[string]interface{}{
		"name":        "Test Plugin",
		"version":     "1.0.0",
		"description": "A test plugin for contract validation",
		"author":      "Test Author",
		"hooks":       []string{"email_received", "email_processed"},
		"config": map[string]string{
			"setting1": "value1",
			"setting2": "value2",
		},
	}
	
	jsonData, err := json.Marshal(pluginData)
	require.NoError(t, err)
	
	// Act
	resp, err := suite.httpClient.Post(
		suite.baseURL+"/api/v3/plugins",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusCreated, resp.Status)
	
	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)
	
	assert.True(t, apiResp.Success)
	assert.NotNil(t, apiResp.Data)
	
	// Validate created plugin structure
	pluginMap := apiResp.Data.(map[string]interface{})
	suite.validatePluginStructure(t, pluginMap)
	assert.Equal(t, pluginData["name"], pluginMap["name"])
	assert.Equal(t, pluginData["version"], pluginMap["version"])
}

func (suite *APIContractTestSuite) TestPluginAPI_CreatePlugin_ValidationError() {
	t := suite.T()
	
	// Arrange - Invalid plugin data (missing required fields)
	pluginData := map[string]interface{}{
		"description": "A plugin without required fields",
	}
	
	jsonData, err := json.Marshal(pluginData)
	require.NoError(t, err)
	
	// Act
	resp, err := suite.httpClient.Post(
		suite.baseURL+"/api/v3/plugins",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusBadRequest, resp.Status)
	
	var apiResp APIResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	require.NoError(t, err)
	
	assert.False(t, apiResp.Success)
	assert.NotNil(t, apiResp.Error)
	assert.Equal(t, "VALIDATION_ERROR", apiResp.Error.Code)
	assert.Contains(t, apiResp.Error.Message, "validation")
}

// Test Health and Status API Contracts
func (suite *APIContractTestSuite) TestHealthAPI_GetHealth_Success() {
	t := suite.T()
	
	// Act
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.Status)
	
	var healthResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&healthResp)
	require.NoError(t, err)
	
	// Validate health response structure
	assert.Contains(t, healthResp, "status")
	assert.Contains(t, healthResp, "timestamp")
	assert.Contains(t, healthResp, "version")
	assert.Contains(t, healthResp, "services")
	
	services := healthResp["services"].(map[string]interface{})
	assert.NotEmpty(t, services)
	
	// Validate individual service health
	for serviceName, serviceStatus := range services {
		statusMap := serviceStatus.(map[string]interface{})
		assert.Contains(t, statusMap, "status")
		assert.Contains(t, statusMap, "last_check")
		suite.T().Logf("Service %s status: %v", serviceName, statusMap["status"])
	}
}

func (suite *APIContractTestSuite) TestStatusAPI_GetStatus_Success() {
	t := suite.T()
	
	// Act
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/status")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.Status)
	
	var statusResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&statusResp)
	require.NoError(t, err)
	
	// Validate status response structure
	assert.Contains(t, statusResp, "fortress")
	assert.Contains(t, statusResp, "uptime")
	assert.Contains(t, statusResp, "stats")
	assert.Contains(t, statusResp, "version")
	
	stats := statusResp["stats"].(map[string]interface{})
	assert.Contains(t, stats, "emails_processed")
	assert.Contains(t, stats, "plugins_loaded")
	assert.Contains(t, stats, "connections_active")
}

// Test HTTP Headers and CORS
func (suite *APIContractTestSuite) TestCORSHeaders() {
	t := suite.T()
	
	// Arrange - Create OPTIONS request
	req, err := http.NewRequest("OPTIONS", suite.baseURL+"/api/v3/emails", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "https://fortress-ui.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
	
	// Act
	resp, err := suite.httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.Status)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "GET")
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Headers"), "Content-Type")
}

func (suite *APIContractTestSuite) TestSecurityHeaders() {
	t := suite.T()
	
	// Act
	resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert security headers
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "deny", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
	assert.NotEmpty(t, resp.Header.Get("X-Request-ID"))
}

// Test Rate Limiting
func (suite *APIContractTestSuite) TestRateLimiting() {
	t := suite.T()
	
	// Act - Make multiple rapid requests
	var lastResp *http.Response
	for i := 0; i < 100; i++ {
		resp, err := suite.httpClient.Get(suite.baseURL + "/api/v3/health")
		require.NoError(t, err)
		if lastResp != nil {
			lastResp.Body.Close()
		}
		lastResp = resp
		
		// Check if we hit rate limit
		if resp.Status == http.StatusTooManyRequests {
			assert.NotEmpty(t, resp.Header.Get("Retry-After"))
			assert.NotEmpty(t, resp.Header.Get("X-RateLimit-Limit"))
			assert.NotEmpty(t, resp.Header.Get("X-RateLimit-Remaining"))
			break
		}
	}
	
	if lastResp != nil {
		lastResp.Body.Close()
	}
}

// Helper methods for validation
func (suite *APIContractTestSuite) validateEmailStructure(t *testing.T, email map[string]interface{}) {
	// Required fields
	assert.Contains(t, email, "id")
	assert.Contains(t, email, "from")
	assert.Contains(t, email, "to")
	assert.Contains(t, email, "subject")
	assert.Contains(t, email, "body")
	assert.Contains(t, email, "headers")
	assert.Contains(t, email, "created_at")
	assert.Contains(t, email, "status")
	
	// Validate email address structure
	if from, ok := email["from"].(map[string]interface{}); ok {
		assert.Contains(t, from, "address")
	}
	
	// Validate timestamp format
	if createdAt, ok := email["created_at"].(string); ok {
		_, err := time.Parse(time.RFC3339, createdAt)
		assert.NoError(t, err, "created_at should be valid RFC3339 timestamp")
	}
	
	// Validate status values
	if status, ok := email["status"].(string); ok {
		validStatuses := []string{"received", "processed", "delivered", "failed"}
		assert.Contains(t, validStatuses, status)
	}
}

func (suite *APIContractTestSuite) validatePluginStructure(t *testing.T, plugin map[string]interface{}) {
	// Required fields
	assert.Contains(t, plugin, "id")
	assert.Contains(t, plugin, "name")
	assert.Contains(t, plugin, "version")
	assert.Contains(t, plugin, "status")
	assert.Contains(t, plugin, "created_at")
	assert.Contains(t, plugin, "updated_at")
	assert.Contains(t, plugin, "hooks")
	
	// Validate hooks array
	if hooks, ok := plugin["hooks"].([]interface{}); ok {
		for _, hook := range hooks {
			assert.IsType(t, "", hook, "Hook should be a string")
		}
	}
	
	// Validate status values
	if status, ok := plugin["status"].(string); ok {
		validStatuses := []string{"loaded", "unloaded", "error", "disabled"}
		assert.Contains(t, validStatuses, status)
	}
}

// Mock HTTP handlers for testing
func (suite *APIContractTestSuite) handleEmails(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		suite.handleGetEmails(w, r)
	case "POST":
		suite.handleCreateEmail(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (suite *APIContractTestSuite) handleGetEmails(w http.ResponseWriter, r *http.Request) {
	// Mock email data
	emails := []EmailMessage{
		{
			ID:      "email-123",
			Subject: "Test Email",
			From:    &EmailAddress{Address: "sender@example.com", Name: "Test Sender"},
			To:      []*EmailAddress{{Address: "recipient@example.com", Name: "Test Recipient"}},
			Body:    "This is a test email",
			Headers: map[string]string{
				"Content-Type": "text/plain",
				"Date":        time.Now().Format(time.RFC1123),
			},
			CreatedAt: time.Now(),
			Status:    "received",
		},
	}
	
	response := APIResponse{
		Success: true,
		Data:    emails,
		Meta: &APIMeta{
			RequestID: "req-" + generateID(),
			Timestamp: time.Now(),
			Version:   "v3",
			Total:     len(emails),
			Page:      1,
			Limit:     50,
		},
	}
	
	suite.sendJSONResponse(w, http.StatusOK, response)
}

func (suite *APIContractTestSuite) handleEmailByID(w http.ResponseWriter, r *http.Request) {
	emailID := strings.TrimPrefix(r.URL.Path, "/api/v3/emails/")
	
	switch r.Method {
	case "GET":
		if emailID == "non-existent-id" {
			suite.sendErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "Email not found")
			return
		}
		
		email := EmailMessage{
			ID:      emailID,
			Subject: "Test Email " + emailID,
			From:    &EmailAddress{Address: "sender@example.com"},
			To:      []*EmailAddress{{Address: "recipient@example.com"}},
			Body:    "Test email body",
			Headers: map[string]string{"Content-Type": "text/plain"},
			CreatedAt: time.Now(),
			Status:    "received",
		}
		
		response := APIResponse{
			Success: true,
			Data:    email,
			Meta: &APIMeta{
				RequestID: "req-" + generateID(),
				Timestamp: time.Now(),
				Version:   "v3",
			},
		}
		
		suite.sendJSONResponse(w, http.StatusOK, response)
		
	case "DELETE":
		response := APIResponse{
			Success: true,
			Meta: &APIMeta{
				RequestID: "req-" + generateID(),
				Timestamp: time.Now(),
				Version:   "v3",
			},
		}
		
		suite.sendJSONResponse(w, http.StatusOK, response)
		
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (suite *APIContractTestSuite) handleEmailSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		suite.sendErrorResponse(w, http.StatusBadRequest, "INVALID_QUERY", "Search query is required")
		return
	}
	
	// Mock search results
	emails := []EmailMessage{
		{
			ID:      "search-result-1",
			Subject: "Search Result",
			From:    &EmailAddress{Address: "test@example.com"},
			To:      []*EmailAddress{{Address: "recipient@example.com"}},
			Body:    "Search result email",
			Headers: map[string]string{"Content-Type": "text/plain"},
			CreatedAt: time.Now(),
			Status:    "received",
		},
	}
	
	response := APIResponse{
		Success: true,
		Data:    emails,
		Meta: &APIMeta{
			RequestID: "req-" + generateID(),
			Timestamp: time.Now(),
			Version:   "v3",
			Total:     len(emails),
		},
	}
	
	suite.sendJSONResponse(w, http.StatusOK, response)
}

func (suite *APIContractTestSuite) handlePlugins(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		suite.handleGetPlugins(w, r)
	case "POST":
		suite.handleCreatePlugin(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (suite *APIContractTestSuite) handleGetPlugins(w http.ResponseWriter, r *http.Request) {
	plugins := []PluginInfo{
		{
			ID:          "plugin-123",
			Name:        "Test Plugin",
			Version:     "1.0.0",
			Description: "A test plugin",
			Author:      "Test Author",
			Status:      "loaded",
			Hooks:       []string{"email_received"},
			CreatedAt:   time.Now().Add(-24 * time.Hour),
			UpdatedAt:   time.Now(),
		},
	}
	
	response := APIResponse{
		Success: true,
		Data:    plugins,
		Meta: &APIMeta{
			RequestID: "req-" + generateID(),
			Timestamp: time.Now(),
			Version:   "v3",
			Total:     len(plugins),
		},
	}
	
	suite.sendJSONResponse(w, http.StatusOK, response)
}

func (suite *APIContractTestSuite) handleCreatePlugin(w http.ResponseWriter, r *http.Request) {
	var pluginData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&pluginData); err != nil {
		suite.sendErrorResponse(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON data")
		return
	}
	
	// Validate required fields
	if _, ok := pluginData["name"]; !ok {
		suite.sendErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Name is required")
		return
	}
	
	if _, ok := pluginData["version"]; !ok {
		suite.sendErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Version is required")
		return
	}
	
	// Create plugin response
	plugin := PluginInfo{
		ID:          "plugin-" + generateID(),
		Name:        pluginData["name"].(string),
		Version:     pluginData["version"].(string),
		Description: getStringValue(pluginData, "description"),
		Author:      getStringValue(pluginData, "author"),
		Status:      "loaded",
		Hooks:       getStringArray(pluginData, "hooks"),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	response := APIResponse{
		Success: true,
		Data:    plugin,
		Meta: &APIMeta{
			RequestID: "req-" + generateID(),
			Timestamp: time.Now(),
			Version:   "v3",
		},
	}
	
	suite.sendJSONResponse(w, http.StatusCreated, response)
}

func (suite *APIContractTestSuite) handlePluginByID(w http.ResponseWriter, r *http.Request) {
	pluginID := strings.TrimPrefix(r.URL.Path, "/api/v3/plugins/")
	
	switch r.Method {
	case "GET":
		plugin := PluginInfo{
			ID:          pluginID,
			Name:        "Plugin " + pluginID,
			Version:     "1.0.0",
			Description: "Test plugin",
			Status:      "loaded",
			Hooks:       []string{"email_received"},
			CreatedAt:   time.Now().Add(-24 * time.Hour),
			UpdatedAt:   time.Now(),
		}
		
		response := APIResponse{
			Success: true,
			Data:    plugin,
			Meta: &APIMeta{
				RequestID: "req-" + generateID(),
				Timestamp: time.Now(),
				Version:   "v3",
			},
		}
		
		suite.sendJSONResponse(w, http.StatusOK, response)
		
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (suite *APIContractTestSuite) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Add security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "deny")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Request-ID", "req-"+generateID())
	
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "v3.0.0",
		"services": map[string]interface{}{
			"database": map[string]interface{}{
				"status":     "healthy",
				"last_check": time.Now(),
			},
			"smtp": map[string]interface{}{
				"status":     "healthy",
				"last_check": time.Now(),
			},
			"plugins": map[string]interface{}{
				"status":     "healthy",
				"last_check": time.Now(),
			},
		},
	}
	
	suite.sendJSONResponse(w, http.StatusOK, health)
}

func (suite *APIContractTestSuite) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"fortress": "Pat Fortress v3.0.0",
		"uptime":   "2h 15m 30s",
		"version":  "v3.0.0",
		"stats": map[string]interface{}{
			"emails_processed":   1234,
			"plugins_loaded":     5,
			"connections_active": 42,
		},
	}
	
	suite.sendJSONResponse(w, http.StatusOK, status)
}

// Helper methods
func (suite *APIContractTestSuite) sendJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteStatus(status)
	json.NewEncoder(w).Encode(data)
}

func (suite *APIContractTestSuite) sendErrorResponse(w http.ResponseWriter, status int, code, message string) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
		},
		Meta: &APIMeta{
			RequestID: "req-" + generateID(),
			Timestamp: time.Now(),
			Version:   "v3",
		},
	}
	
	suite.sendJSONResponse(w, status, response)
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func getStringValue(data map[string]interface{}, key string) string {
	if value, ok := data[key].(string); ok {
		return value
	}
	return ""
}

func getStringArray(data map[string]interface{}, key string) []string {
	if value, ok := data[key].([]interface{}); ok {
		result := make([]string, len(value))
		for i, v := range value {
			if str, ok := v.(string); ok {
				result[i] = str
			}
		}
		return result
	}
	return []string{}
}

// Run the test suite
func TestAPIContractSuite(t *testing.T) {
	suite.Run(t, new(APIContractTestSuite))
}