package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pat-fortress/pkg/fortress/legacy"
)

// EmailAnalyzer provides AI-powered email analysis with enhanced error handling
type EmailAnalyzer struct {
	provider AIProvider
	enabled  bool
	retryer  *RetryerWithStats
	config   *AnalyzerConfig
}

// AnalyzerConfig defines configuration for the email analyzer
type AnalyzerConfig struct {
	Timeout         time.Duration `json:"timeout"`
	RetryConfig     *RetryConfig  `json:"retry_config"`
	FallbackEnabled bool          `json:"fallback_enabled"`
	MaxConcurrent   int           `json:"max_concurrent"`
}

// AIProvider interface for different AI services
type AIProvider interface {
	AnalyzeEmail(ctx context.Context, email *legacy.Message) (*Analysis, error)
}

// Analysis results from AI analysis
type Analysis struct {
	EmailID     string    `json:"email_id"`
	Timestamp   time.Time `json:"timestamp"`

	// Practical insights developers actually need
	SpamRisk    SpamRisk    `json:"spam_risk"`
	ContentIssues []Issue   `json:"content_issues"`
	DeliverabilityIssues []Issue `json:"deliverability_issues"`

	// Quick summary for busy developers
	Summary     string     `json:"summary"`
	Confidence  float64    `json:"confidence"`
}

type SpamRisk struct {
	Score      float64  `json:"score"`        // 0-100
	Level      string   `json:"level"`        // low/medium/high
	Reasons    []string `json:"reasons"`      // Specific issues found
}

type Issue struct {
	Type        string `json:"type"`         // "mime", "links", "tone", "security"
	Severity    string `json:"severity"`     // "low", "medium", "high"
	Description string `json:"description"`  // Human readable
	Location    string `json:"location"`     // "subject", "body", "headers"
	Suggestion  string `json:"suggestion"`   // How to fix
}

// DefaultAnalyzerConfig returns default analyzer configuration
func DefaultAnalyzerConfig() *AnalyzerConfig {
	return &AnalyzerConfig{
		Timeout:         30 * time.Second,
		RetryConfig:     DefaultRetryConfig(),
		FallbackEnabled: true,
		MaxConcurrent:   5,
	}
}

// NewEmailAnalyzer creates a new email analyzer with enhanced error handling
func NewEmailAnalyzer(provider AIProvider) *EmailAnalyzer {
	config := DefaultAnalyzerConfig()
	return &EmailAnalyzer{
		provider: provider,
		enabled:  provider != nil,
		retryer:  NewRetryerWithStats(config.RetryConfig),
		config:   config,
	}
}

// NewEmailAnalyzerWithConfig creates a new email analyzer with custom configuration
func NewEmailAnalyzerWithConfig(provider AIProvider, config *AnalyzerConfig) *EmailAnalyzer {
	if config == nil {
		config = DefaultAnalyzerConfig()
	}
	return &EmailAnalyzer{
		provider: provider,
		enabled:  provider != nil,
		retryer:  NewRetryerWithStats(config.RetryConfig),
		config:   config,
	}
}

// AnalyzeEmail performs AI analysis on an email with enhanced error handling and retry logic
func (a *EmailAnalyzer) AnalyzeEmail(email *legacy.Message) (*Analysis, error) {
	if !a.enabled {
		return a.getFallbackAnalysis(email, "AI analysis disabled"), nil
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
	defer cancel()

	var result *Analysis

	// Execute with retry logic
	err := a.retryer.Execute(ctx, func(ctx context.Context) error {
		analysis, err := a.provider.AnalyzeEmail(ctx, email)
		if err != nil {
			return err
		}
		result = analysis
		return nil
	})

	if err != nil {
		// If fallback is enabled, return a basic analysis
		if a.config.FallbackEnabled {
			return a.getFallbackAnalysis(email, fmt.Sprintf("AI analysis failed: %v", err)), nil
		}

		// Return the original error with enhanced information
		if aiErr, ok := err.(*AIError); ok {
			return nil, aiErr
		}

		// Wrap unknown errors
		return nil, NewAIError("analysis_failed", fmt.Sprintf("AI analysis failed: %v", err), false, err)
	}

	return result, nil
}

// getFallbackAnalysis provides a basic fallback analysis when AI is unavailable
func (a *EmailAnalyzer) getFallbackAnalysis(email *legacy.Message, reason string) *Analysis {
	// Perform basic analysis without AI
	spamScore := a.calculateBasicSpamScore(email)
	issues := a.detectBasicIssues(email)

	return &Analysis{
		EmailID:   string(email.ID),
		Timestamp: time.Now(),
		SpamRisk: SpamRisk{
			Score:   spamScore,
			Level:   a.getSpamLevel(spamScore),
			Reasons: []string{reason},
		},
		ContentIssues:        issues,
		DeliverabilityIssues: []Issue{},
		Summary:              fmt.Sprintf("Basic analysis completed (%s)", reason),
		Confidence:           0.3, // Lower confidence for fallback analysis
	}
}

// calculateBasicSpamScore performs basic spam scoring without AI
func (a *EmailAnalyzer) calculateBasicSpamScore(email *legacy.Message) float64 {
	score := 0.0

	if email.Content == nil {
		return score
	}

	// Check for common spam indicators
	content := strings.ToLower(email.Content.Body)
	subject := ""
	if subjectHeaders, ok := email.Content.Headers["Subject"]; ok && len(subjectHeaders) > 0 {
		subject = strings.ToLower(subjectHeaders[0])
	}

	// Basic spam keywords
	spamWords := []string{"free", "urgent", "act now", "limited time", "click here", "guarantee"}
	for _, word := range spamWords {
		if strings.Contains(content, word) || strings.Contains(subject, word) {
			score += 10
		}
	}

	// Excessive caps
	if strings.Count(subject, strings.ToUpper(subject)) > len(subject)/2 {
		score += 15
	}

	// Multiple exclamation marks
	if strings.Count(content, "!") > 3 {
		score += 10
	}

	return math.Min(score, 100) // Cap at 100
}

// detectBasicIssues performs basic issue detection without AI
func (a *EmailAnalyzer) detectBasicIssues(email *legacy.Message) []Issue {
	var issues []Issue

	if email.Content == nil {
		return issues
	}

	// Check for missing subject
	if subjectHeaders, ok := email.Content.Headers["Subject"]; !ok || len(subjectHeaders) == 0 || strings.TrimSpace(subjectHeaders[0]) == "" {
		issues = append(issues, Issue{
			Type:        "headers",
			Severity:    "medium",
			Description: "Missing or empty subject line",
			Location:    "headers",
			Suggestion:  "Add a descriptive subject line",
		})
	}

	// Check for missing From header
	if fromHeaders, ok := email.Content.Headers["From"]; !ok || len(fromHeaders) == 0 {
		issues = append(issues, Issue{
			Type:        "headers",
			Severity:    "high",
			Description: "Missing From header",
			Location:    "headers",
			Suggestion:  "Add a valid From header",
		})
	}

	// Check for very short content
	if len(strings.TrimSpace(email.Content.Body)) < 10 {
		issues = append(issues, Issue{
			Type:        "content",
			Severity:    "low",
			Description: "Very short email content",
			Location:    "body",
			Suggestion:  "Consider adding more meaningful content",
		})
	}

	return issues
}

// getSpamLevel converts spam score to level
func (a *EmailAnalyzer) getSpamLevel(score float64) string {
	if score >= 70 {
		return "high"
	} else if score >= 30 {
		return "medium"
	} else if score > 0 {
		return "low"
	}
	return "none"
}

// GetStats returns statistics about the analyzer's performance
func (a *EmailAnalyzer) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled": a.enabled,
		"config":  a.config,
	}

	if a.retryer != nil {
		stats["retry_stats"] = a.retryer.GetStats()
	}

	return stats
}

// HTTPClientPool manages shared HTTP clients with connection pooling
type HTTPClientPool struct {
	mu      sync.RWMutex
	clients map[string]*http.Client
	metrics *PoolMetrics
}

// PoolMetrics tracks connection pool statistics
type PoolMetrics struct {
	ActiveConnections   int64
	TotalRequests       int64
	SuccessfulRequests  int64
	FailedRequests      int64
	AverageResponseTime time.Duration
	mu                  sync.RWMutex
}

// Global shared HTTP client pool
var (
	globalHTTPPool *HTTPClientPool
	poolOnce       sync.Once
)

// GetHTTPClientPool returns the singleton HTTP client pool
func GetHTTPClientPool() *HTTPClientPool {
	poolOnce.Do(func() {
		globalHTTPPool = &HTTPClientPool{
			clients: make(map[string]*http.Client),
			metrics: &PoolMetrics{},
		}
	})
	return globalHTTPPool
}

// GetClient returns an optimized HTTP client for the given provider
func (p *HTTPClientPool) GetClient(provider string) *http.Client {
	p.mu.RLock()
	client, exists := p.clients[provider]
	p.mu.RUnlock()

	if exists {
		return client
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if client, exists := p.clients[provider]; exists {
		return client
	}

	// Create optimized client with connection pooling
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       50,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
	}

	client = &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second, // Generous timeout for AI services
	}

	p.clients[provider] = client
	return client
}

// RecordRequest updates pool metrics
func (p *HTTPClientPool) RecordRequest(success bool, responseTime time.Duration) {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	p.metrics.TotalRequests++
	if success {
		p.metrics.SuccessfulRequests++
	} else {
		p.metrics.FailedRequests++
	}

	// Update average response time using exponential moving average
	alpha := 0.1 // Smoothing factor
	if p.metrics.AverageResponseTime == 0 {
		p.metrics.AverageResponseTime = responseTime
	} else {
		p.metrics.AverageResponseTime = time.Duration(
			alpha*float64(responseTime) + (1-alpha)*float64(p.metrics.AverageResponseTime),
		)
	}
}

// GetMetrics returns current pool metrics
func (p *HTTPClientPool) GetMetrics() PoolMetrics {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()
	return *p.metrics
}

// SimpleOpenAIProvider implements basic OpenAI integration
type SimpleOpenAIProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
	pool       *HTTPClientPool
}

func NewOpenAIProvider(apiKey, model string) *SimpleOpenAIProvider {
	pool := GetHTTPClientPool()
	return &SimpleOpenAIProvider{
		apiKey:     apiKey,
		model:      model,
		httpClient: pool.GetClient("openai"),
		pool:       pool,
	}
}

// OllamaProvider implements AIProvider for Ollama local models
type OllamaProvider struct {
	baseURL    string
	model      string
	httpClient *http.Client
	pool       *HTTPClientPool
}

// NewOllamaProvider creates a new Ollama provider
func NewOllamaProvider(baseURL, model string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434" // Default Ollama URL
	}
	pool := GetHTTPClientPool()
	return &OllamaProvider{
		baseURL:    baseURL,
		model:      model,
		httpClient: pool.GetClient("ollama"),
		pool:       pool,
	}
}

func (p *SimpleOpenAIProvider) AnalyzeEmail(ctx context.Context, email *legacy.Message) (*Analysis, error) {
	// If no API key provided, fall back to basic analysis
	if p.apiKey == "" {
		return p.getBasicAnalysis(email), nil
	}

	// Build focused prompt for email analysis
	prompt := fmt.Sprintf(`Analyze this email for practical development issues. Return JSON only:

Email Details:
Subject: %s
From: %s
Body: %s

Return this exact JSON structure:
{
  "spam_risk": {
    "score": 0-100,
    "level": "low|medium|high",
    "reasons": ["specific issues found"]
  },
  "content_issues": [
    {"type": "tone|links|formatting", "severity": "low|medium|high", "description": "issue", "suggestion": "fix"}
  ],
  "deliverability_issues": [
    {"type": "headers|structure", "severity": "low|medium|high", "description": "issue", "suggestion": "fix"}
  ],
  "summary": "brief assessment",
  "confidence": 0.0-1.0
}`,
		getHeader(email, "Subject"),
		email.From.String(),
		email.Content.Body)

	// Try AI analysis with enhanced error handling
	analysis, err := p.callOpenAI(ctx, prompt)
	if err != nil {
		// Return enhanced error instead of always falling back
		return nil, err
	}

	// Set metadata that AI doesn't handle
	analysis.EmailID = string(email.ID)
	analysis.Timestamp = time.Now()

	return analysis, nil
}

func (p *SimpleOpenAIProvider) getBasicAnalysis(email *legacy.Message) *Analysis {
	return &Analysis{
		EmailID:   string(email.ID),
		Timestamp: time.Now(),
		SpamRisk: SpamRisk{
			Score:   calculateBasicSpamScore(email),
			Level:   getSpamLevel(calculateBasicSpamScore(email)),
			Reasons: getSpamReasons(email),
		},
		ContentIssues:        analyzeContent(email),
		DeliverabilityIssues: analyzeDeliverability(email),
		Summary:             generateSummary(email),
		Confidence:          0.75, // Lower confidence for basic analysis
	}
}

// Helper functions for basic analysis (fallback when AI unavailable)
func calculateBasicSpamScore(email *legacy.Message) float64 {
	score := 0.0

	// Check for spam indicators
	subject := strings.ToLower(getHeader(email, "Subject"))
	body := strings.ToLower(email.Content.Body)

	if strings.Contains(subject, "urgent") || strings.Contains(subject, "act now") {
		score += 20
	}
	if strings.Count(subject, "!") > 2 {
		score += 15
	}
	if strings.Contains(body, "click here") {
		score += 10
	}
	if len(strings.Split(subject, " ")) > 10 {
		score += 5
	}

	return score
}

func getSpamLevel(score float64) string {
	if score < 30 {
		return "low"
	} else if score < 70 {
		return "medium"
	}
	return "high"
}

func getSpamReasons(email *legacy.Message) []string {
	reasons := []string{}
	subject := strings.ToLower(getHeader(email, "Subject"))

	if strings.Contains(subject, "urgent") {
		reasons = append(reasons, "Subject contains urgency keywords")
	}
	if strings.Count(subject, "!") > 2 {
		reasons = append(reasons, "Excessive exclamation marks in subject")
	}

	return reasons
}

func analyzeContent(email *legacy.Message) []Issue {
	issues := []Issue{}

	// Check for broken links (simple version)
	if strings.Contains(email.Content.Body, "http://") {
		issues = append(issues, Issue{
			Type:        "security",
			Severity:    "medium",
			Description: "Non-HTTPS links found",
			Location:    "body",
			Suggestion:  "Use HTTPS links for better security",
		})
	}

	return issues
}

func analyzeDeliverability(email *legacy.Message) []Issue {
	issues := []Issue{}

	// Check for missing headers
	if getHeader(email, "Return-Path") == "" {
		issues = append(issues, Issue{
			Type:        "deliverability",
			Severity:    "low",
			Description: "Missing Return-Path header",
			Location:    "headers",
			Suggestion:  "Add Return-Path header for better deliverability",
		})
	}

	return issues
}

func generateSummary(email *legacy.Message) string {
	score := calculateBasicSpamScore(email)
	if score < 30 {
		return "Email looks good for delivery"
	} else if score < 70 {
		return "Some potential deliverability issues detected"
	}
	return "High spam risk - review before sending"
}

func getHeader(email *legacy.Message, key string) string {
	if headers, ok := email.Content.Headers[key]; ok && len(headers) > 0 {
		return headers[0]
	}
	return ""
}

// Helper functions for email data extraction
func getEmailSubject(email *legacy.Message) string {
	return getHeader(email, "Subject")
}

func getEmailFrom(email *legacy.Message) string {
	if email.From != nil {
		return email.From.String()
	}
	return getHeader(email, "From")
}

func getEmailBody(email *legacy.Message) string {
	if email.Content != nil {
		return email.Content.Body
	}
	return ""
}

func getEmailID(email *legacy.Message) legacy.MessageID {
	return email.ID
}

// OpenAI API structures
type openAIRequest struct {
	Model       string    `json:"model"`
	Messages    []message `json:"messages"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []choice `json:"choices"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type choice struct {
	Message message `json:"message"`
}

// callOpenAI makes the actual API call to OpenAI
func (p *SimpleOpenAIProvider) callOpenAI(ctx context.Context, prompt string) (*Analysis, error) {
	// Build request
	reqData := openAIRequest{
		Model: p.model,
		Messages: []message{
			{
				Role:    "system",
				Content: "You are a helpful email analysis assistant. Return only valid JSON in the requested format.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		Temperature: 0.3, // Low temperature for consistent results
		MaxTokens:   1000,
	}

	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	// Make request with connection pooling
	start := time.Now()
	resp, err := p.httpClient.Do(req)
	responseTime := time.Since(start)

	// Record metrics
	p.pool.RecordRequest(err == nil && resp != nil && resp.StatusCode == http.StatusOK, responseTime)
	if err != nil {
		return nil, NewNetworkError(fmt.Sprintf("API request failed: %v", err), true, err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewNetworkError(fmt.Sprintf("Failed to read response: %v", err), true, err)
	}

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, ClassifyHTTPError(resp.StatusCode, string(body), fmt.Errorf("HTTP %d", resp.StatusCode))
	}

	// Parse OpenAI response
	var openAIResp openAIResponse
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		return nil, NewAIError("parse_error", fmt.Sprintf("Failed to parse OpenAI response: %v", err), false, err)
	}

	if openAIResp.Error != nil {
		// Handle OpenAI-specific errors based on message content
		errorMsg := openAIResp.Error.Message
		if strings.Contains(errorMsg, "quota") || strings.Contains(errorMsg, "billing") {
			return nil, NewQuotaError(fmt.Errorf("OpenAI quota exceeded: %s", errorMsg))
		} else if strings.Contains(errorMsg, "api_key") || strings.Contains(errorMsg, "authentication") {
			return nil, NewAuthenticationError(fmt.Errorf("Invalid OpenAI API key: %s", errorMsg))
		} else if strings.Contains(errorMsg, "rate") && strings.Contains(errorMsg, "limit") {
			return nil, NewRateLimitError(60*time.Second, fmt.Errorf("OpenAI rate limit exceeded: %s", errorMsg))
		} else if strings.Contains(errorMsg, "model") && strings.Contains(errorMsg, "not found") {
			return nil, NewModelError(p.model, fmt.Errorf("OpenAI model error: %s", errorMsg))
		} else {
			return nil, NewAIError("openai_error", errorMsg, false, fmt.Errorf("OpenAI API error: %s", errorMsg))
		}
	}

	if len(openAIResp.Choices) == 0 {
		return nil, NewAIError("no_response", "No response choices from OpenAI", true, fmt.Errorf("empty response from OpenAI"))
	}

	// Parse the JSON content from OpenAI
	var analysis Analysis
	content := openAIResp.Choices[0].Message.Content
	if err := json.Unmarshal([]byte(content), &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse AI analysis JSON: %w", err)
	}

	return &analysis, nil
}

// AnalyzeEmail implements AIProvider for Ollama
func (p *OllamaProvider) AnalyzeEmail(ctx context.Context, email *legacy.Message) (*Analysis, error) {
	if p.model == "" {
		return nil, NewAIError("model_error", "No Ollama model specified", false, nil)
	}

	// Build the same focused prompt as OpenAI
	prompt := fmt.Sprintf(`Analyze this email for practical development issues. Return JSON only:

Email Details:
Subject: %s
From: %s
Body: %s

Return this exact JSON structure:
{
  "spam_risk": {
    "score": 0-100,
    "level": "low|medium|high",
    "reasons": ["reason1", "reason2"]
  },
  "summary": "Brief analysis summary",
  "confidence": 0.0-1.0
}`,
		getEmailSubject(email),
		getEmailFrom(email),
		getEmailBody(email))

	// Create Ollama request payload
	payload := map[string]interface{}{
		"model":  p.model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.3,
		},
	}

	// Convert to JSON
	reqData, err := json.Marshal(payload)
	if err != nil {
		return nil, NewAIError("request_error", fmt.Sprintf("Failed to marshal request: %v", err), false, err)
	}

	// Execute with circuit breaker protection
	var analysis *Analysis
	err = p.circuitBreaker.Execute(ctx, func(ctx context.Context) error {
		result, err := p.callOllama(ctx, reqData)
		if err != nil {
			return err
		}
		analysis = result
		return nil
	})

	if err != nil {
		// Check if it's a circuit breaker error
		if cbErr, ok := err.(*CircuitBreakerError); ok {
			return nil, NewAIError("circuit_breaker",
				fmt.Sprintf("Ollama service temporarily unavailable: %v", cbErr),
				true, err)
		}
		return nil, err
	}

	return analysis, nil
}

// callOllama makes the actual API call to Ollama
func (p *OllamaProvider) callOllama(ctx context.Context, reqData []byte) (*Analysis, error) {
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/generate", bytes.NewBuffer(reqData))
	if err != nil {
		return nil, NewNetworkError(fmt.Sprintf("Failed to create request: %v", err), true, err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Make the request with connection pooling
	start := time.Now()
	resp, err := p.httpClient.Do(req)
	responseTime := time.Since(start)

	// Record metrics
	p.pool.RecordRequest(err == nil && resp != nil && resp.StatusCode == http.StatusOK, responseTime)
	if err != nil {
		return nil, NewNetworkError(fmt.Sprintf("Failed to connect to Ollama: %v", err), true, err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewNetworkError(fmt.Sprintf("Failed to read Ollama response: %v", err), true, err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return nil, ClassifyHTTPError(resp.StatusCode, string(body), fmt.Errorf("Ollama HTTP %d", resp.StatusCode))
	}

	// Parse Ollama response
	var ollamaResp struct {
		Response string `json:"response"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return nil, NewAIError("parse_error", fmt.Sprintf("Failed to parse Ollama response: %v", err), false, err)
	}

	if ollamaResp.Error != "" {
		return nil, NewAIError("ollama_error", ollamaResp.Error, false, fmt.Errorf("Ollama error: %s", ollamaResp.Error))
	}

	// Parse the JSON content from Ollama
	var analysis Analysis
	if err := json.Unmarshal([]byte(ollamaResp.Response), &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse Ollama analysis JSON: %w", err)
	}

	// Set metadata
	analysis.EmailID = string(getEmailID(email))
	analysis.Timestamp = time.Now()

	return &analysis, nil
}

// OllamaModel represents a model available in Ollama
type OllamaModel struct {
	Name     string `json:"name"`
	Modified string `json:"modified_at"`
	Size     int64  `json:"size"`
}

// GetOllamaModels fetches available models from Ollama
func GetOllamaModels(baseURL string) ([]OllamaModel, error) {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	pool := GetHTTPClientPool()
	client := pool.GetClient("ollama-models")
	resp, err := client.Get(baseURL + "/api/tags")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ollama: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama returned status %d", resp.StatusCode)
	}

	var response struct {
		Models []OllamaModel `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse Ollama response: %w", err)
	}

	return response.Models, nil
}

// CheckOllamaAvailability checks if Ollama is running and accessible
func CheckOllamaAvailability(baseURL string) bool {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	pool := GetHTTPClientPool()
	client := pool.GetClient("ollama-health")
	resp, err := client.Get(baseURL + "/api/version")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}