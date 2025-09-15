package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pat-fortress/pkg/fortress/legacy"
)

// EmailAnalyzer provides AI-powered email analysis
type EmailAnalyzer struct {
	provider AIProvider
	enabled  bool
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

// NewEmailAnalyzer creates a simple email analyzer
func NewEmailAnalyzer(provider AIProvider) *EmailAnalyzer {
	return &EmailAnalyzer{
		provider: provider,
		enabled:  provider != nil,
	}
}

// AnalyzeEmail performs AI analysis on an email (if enabled)
func (a *EmailAnalyzer) AnalyzeEmail(email *legacy.Message) (*Analysis, error) {
	if !a.enabled {
		return &Analysis{
			EmailID:   string(email.ID),
			Timestamp: time.Now(),
			Summary:   "AI analysis disabled",
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	analysis, err := a.provider.AnalyzeEmail(ctx, email)
	if err != nil {
		// Graceful degradation - return basic analysis
		return &Analysis{
			EmailID:   string(email.ID),
			Timestamp: time.Now(),
			Summary:   "AI analysis unavailable: " + err.Error(),
		}, nil
	}

	return analysis, nil
}

// SimpleOpenAIProvider implements basic OpenAI integration
type SimpleOpenAIProvider struct {
	apiKey string
	model  string
}

func NewOpenAIProvider(apiKey, model string) *SimpleOpenAIProvider {
	return &SimpleOpenAIProvider{
		apiKey: apiKey,
		model:  model,
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

	// Try AI analysis first, fallback to basic if it fails
	analysis, err := p.callOpenAI(ctx, prompt)
	if err != nil {
		// Graceful fallback to basic analysis
		basic := p.getBasicAnalysis(email)
		basic.Summary = "AI analysis unavailable, using basic checks: " + basic.Summary
		return basic, nil
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

	// Make request
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse OpenAI response
	var openAIResp openAIResponse
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAI response: %w", err)
	}

	if openAIResp.Error != nil {
		return nil, fmt.Errorf("OpenAI API error: %s", openAIResp.Error.Message)
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("no response choices from OpenAI")
	}

	// Parse the JSON content from OpenAI
	var analysis Analysis
	content := openAIResp.Choices[0].Message.Content
	if err := json.Unmarshal([]byte(content), &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse AI analysis JSON: %w", err)
	}

	return &analysis, nil
}