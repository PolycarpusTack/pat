package analyzer

import (
    "context"
    "net/mail"
    "strings"
    "testing"
    "time"

    "github.com/pat-fortress/pkg/fortress/legacy"
)

func TestDefaultAnalyzerConfig(t *testing.T) {
	config := DefaultAnalyzerConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("Expected timeout to be 30s, got %v", config.Timeout)
	}

	if !config.FallbackEnabled {
		t.Error("Expected fallback to be enabled by default")
	}

	if config.MaxConcurrent != 5 {
		t.Errorf("Expected max concurrent to be 5, got %d", config.MaxConcurrent)
	}

	if config.RetryConfig == nil {
		t.Error("Expected retry config to be set")
	}
}

func TestNewEmailAnalyzer(t *testing.T) {
	// Test with nil provider
	analyzer := NewEmailAnalyzer(nil)
	if analyzer.enabled {
		t.Error("Expected analyzer to be disabled with nil provider")
	}

	// Test with mock provider
	mockProvider := &MockAIProvider{}
	analyzer = NewEmailAnalyzer(mockProvider)
	if !analyzer.enabled {
		t.Error("Expected analyzer to be enabled with valid provider")
	}

	if analyzer.retryer == nil {
		t.Error("Expected retryer to be initialized")
	}

	if analyzer.config == nil {
		t.Error("Expected config to be initialized")
	}
}

func TestEmailAnalyzer_AnalyzeEmail_Disabled(t *testing.T) {
	analyzer := NewEmailAnalyzer(nil)

	email := createTestEmail()
	analysis, err := analyzer.AnalyzeEmail(email)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if analysis == nil {
		t.Fatal("Expected analysis result")
	}

	if analysis.Summary != "Basic analysis completed (AI analysis disabled)" {
		t.Errorf("Expected fallback summary, got: %s", analysis.Summary)
	}

	if analysis.Confidence != 0.3 {
		t.Errorf("Expected confidence 0.3, got %f", analysis.Confidence)
	}
}

func TestEmailAnalyzer_AnalyzeEmail_WithFallback(t *testing.T) {
	mockProvider := &MockAIProvider{
		shouldFail: true,
		error:      NewNetworkError("Network timeout", true, nil),
	}

	analyzer := NewEmailAnalyzerWithConfig(mockProvider, &AnalyzerConfig{
		Timeout:         5 * time.Second,
		RetryConfig:     &RetryConfig{MaxRetries: 1},
		FallbackEnabled: true,
		MaxConcurrent:   5,
	})

	email := createTestEmail()
	analysis, err := analyzer.AnalyzeEmail(email)

	if err != nil {
		t.Errorf("Expected no error with fallback enabled, got %v", err)
	}

	if analysis == nil {
		t.Fatal("Expected analysis result")
	}

	if !strings.Contains(analysis.Summary, "Basic analysis completed") {
		t.Errorf("Expected fallback analysis summary, got: %s", analysis.Summary)
	}
}

func TestEmailAnalyzer_AnalyzeEmail_WithoutFallback(t *testing.T) {
	mockProvider := &MockAIProvider{
		shouldFail: true,
		error:      NewAuthenticationError(nil),
	}

	analyzer := NewEmailAnalyzerWithConfig(mockProvider, &AnalyzerConfig{
		Timeout:         5 * time.Second,
		RetryConfig:     &RetryConfig{MaxRetries: 1},
		FallbackEnabled: false,
		MaxConcurrent:   5,
	})

	email := createTestEmail()
	analysis, err := analyzer.AnalyzeEmail(email)

	if err == nil {
		t.Error("Expected error when fallback is disabled")
	}

	if analysis != nil {
		t.Error("Expected no analysis result when error occurred")
	}

	if aiErr, ok := err.(*AIError); ok {
		if aiErr.Type != "authentication_error" {
			t.Errorf("Expected authentication error, got %s", aiErr.Type)
		}
	} else {
		t.Error("Expected AIError type")
	}
}

func TestEmailAnalyzer_GetStats(t *testing.T) {
	mockProvider := &MockAIProvider{}
	analyzer := NewEmailAnalyzer(mockProvider)

	stats := analyzer.GetStats()

	if stats["enabled"] != true {
		t.Error("Expected enabled to be true")
	}

	if stats["config"] == nil {
		t.Error("Expected config to be present in stats")
	}

	if stats["retry_stats"] == nil {
		t.Error("Expected retry_stats to be present")
	}
}

func TestCalculateBasicSpamScore(t *testing.T) {
	analyzer := NewEmailAnalyzer(nil)

	tests := []struct {
		name     string
		email    *legacy.Message
		expected float64
	}{
		{
			name:     "no content",
			email:    &legacy.Message{},
			expected: 0,
		},
		{
			name: "spam keywords in subject",
			email: &legacy.Message{
				Content: &legacy.Content{
					Headers: map[string][]string{
						"Subject": {"FREE money now! Act NOW!"},
					},
					Body: "Regular content",
				},
			},
			expected: 20, // "free" + "act now"
		},
		{
			name: "excessive exclamation marks",
			email: &legacy.Message{
				Content: &legacy.Content{
					Headers: map[string][]string{
						"Subject": {"Hello"},
					},
					Body: "Hello!!!! This is urgent!!!!",
				},
			},
			expected: 10, // More than 3 exclamation marks
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.calculateBasicSpamScore(tt.email)
			if score != tt.expected {
				t.Errorf("Expected spam score %f, got %f", tt.expected, score)
			}
		})
	}
}

func TestDetectBasicIssues(t *testing.T) {
	analyzer := NewEmailAnalyzer(nil)

	email := &legacy.Message{
		Content: &legacy.Content{
			Headers: map[string][]string{
				// Missing Subject and From headers
			},
			Body: "Hi", // Very short content
		},
	}

	issues := analyzer.detectBasicIssues(email)

	expectedIssues := 3 // Missing subject, missing from, short content
	if len(issues) != expectedIssues {
		t.Errorf("Expected %d issues, got %d", expectedIssues, len(issues))
	}

	// Check for specific issues
	hasSubjectIssue := false
	hasFromIssue := false
	hasContentIssue := false

	for _, issue := range issues {
		switch issue.Description {
		case "Missing or empty subject line":
			hasSubjectIssue = true
		case "Missing From header":
			hasFromIssue = true
		case "Very short email content":
			hasContentIssue = true
		}
	}

	if !hasSubjectIssue {
		t.Error("Expected subject issue to be detected")
	}
	if !hasFromIssue {
		t.Error("Expected from header issue to be detected")
	}
	if !hasContentIssue {
		t.Error("Expected content length issue to be detected")
	}
}

func TestGetSpamLevel(t *testing.T) {
	analyzer := NewEmailAnalyzer(nil)

	tests := []struct {
		score    float64
		expected string
	}{
		{0, "none"},
		{10, "low"},
		{30, "medium"},
		{50, "medium"},
		{70, "high"},
		{100, "high"},
	}

	for _, tt := range tests {
		level := analyzer.getSpamLevel(tt.score)
		if level != tt.expected {
			t.Errorf("Score %f: expected level %s, got %s", tt.score, tt.expected, level)
		}
	}
}

// MockAIProvider for testing
type MockAIProvider struct {
	shouldFail bool
	error      error
	result     *Analysis
}

func (m *MockAIProvider) AnalyzeEmail(ctx context.Context, email *legacy.Message) (*Analysis, error) {
	if m.shouldFail {
		return nil, m.error
	}

	if m.result != nil {
		return m.result, nil
	}

	return &Analysis{
		EmailID:   string(email.ID),
		Timestamp: time.Now(),
		SpamRisk: SpamRisk{
			Score:   25,
			Level:   "low",
			Reasons: []string{"Mock analysis"},
		},
		Summary:    "Mock analysis completed",
		Confidence: 0.8,
	}, nil
}

// Helper function to create test emails
func createTestEmail() *legacy.Message {
    return &legacy.Message{
        ID: "test-message-1",
        From: &mail.Address{Address: "sender@test.com", Name: "Sender"},
        To:   []*mail.Address{{Address: "recipient@test.com", Name: "Recipient"}},
        Content: &legacy.Content{
            Headers: map[string][]string{
                "Subject": {"Test Subject"},
                "From":    {"sender@test.com"},
                "To":      {"recipient@test.com"},
            },
            Body: "This is a test email body with enough content to avoid triggering the short content warning.",
            Size: 100,
        },
        Created: time.Now(),
    }
}
