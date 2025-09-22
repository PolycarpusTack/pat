package analyzer

import (
	"fmt"
	"time"
)

// AI Analysis specific errors are created using the New*Error functions below

// AIError represents a detailed AI analysis error
type AIError struct {
	Type        string        `json:"type"`
	Message     string        `json:"message"`
	Code        string        `json:"code,omitempty"`
	Retryable   bool          `json:"retryable"`
	RetryAfter  time.Duration `json:"retry_after,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	OriginalErr error         `json:"-"`
}

func (e *AIError) Error() string {
	if e.OriginalErr != nil {
		return fmt.Sprintf("%s: %s (original: %v)", e.Type, e.Message, e.OriginalErr)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *AIError) Unwrap() error {
	return e.OriginalErr
}

func (e *AIError) IsRetryable() bool {
	return e.Retryable
}

func (e *AIError) GetRetryAfter() time.Duration {
	return e.RetryAfter
}

// NewAIError creates a new AI error
func NewAIError(errorType, message string, retryable bool, originalErr error) *AIError {
	return &AIError{
		Type:        errorType,
		Message:     message,
		Retryable:   retryable,
		OriginalErr: originalErr,
		Details:     make(map[string]interface{}),
	}
}

// NewRateLimitError creates a rate limit error with retry after duration
func NewRateLimitError(retryAfter time.Duration, originalErr error) *AIError {
	return &AIError{
		Type:        "rate_limit",
		Message:     "Rate limit exceeded. Please try again later.",
		Retryable:   true,
		RetryAfter:  retryAfter,
		OriginalErr: originalErr,
		Details:     make(map[string]interface{}),
	}
}

// NewQuotaError creates a quota exceeded error
func NewQuotaError(originalErr error) *AIError {
	return &AIError{
		Type:        "quota_exceeded",
		Message:     "API quota exceeded. Check your billing and usage limits.",
		Retryable:   false,
		OriginalErr: originalErr,
		Details:     make(map[string]interface{}),
	}
}

// NewNetworkError creates a network-related error
func NewNetworkError(message string, retryable bool, originalErr error) *AIError {
	return &AIError{
		Type:        "network_error",
		Message:     message,
		Retryable:   retryable,
		OriginalErr: originalErr,
		Details:     make(map[string]interface{}),
	}
}

// NewAuthenticationError creates an authentication error
func NewAuthenticationError(originalErr error) *AIError {
	return &AIError{
		Type:        "authentication_error",
		Message:     "Invalid API key or authentication failed",
		Retryable:   false,
		OriginalErr: originalErr,
		Details:     make(map[string]interface{}),
	}
}

// NewModelError creates a model-related error
func NewModelError(model string, originalErr error) *AIError {
	return &AIError{
		Type:        "model_error",
		Message:     fmt.Sprintf("Model '%s' not found or unavailable", model),
		Retryable:   false,
		OriginalErr: originalErr,
		Details: map[string]interface{}{
			"model": model,
		},
	}
}

// NewServiceError creates a service unavailable error
func NewServiceError(retryAfter time.Duration, originalErr error) *AIError {
	return &AIError{
		Type:        "service_error",
		Message:     "AI service temporarily unavailable",
		Retryable:   true,
		RetryAfter:  retryAfter,
		OriginalErr: originalErr,
		Details:     make(map[string]interface{}),
	}
}

// ClassifyHTTPError classifies HTTP errors into appropriate AI errors
func ClassifyHTTPError(statusCode int, body string, err error) *AIError {
	switch statusCode {
	case 401:
		return NewAuthenticationError(err)
	case 403:
		return NewQuotaError(err)
	case 404:
		return NewModelError("unknown", err)
	case 429:
		// Try to parse retry-after from response body or headers
		retryAfter := 60 * time.Second // Default retry after 1 minute
		return NewRateLimitError(retryAfter, err)
	case 500, 502, 503, 504:
		retryAfter := 30 * time.Second // Default retry after 30 seconds
		return NewServiceError(retryAfter, err)
	case 408:
		return NewNetworkError("Request timeout", true, err)
	default:
		if statusCode >= 400 && statusCode < 500 {
			return NewAIError("client_error", fmt.Sprintf("Client error: %d", statusCode), false, err)
		}
		if statusCode >= 500 {
			return NewAIError("server_error", fmt.Sprintf("Server error: %d", statusCode), true, err)
		}
		return NewAIError("unknown_error", fmt.Sprintf("Unknown HTTP error: %d", statusCode), false, err)
	}
}

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if aiErr, ok := err.(*AIError); ok {
		return aiErr.IsRetryable()
	}
	return false
}

// GetRetryAfter extracts retry after duration from an error
func GetRetryAfter(err error) time.Duration {
	if aiErr, ok := err.(*AIError); ok {
		return aiErr.GetRetryAfter()
	}
	return 0
}