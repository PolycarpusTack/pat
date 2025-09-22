package analyzer

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// RetryConfig defines configuration for retry logic
type RetryConfig struct {
	MaxRetries      int           `json:"max_retries"`
	InitialDelay    time.Duration `json:"initial_delay"`
	MaxDelay        time.Duration `json:"max_delay"`
	BackoffFactor   float64       `json:"backoff_factor"`
	EnableJitter    bool          `json:"enable_jitter"`
	RetryableErrors []string      `json:"retryable_errors"`
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:    3,
		InitialDelay:  1 * time.Second,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
		EnableJitter:  true,
		RetryableErrors: []string{
			"rate_limit",
			"service_error",
			"network_error",
			"server_error",
		},
	}
}

// RetryableFunction represents a function that can be retried
type RetryableFunction func(ctx context.Context) error

// Retryer handles retry logic for AI operations
type Retryer struct {
	config *RetryConfig
	random *rand.Rand
}

// NewRetryer creates a new retryer with the given configuration
func NewRetryer(config *RetryConfig) *Retryer {
	if config == nil {
		config = DefaultRetryConfig()
	}

	return &Retryer{
		config: config,
		random: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Execute executes a function with retry logic
func (r *Retryer) Execute(ctx context.Context, fn RetryableFunction) error {
	var lastErr error

	for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
		// Execute the function
		err := fn(ctx)
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Check if this is the last attempt
		if attempt == r.config.MaxRetries {
			break
		}

		// Check if the error is retryable
		if !r.isRetryableError(err) {
			return err // Non-retryable error, fail immediately
		}

		// Calculate delay for next retry
		delay := r.calculateDelay(attempt, err)

		// Wait before retrying (with context cancellation support)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return lastErr
}

// isRetryableError checks if an error should be retried
func (r *Retryer) isRetryableError(err error) bool {
	aiErr, ok := err.(*AIError)
	if !ok {
		return false // Unknown error type, don't retry
	}

	// Check if this error type is in the retryable list
	for _, retryableType := range r.config.RetryableErrors {
		if aiErr.Type == retryableType {
			return aiErr.IsRetryable()
		}
	}

	return false
}

// calculateDelay calculates the delay before the next retry attempt
func (r *Retryer) calculateDelay(attempt int, err error) time.Duration {
	// Check if the error specifies a retry-after duration
	if aiErr, ok := err.(*AIError); ok && aiErr.RetryAfter > 0 {
		return r.addJitter(aiErr.RetryAfter)
	}

	// Calculate exponential backoff delay
	delay := float64(r.config.InitialDelay) * math.Pow(r.config.BackoffFactor, float64(attempt))

	// Cap the delay at MaxDelay
	if delay > float64(r.config.MaxDelay) {
		delay = float64(r.config.MaxDelay)
	}

	duration := time.Duration(delay)

	// Add jitter if enabled
	if r.config.EnableJitter {
		duration = r.addJitter(duration)
	}

	return duration
}

// addJitter adds random jitter to a duration to avoid thundering herd
func (r *Retryer) addJitter(duration time.Duration) time.Duration {
	if !r.config.EnableJitter {
		return duration
	}

	// Add up to 25% random jitter
	maxJitter := float64(duration) * 0.25
	jitter := r.random.Float64() * maxJitter

	return duration + time.Duration(jitter)
}

// WithRetry is a convenience function that creates a retryer and executes a function
func WithRetry(ctx context.Context, config *RetryConfig, fn RetryableFunction) error {
	retryer := NewRetryer(config)
	return retryer.Execute(ctx, fn)
}

// RetryStats tracks statistics about retry attempts
type RetryStats struct {
	TotalAttempts    int64         `json:"total_attempts"`
	SuccessfulRetries int64         `json:"successful_retries"`
	FailedRetries    int64         `json:"failed_retries"`
	AverageAttempts  float64       `json:"average_attempts"`
	TotalDelay       time.Duration `json:"total_delay"`
}

// RetryerWithStats extends Retryer with statistics tracking
type RetryerWithStats struct {
	*Retryer
	stats *RetryStats
}

// NewRetryerWithStats creates a new retryer with statistics tracking
func NewRetryerWithStats(config *RetryConfig) *RetryerWithStats {
	return &RetryerWithStats{
		Retryer: NewRetryer(config),
		stats:   &RetryStats{},
	}
}

// Execute executes a function with retry logic and tracks statistics
func (r *RetryerWithStats) Execute(ctx context.Context, fn RetryableFunction) error {
	startTime := time.Now()
	attempts := int64(0)

	err := r.Retryer.Execute(ctx, func(ctx context.Context) error {
		attempts++
		return fn(ctx)
	})

	// Update statistics
	r.stats.TotalAttempts += attempts
	r.stats.TotalDelay += time.Since(startTime)

	if err == nil {
		r.stats.SuccessfulRetries++
	} else {
		r.stats.FailedRetries++
	}

	// Calculate average attempts
	totalOperations := r.stats.SuccessfulRetries + r.stats.FailedRetries
	if totalOperations > 0 {
		r.stats.AverageAttempts = float64(r.stats.TotalAttempts) / float64(totalOperations)
	}

	return err
}

// GetStats returns the current retry statistics
func (r *RetryerWithStats) GetStats() *RetryStats {
	return r.stats
}

// ResetStats resets the retry statistics
func (r *RetryerWithStats) ResetStats() {
	r.stats = &RetryStats{}
}