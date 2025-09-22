package analyzer

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CircuitBreakerState represents the state of the circuit breaker
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateHalfOpen
	StateOpen
)

// CircuitBreaker implements the circuit breaker pattern for AI services
type CircuitBreaker struct {
	mu             sync.RWMutex
	state          CircuitBreakerState
	failures       int
	requests       int
	lastFailTime   time.Time
	config         *CircuitBreakerConfig
	metrics        *CircuitBreakerMetrics
}

// CircuitBreakerConfig defines configuration for the circuit breaker
type CircuitBreakerConfig struct {
	MaxFailures     int           `json:"max_failures"`     // Number of failures before opening
	Timeout         time.Duration `json:"timeout"`          // Time to wait before trying half-open
	MaxRequests     int           `json:"max_requests"`     // Max requests in half-open state
	FailureRatio    float64       `json:"failure_ratio"`    // Ratio of failures to open (0.0-1.0)
	MinRequests     int           `json:"min_requests"`     // Min requests before considering ratio
}

// CircuitBreakerMetrics tracks circuit breaker statistics
type CircuitBreakerMetrics struct {
	mu                sync.RWMutex
	TotalRequests     int64     `json:"total_requests"`
	SuccessfulRequests int64    `json:"successful_requests"`
	FailedRequests    int64     `json:"failed_requests"`
	TimesClosed       int64     `json:"times_closed"`
	TimesHalfOpen     int64     `json:"times_half_open"`
	TimesOpen         int64     `json:"times_open"`
	LastStateChange   time.Time `json:"last_state_change"`
}

// DefaultCircuitBreakerConfig returns default circuit breaker configuration
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		MaxFailures:  5,
		Timeout:      30 * time.Second,
		MaxRequests:  3,
		FailureRatio: 0.6, // 60% failure rate triggers opening
		MinRequests:  10,  // Need at least 10 requests to consider ratio
	}
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	return &CircuitBreaker{
		state:   StateClosed,
		config:  config,
		metrics: &CircuitBreakerMetrics{LastStateChange: time.Now()},
	}
}

// Execute runs a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	// Check if we can proceed with the request
	if !cb.canProceed() {
		cb.recordMetric(false)
		return NewCircuitBreakerError(cb.state, "Circuit breaker is open")
	}

	// Execute the function
	err := fn(ctx)

	// Record the result
	success := err == nil
	cb.recordResult(success)
	cb.recordMetric(success)

	return err
}

// canProceed determines if a request can proceed based on circuit breaker state
func (cb *CircuitBreaker) canProceed() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if timeout has elapsed
		if time.Since(cb.lastFailTime) > cb.config.Timeout {
			cb.setState(StateHalfOpen)
			cb.requests = 0
			return true
		}
		return false
	case StateHalfOpen:
		// Allow limited requests in half-open state
		return cb.requests < cb.config.MaxRequests
	default:
		return false
	}
}

// recordResult updates circuit breaker state based on request result
func (cb *CircuitBreaker) recordResult(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.requests++

	if success {
		// Reset failure count on success
		cb.failures = 0

		// If in half-open state and we've had enough successful requests, close the circuit
		if cb.state == StateHalfOpen && cb.requests >= cb.config.MaxRequests {
			cb.setState(StateClosed)
			cb.requests = 0
		}
	} else {
		cb.failures++
		cb.lastFailTime = time.Now()

		// Determine if we should open the circuit
		shouldOpen := false

		switch cb.state {
		case StateClosed:
			// Open if we exceed max failures or failure ratio
			if cb.failures >= cb.config.MaxFailures {
				shouldOpen = true
			} else if cb.requests >= cb.config.MinRequests {
				failureRatio := float64(cb.failures) / float64(cb.requests)
				if failureRatio >= cb.config.FailureRatio {
					shouldOpen = true
				}
			}
		case StateHalfOpen:
			// Any failure in half-open state opens the circuit
			shouldOpen = true
		}

		if shouldOpen {
			cb.setState(StateOpen)
			cb.requests = 0
		}
	}
}

// setState updates the circuit breaker state and metrics
func (cb *CircuitBreaker) setState(newState CircuitBreakerState) {
	if cb.state != newState {
		cb.state = newState
		cb.metrics.mu.Lock()
		cb.metrics.LastStateChange = time.Now()
		switch newState {
		case StateClosed:
			cb.metrics.TimesClosed++
		case StateHalfOpen:
			cb.metrics.TimesHalfOpen++
		case StateOpen:
			cb.metrics.TimesOpen++
		}
		cb.metrics.mu.Unlock()
	}
}

// recordMetric updates circuit breaker metrics
func (cb *CircuitBreaker) recordMetric(success bool) {
	cb.metrics.mu.Lock()
	defer cb.metrics.mu.Unlock()

	cb.metrics.TotalRequests++
	if success {
		cb.metrics.SuccessfulRequests++
	} else {
		cb.metrics.FailedRequests++
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetMetrics returns current circuit breaker metrics
func (cb *CircuitBreaker) GetMetrics() CircuitBreakerMetrics {
	cb.metrics.mu.RLock()
	defer cb.metrics.mu.RUnlock()
	return *cb.metrics
}

// IsOpen returns true if the circuit breaker is open
func (cb *CircuitBreaker) IsOpen() bool {
	return cb.GetState() == StateOpen
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.setState(StateClosed)
	cb.failures = 0
	cb.requests = 0
}

// CircuitBreakerError represents a circuit breaker error
type CircuitBreakerError struct {
	State   CircuitBreakerState
	Message string
}

func (e *CircuitBreakerError) Error() string {
	stateStr := "unknown"
	switch e.State {
	case StateClosed:
		stateStr = "closed"
	case StateHalfOpen:
		stateStr = "half-open"
	case StateOpen:
		stateStr = "open"
	}
	return fmt.Sprintf("circuit breaker %s: %s", stateStr, e.Message)
}

// NewCircuitBreakerError creates a new circuit breaker error
func NewCircuitBreakerError(state CircuitBreakerState, message string) *CircuitBreakerError {
	return &CircuitBreakerError{
		State:   state,
		Message: message,
	}
}

// String returns a string representation of the circuit breaker state
func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return "unknown"
	}
}