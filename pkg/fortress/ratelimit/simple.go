package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// SimpleRateLimiter provides basic per-IP request counting for email testing
type SimpleRateLimiter struct {
	requests map[string]*requestCounter
	mu       sync.RWMutex
	maxPerIP int
	cleanup  *time.Ticker
	stop     chan struct{}
}

type requestCounter struct {
	count     int
	resetTime time.Time
}

// NewSimpleRateLimiter creates a basic rate limiter (good enough for email testing)
func NewSimpleRateLimiter(maxPerIP int) *SimpleRateLimiter {
	rl := &SimpleRateLimiter{
		requests: make(map[string]*requestCounter),
		maxPerIP: maxPerIP,
		cleanup:  time.NewTicker(time.Minute),
		stop:     make(chan struct{}),
	}

	// Simple cleanup every minute
	go func() {
		for {
			select {
			case <-rl.cleanup.C:
				rl.cleanupOld()
			case <-rl.stop:
				return
			}
		}
	}()

	return rl
}

// Allow checks if IP can make request (simple: max requests per minute)
func (rl *SimpleRateLimiter) Allow(remoteAddr string) bool {
	if rl.maxPerIP <= 0 {
		return true
	}

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return true // Allow if can't parse
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, exists := rl.requests[ip]

	if !exists || now.After(counter.resetTime) {
		// New IP or time window reset
		rl.requests[ip] = &requestCounter{
			count:     1,
			resetTime: now.Add(time.Minute),
		}
		return true
	}

	if counter.count < rl.maxPerIP {
		counter.count++
		return true
	}

	return false // Rate limited
}

// GetStats returns basic stats
func (rl *SimpleRateLimiter) GetStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return map[string]interface{}{
		"enabled":    rl.maxPerIP > 0,
		"max_per_ip": rl.maxPerIP,
		"window":     "1 minute",
		"active_ips": len(rl.requests),
	}
}

// Close stops the rate limiter
func (rl *SimpleRateLimiter) Close() {
	close(rl.stop)
	rl.cleanup.Stop()
}

// cleanupOld removes old entries (simple cleanup)
func (rl *SimpleRateLimiter) cleanupOld() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, counter := range rl.requests {
		if now.After(counter.resetTime.Add(time.Minute)) {
			delete(rl.requests, ip)
		}
	}
}

// HTTPMiddleware creates simple HTTP rate limiting middleware
func (rl *SimpleRateLimiter) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.Allow(r.RemoteAddr) {
				w.Header().Set("X-RateLimit-Limit", "10")
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Rate limit exceeded - max 10 requests per minute", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}