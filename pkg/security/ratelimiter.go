// Package security implements fortress-grade security controls for Pat
// RAMPART DEFENSE SYSTEM - Multi-tier rate limiting with Redis backend
package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

// RampartLimiterConfig defines fortress rate limiting configuration
type RampartLimiterConfig struct {
	// Global fortress limits
	GlobalRequestsPerMinute    int           `json:"global_requests_per_minute"`
	GlobalBurstCapacity       int           `json:"global_burst_capacity"`
	
	// Per-IP rampart limits
	IPRequestsPerMinute       int           `json:"ip_requests_per_minute"`
	IPRequestsPerMinuteAuth   int           `json:"ip_requests_per_minute_auth"`
	IPBurstCapacity          int           `json:"ip_burst_capacity"`
	
	// Per-User fortress limits
	UserRequestsPerMinute     int           `json:"user_requests_per_minute"`
	UserBurstCapacity        int           `json:"user_burst_capacity"`
	
	// Endpoint-specific rampart controls
	EndpointLimits           map[string]int `json:"endpoint_limits"`
	
	// Redis backend configuration
	RedisURL                 string        `json:"redis_url"`
	KeyPrefix               string        `json:"key_prefix"`
	SlidingWindowSize       time.Duration `json:"sliding_window_size"`
	
	// Fortress emergency controls
	EmergencyMode           bool          `json:"emergency_mode"`
	EmergencyMultiplier     float64       `json:"emergency_multiplier"`
	
	// Adaptive controls
	SystemLoadThreshold     float64       `json:"system_load_threshold"`
	AdaptiveReduction       float64       `json:"adaptive_reduction"`
}

// DefaultRampartConfig returns fortress-grade default configuration
func DefaultRampartConfig() *RampartLimiterConfig {
	return &RampartLimiterConfig{
		GlobalRequestsPerMinute:   10000,
		GlobalBurstCapacity:      20000,
		IPRequestsPerMinute:      100,
		IPRequestsPerMinuteAuth:  1000,
		IPBurstCapacity:         200,
		UserRequestsPerMinute:    5000,
		UserBurstCapacity:       10000,
		EndpointLimits: map[string]int{
			"/api/v1/emails":        500,
			"/api/v1/smtp":         1000,
			"/api/v1/auth/login":    50,
			"/api/v1/upload":        20,
			"/api/graphql":          200,
		},
		RedisURL:               "redis://localhost:6379",
		KeyPrefix:             "fortress:rampart:",
		SlidingWindowSize:     time.Minute,
		EmergencyMode:         false,
		EmergencyMultiplier:   0.1,
		SystemLoadThreshold:   0.8,
		AdaptiveReduction:     0.7,
	}
}

// RampartRequest represents a request for rate limiting evaluation
type RampartRequest struct {
	IP        string            `json:"ip"`
	UserID    string            `json:"user_id,omitempty"`
	Endpoint  string            `json:"endpoint"`
	Headers   map[string]string `json:"headers"`
	Timestamp time.Time         `json:"timestamp"`
	IsAuth    bool              `json:"is_auth"`
}

// RampartResponse represents the fortress evaluation result
type RampartResponse struct {
	Allowed          bool          `json:"allowed"`
	RemainingRequests int          `json:"remaining_requests"`
	ResetTime        time.Time     `json:"reset_time"`
	RetryAfter       time.Duration `json:"retry_after"`
	LimitType        string        `json:"limit_type"`
	ThreatLevel      string        `json:"threat_level"`
	BlockReason      string        `json:"block_reason,omitempty"`
}

// TokenBucket implements fortress-grade token bucket algorithm
type TokenBucket struct {
	capacity     int
	tokens       int
	refillRate   int
	lastRefill   time.Time
	mutex        sync.RWMutex
}

// NewTokenBucket creates a new fortress token bucket
func NewTokenBucket(capacity, refillRate int) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Consume attempts to consume tokens from the bucket
func (tb *TokenBucket) Consume(tokens int) bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	
	// Refill tokens based on elapsed time
	if elapsed > 0 {
		tokensToAdd := int(elapsed.Minutes()) * tb.refillRate
		tb.tokens = min(tb.capacity, tb.tokens+tokensToAdd)
		tb.lastRefill = now
	}
	
	if tb.tokens >= tokens {
		tb.tokens -= tokens
		return true
	}
	
	return false
}

// RampartLimiter implements multi-tier fortress rate limiting
type RampartLimiter struct {
	config      *RampartLimiterConfig
	redis       *redis.Client
	logger      *zap.Logger
	buckets     sync.Map // In-memory buckets for performance
	stats       *RampartStats
}

// RampartStats tracks fortress security metrics
type RampartStats struct {
	TotalRequests      int64 `json:"total_requests"`
	BlockedRequests    int64 `json:"blocked_requests"`
	GlobalBlocks       int64 `json:"global_blocks"`
	IPBlocks          int64 `json:"ip_blocks"`
	UserBlocks        int64 `json:"user_blocks"`
	EndpointBlocks    int64 `json:"endpoint_blocks"`
	EmergencyBlocks   int64 `json:"emergency_blocks"`
	mutex             sync.RWMutex
}

// NewRampartLimiter creates a new fortress rate limiter
func NewRampartLimiter(config *RampartLimiterConfig, logger *zap.Logger) (*RampartLimiter, error) {
	if config == nil {
		config = DefaultRampartConfig()
	}
	
	// Initialize Redis client for distributed limiting
	redisOpts, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}
	
	redisClient := redis.NewClient(redisOpts)
	
	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Warn("Redis unavailable, using local rate limiting only", zap.Error(err))
	}
	
	return &RampartLimiter{
		config: config,
		redis:  redisClient,
		logger: logger,
		stats:  &RampartStats{},
	}, nil
}

// EvaluateRequest performs fortress-grade rate limit evaluation
func (rl *RampartLimiter) EvaluateRequest(req *RampartRequest) *RampartResponse {
	rl.stats.mutex.Lock()
	rl.stats.TotalRequests++
	rl.stats.mutex.Unlock()
	
	// Check global fortress limits first
	if !rl.checkGlobalLimit() {
		rl.stats.mutex.Lock()
		rl.stats.BlockedRequests++
		rl.stats.GlobalBlocks++
		rl.stats.mutex.Unlock()
		
		return &RampartResponse{
			Allowed:     false,
			LimitType:   "global",
			ThreatLevel: "HIGH",
			BlockReason: "Global fortress rate limit exceeded",
			RetryAfter:  time.Minute,
		}
	}
	
	// Check IP-based rampart limits
	if !rl.checkIPLimit(req.IP, req.IsAuth) {
		rl.stats.mutex.Lock()
		rl.stats.BlockedRequests++
		rl.stats.IPBlocks++
		rl.stats.mutex.Unlock()
		
		return &RampartResponse{
			Allowed:     false,
			LimitType:   "ip",
			ThreatLevel: "MEDIUM",
			BlockReason: "IP rate limit exceeded",
			RetryAfter:  time.Minute,
		}
	}
	
	// Check user-specific limits (if authenticated)
	if req.UserID != "" && !rl.checkUserLimit(req.UserID) {
		rl.stats.mutex.Lock()
		rl.stats.BlockedRequests++
		rl.stats.UserBlocks++
		rl.stats.mutex.Unlock()
		
		return &RampartResponse{
			Allowed:     false,
			LimitType:   "user",
			ThreatLevel: "MEDIUM",
			BlockReason: "User rate limit exceeded",
			RetryAfter:  time.Minute,
		}
	}
	
	// Check endpoint-specific rampart limits
	if !rl.checkEndpointLimit(req.Endpoint) {
		rl.stats.mutex.Lock()
		rl.stats.BlockedRequests++
		rl.stats.EndpointBlocks++
		rl.stats.mutex.Unlock()
		
		return &RampartResponse{
			Allowed:     false,
			LimitType:   "endpoint",
			ThreatLevel: "LOW",
			BlockReason: "Endpoint rate limit exceeded",
			RetryAfter:  time.Minute,
		}
	}
	
	// Check emergency fortress mode
	if rl.config.EmergencyMode && !rl.checkEmergencyLimits(req) {
		rl.stats.mutex.Lock()
		rl.stats.BlockedRequests++
		rl.stats.EmergencyBlocks++
		rl.stats.mutex.Unlock()
		
		return &RampartResponse{
			Allowed:     false,
			LimitType:   "emergency",
			ThreatLevel: "CRITICAL",
			BlockReason: "Emergency fortress mode active",
			RetryAfter:  time.Minute * 5,
		}
	}
	
	return &RampartResponse{
		Allowed:     true,
		LimitType:   "none",
		ThreatLevel: "SAFE",
	}
}

// checkGlobalLimit evaluates global fortress limits
func (rl *RampartLimiter) checkGlobalLimit() bool {
	key := rl.config.KeyPrefix + "global"
	return rl.checkRedisLimit(key, rl.config.GlobalRequestsPerMinute, rl.config.GlobalBurstCapacity)
}

// checkIPLimit evaluates IP-based rampart limits
func (rl *RampartLimiter) checkIPLimit(ip string, isAuth bool) bool {
	// Normalize IP address
	normalizedIP := rl.normalizeIP(ip)
	key := rl.config.KeyPrefix + "ip:" + normalizedIP
	
	limit := rl.config.IPRequestsPerMinute
	if isAuth {
		limit = rl.config.IPRequestsPerMinuteAuth
	}
	
	return rl.checkRedisLimit(key, limit, rl.config.IPBurstCapacity)
}

// checkUserLimit evaluates user-specific limits
func (rl *RampartLimiter) checkUserLimit(userID string) bool {
	key := rl.config.KeyPrefix + "user:" + userID
	return rl.checkRedisLimit(key, rl.config.UserRequestsPerMinute, rl.config.UserBurstCapacity)
}

// checkEndpointLimit evaluates endpoint-specific rampart limits
func (rl *RampartLimiter) checkEndpointLimit(endpoint string) bool {
	limit, exists := rl.config.EndpointLimits[endpoint]
	if !exists {
		return true // No specific limit for this endpoint
	}
	
	key := rl.config.KeyPrefix + "endpoint:" + endpoint
	return rl.checkRedisLimit(key, limit, limit*2) // 2x burst for endpoints
}

// checkEmergencyLimits evaluates emergency fortress restrictions
func (rl *RampartLimiter) checkEmergencyLimits(req *RampartRequest) bool {
	// Apply emergency multiplier to all limits
	limit := int(float64(rl.config.IPRequestsPerMinute) * rl.config.EmergencyMultiplier)
	key := rl.config.KeyPrefix + "emergency:ip:" + rl.normalizeIP(req.IP)
	
	return rl.checkRedisLimit(key, limit, limit)
}

// checkRedisLimit performs distributed rate limit check using Redis
func (rl *RampartLimiter) checkRedisLimit(key string, limit, burst int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	
	// Try Redis first for distributed limiting
	if rl.redis != nil {
		allowed, err := rl.checkRedisLimitLua(ctx, key, limit, burst)
		if err == nil {
			return allowed
		}
		// Fall back to local if Redis fails
		rl.logger.Debug("Redis rate limit check failed, using local fallback", 
			zap.String("key", key), zap.Error(err))
	}
	
	// Local fallback using token buckets
	return rl.checkLocalLimit(key, limit, burst)
}

// checkRedisLimitLua performs atomic rate limit check using Lua script
func (rl *RampartLimiter) checkRedisLimitLua(ctx context.Context, key string, limit, burst int) (bool, error) {
	// Lua script for atomic sliding window rate limiting
	script := `
		local key = KEYS[1]
		local window = tonumber(ARGV[1])
		local limit = tonumber(ARGV[2])
		local burst = tonumber(ARGV[3])
		local now = tonumber(ARGV[4])
		
		-- Clean old entries (sliding window)
		redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
		
		-- Count current requests
		local current = redis.call('ZCARD', key)
		
		-- Check if we can allow the request
		local allowed = 0
		if current < limit or current < burst then
			redis.call('ZADD', key, now, now)
			redis.call('EXPIRE', key, window)
			allowed = 1
		end
		
		return {allowed, current, limit - current}
	`
	
	now := time.Now().Unix()
	window := int64(rl.config.SlidingWindowSize.Seconds())
	
	result, err := rl.redis.Eval(ctx, script, []string{key}, window, limit, burst, now).Result()
	if err != nil {
		return false, err
	}
	
	values, ok := result.([]interface{})
	if !ok || len(values) < 1 {
		return false, fmt.Errorf("unexpected Redis response format")
	}
	
	allowed, ok := values[0].(int64)
	if !ok {
		return false, fmt.Errorf("unexpected allowed value type")
	}
	
	return allowed == 1, nil
}

// checkLocalLimit performs local rate limiting using token buckets
func (rl *RampartLimiter) checkLocalLimit(key string, limit, burst int) bool {
	bucketInterface, exists := rl.buckets.Load(key)
	if !exists {
		bucket := NewTokenBucket(burst, limit)
		rl.buckets.Store(key, bucket)
		bucketInterface = bucket
	}
	
	bucket, ok := bucketInterface.(*TokenBucket)
	if !ok {
		return false
	}
	
	return bucket.Consume(1)
}

// normalizeIP normalizes IP addresses for consistent rate limiting
func (rl *RampartLimiter) normalizeIP(ip string) string {
	// Parse IP to handle IPv6 and IPv4 consistently
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip // Return as-is if parsing fails
	}
	
	// For IPv6, use /64 subnet for rate limiting
	if parsed.To4() == nil {
		// IPv6 - use /64 subnet
		mask := net.CIDRMask(64, 128)
		network := parsed.Mask(mask)
		return network.String()
	}
	
	// For IPv4, use individual IP
	return parsed.String()
}

// GetStats returns current fortress security statistics
func (rl *RampartLimiter) GetStats() *RampartStats {
	rl.stats.mutex.RLock()
	defer rl.stats.mutex.RUnlock()
	
	// Return a copy to prevent race conditions
	return &RampartStats{
		TotalRequests:   rl.stats.TotalRequests,
		BlockedRequests: rl.stats.BlockedRequests,
		GlobalBlocks:    rl.stats.GlobalBlocks,
		IPBlocks:       rl.stats.IPBlocks,
		UserBlocks:     rl.stats.UserBlocks,
		EndpointBlocks: rl.stats.EndpointBlocks,
		EmergencyBlocks: rl.stats.EmergencyBlocks,
	}
}

// SetEmergencyMode activates fortress emergency protocols
func (rl *RampartLimiter) SetEmergencyMode(enabled bool) {
	rl.config.EmergencyMode = enabled
	rl.logger.Warn("Fortress emergency mode changed", zap.Bool("enabled", enabled))
}

// UpdateConfig dynamically updates fortress configuration
func (rl *RampartLimiter) UpdateConfig(config *RampartLimiterConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	rl.config = config
	rl.logger.Info("Fortress rampart configuration updated")
	
	return nil
}

// Close gracefully shuts down the fortress rate limiter
func (rl *RampartLimiter) Close() error {
	if rl.redis != nil {
		return rl.redis.Close()
	}
	return nil
}

// Helper function for min calculation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}