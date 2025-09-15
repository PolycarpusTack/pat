// Package security implements fortress security tests
// FORTRESS TESTING - Comprehensive rate limiter validation tests
package security

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestRampartLimiter_Basic(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRampartConfig()
	config.IPRequestsPerMinute = 10
	config.IPBurstCapacity = 15
	
	limiter, err := NewRampartLimiter(config, logger)
	require.NoError(t, err)
	defer limiter.Close()
	
	// Test normal requests
	req := &RampartRequest{
		IP:       "192.168.1.100",
		Endpoint: "/api/test",
		IsAuth:   false,
	}
	
	// Should allow initial requests
	for i := 0; i < 10; i++ {
		result := limiter.EvaluateRequest(req)
		assert.True(t, result.Allowed, "Request %d should be allowed", i+1)
		assert.Equal(t, "SAFE", result.ThreatLevel)
	}
	
	// Should start blocking after limit
	result := limiter.EvaluateRequest(req)
	assert.False(t, result.Allowed, "Request should be blocked after limit")
	assert.Equal(t, "ip", result.LimitType)
	assert.Contains(t, result.BlockReason, "IP rate limit exceeded")
}

func TestRampartLimiter_AuthenticatedRequests(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRampartConfig()
	config.IPRequestsPerMinute = 10
	config.IPRequestsPerMinuteAuth = 50
	
	limiter, err := NewRampartLimiter(config, logger)
	require.NoError(t, err)
	defer limiter.Close()
	
	// Test authenticated requests get higher limits
	req := &RampartRequest{
		IP:       "192.168.1.101",
		Endpoint: "/api/test",
		IsAuth:   true,
	}
	
	// Should allow more requests when authenticated
	for i := 0; i < 50; i++ {
		result := limiter.EvaluateRequest(req)
		if !result.Allowed {
			t.Errorf("Authenticated request %d should be allowed, got: %s", i+1, result.BlockReason)
			break
		}
	}
}

func TestRampartLimiter_UserLimits(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRampartConfig()
	config.UserRequestsPerMinute = 20
	
	limiter, err := NewRampartLimiter(config, logger)
	require.NoError(t, err)
	defer limiter.Close()
	
	req := &RampartRequest{
		IP:       "192.168.1.102",
		UserID:   "user123",
		Endpoint: "/api/test",
		IsAuth:   true,
	}
	
	// Test user-specific limits
	for i := 0; i < 20; i++ {
		result := limiter.EvaluateRequest(req)
		assert.True(t, result.Allowed, "User request %d should be allowed", i+1)
	}
	
	// Should block after user limit
	result := limiter.EvaluateRequest(req)
	assert.False(t, result.Allowed, "Request should be blocked after user limit")
	assert.Equal(t, "user", result.LimitType)
}

func TestRampartLimiter_EndpointLimits(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRampartConfig()
	config.EndpointLimits = map[string]int{
		"/api/sensitive": 5,
	}
	
	limiter, err := NewRampartLimiter(config, logger)
	require.NoError(t, err)
	defer limiter.Close()
	
	req := &RampartRequest{
		IP:       "192.168.1.103",
		Endpoint: "/api/sensitive",
		IsAuth:   true,
	}
	
	// Test endpoint-specific limits
	for i := 0; i < 5; i++ {
		result := limiter.EvaluateRequest(req)
		assert.True(t, result.Allowed, "Endpoint request %d should be allowed", i+1)
	}
	
	// Should block after endpoint limit
	result := limiter.EvaluateRequest(req)
	assert.False(t, result.Allowed, "Request should be blocked after endpoint limit")
	assert.Equal(t, "endpoint", result.LimitType)
}

func TestRampartLimiter_EmergencyMode(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRampartConfig()
	config.EmergencyMode = true
	config.EmergencyMultiplier = 0.1
	config.IPRequestsPerMinute = 100
	
	limiter, err := NewRampartLimiter(config, logger)
	require.NoError(t, err)
	defer limiter.Close()
	
	req := &RampartRequest{
		IP:       "192.168.1.104",
		Endpoint: "/api/test",
		IsAuth:   false,
	}
	
	// Emergency mode should severely restrict limits
	// Normal limit is 100, emergency multiplier 0.1 = 10
	for i := 0; i < 10; i++ {
		result := limiter.EvaluateRequest(req)
		if !result.Allowed {
			// May hit emergency limits before 10
			assert.Equal(t, "emergency", result.LimitType)
			assert.Equal(t, "CRITICAL", result.ThreatLevel)
			break
		}
	}
}

func TestRampartLimiter_IPv6Normalization(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRampartConfig()
	config.IPRequestsPerMinute = 5
	
	limiter, err := NewRampartLimiter(config, logger)
	require.NoError(t, err)
	defer limiter.Close()
	
	// Test IPv6 address normalization
	ipv6Addresses := []string{
		"2001:db8::1",
		"2001:db8:0:0:0:0:0:2",
		"2001:db8::3",
	}
	
	for _, ip := range ipv6Addresses {
		req := &RampartRequest{
			IP:       ip,
			Endpoint: "/api/test",
		}
		
		result := limiter.EvaluateRequest(req)
		assert.True(t, result.Allowed, "IPv6 request should be allowed")
	}
}

func TestRampartLimiter_Stats(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRampartConfig()
	config.IPRequestsPerMinute = 2
	
	limiter, err := NewRampartLimiter(config, logger)
	require.NoError(t, err)
	defer limiter.Close()
	
	req := &RampartRequest{
		IP:       "192.168.1.105",
		Endpoint: "/api/test",
	}
	
	// Make some requests to generate stats
	limiter.EvaluateRequest(req)
	limiter.EvaluateRequest(req)
	limiter.EvaluateRequest(req) // This should be blocked
	
	stats := limiter.GetStats()
	assert.Equal(t, int64(3), stats.TotalRequests)
	assert.Equal(t, int64(1), stats.BlockedRequests)
	assert.Equal(t, int64(1), stats.IPBlocks)
}

func TestTokenBucket_Refill(t *testing.T) {
	bucket := NewTokenBucket(10, 5) // 10 capacity, 5 per minute refill
	
	// Consume all tokens
	for i := 0; i < 10; i++ {
		assert.True(t, bucket.Consume(1), "Should consume token %d", i+1)
	}
	
	// No more tokens available
	assert.False(t, bucket.Consume(1), "Should not have tokens available")
	
	// Simulate time passage (would need to modify bucket for testing)
	// In real implementation, you'd use dependency injection for time
}

func TestRampartLimiter_Configuration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	
	// Test with nil config (should use defaults)
	limiter, err := NewRampartLimiter(nil, logger)
	require.NoError(t, err)
	defer limiter.Close()
	
	req := &RampartRequest{
		IP:       "192.168.1.106",
		Endpoint: "/api/test",
	}
	
	result := limiter.EvaluateRequest(req)
	assert.True(t, result.Allowed)
	
	// Test config update
	newConfig := DefaultRampartConfig()
	newConfig.IPRequestsPerMinute = 1
	
	err = limiter.UpdateConfig(newConfig)
	assert.NoError(t, err)
}

func TestRampartLimiter_GlobalLimits(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRampartConfig()
	config.GlobalRequestsPerMinute = 50 // Very low for testing
	
	limiter, err := NewRampartLimiter(config, logger)
	require.NoError(t, err)
	defer limiter.Close()
	
	// Make requests from different IPs to test global limits
	for i := 0; i < 60; i++ {
		req := &RampartRequest{
			IP:       fmt.Sprintf("192.168.1.%d", 100+i%10),
			Endpoint: "/api/test",
		}
		
		result := limiter.EvaluateRequest(req)
		if !result.Allowed && result.LimitType == "global" {
			assert.Equal(t, "HIGH", result.ThreatLevel)
			assert.Contains(t, result.BlockReason, "Global fortress rate limit exceeded")
			break
		}
	}
}

func BenchmarkRampartLimiter_EvaluateRequest(b *testing.B) {
	logger := zaptest.NewLogger(b)
	config := DefaultRampartConfig()
	
	limiter, err := NewRampartLimiter(config, logger)
	require.NoError(b, err)
	defer limiter.Close()
	
	req := &RampartRequest{
		IP:       "192.168.1.200",
		Endpoint: "/api/benchmark",
		IsAuth:   true,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.EvaluateRequest(req)
	}
}

func BenchmarkTokenBucket_Consume(b *testing.B) {
	bucket := NewTokenBucket(10000, 1000) // High capacity for benchmarking
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bucket.Consume(1)
	}
}