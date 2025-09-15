package external_systems

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/pat-fortress/tests/integration/testdata/fixtures"
	"github.com/pat-fortress/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// FortressRedisIntegrationSuite tests Redis integration functionality
type FortressRedisIntegrationSuite struct {
	suite.Suite
	testUtils      *utils.FortressTestUtils
	configFixtures *fixtures.ConfigFixtures
	emailFixtures  *fixtures.EmailFixtures
	
	// Redis connections and services
	redisClient  *redis.Client
	rampart      interfaces.Rampart
	foundation   interfaces.Foundation
	
	// Test configuration
	ctx     context.Context
	cancel  context.CancelFunc
	config  *interfaces.RedisConfig
	testPrefix string
}

// SetupSuite initializes the Redis integration test environment
func (s *FortressRedisIntegrationSuite) SetupSuite() {
	s.testUtils = utils.NewFortressTestUtils(s.T())
	s.configFixtures = fixtures.NewConfigFixtures()
	s.emailFixtures = fixtures.NewEmailFixtures()
	s.testPrefix = "fortress:test:integration:"
	
	s.ctx, s.cancel = context.WithTimeout(context.Background(), time.Minute*10)
	
	// Get Redis configuration
	s.config = s.configFixtures.TestRedisConfig()
	s.config.Prefix = s.testPrefix
	
	// Override with environment variables if present
	s.overrideConfigFromEnv()
	
	// Initialize Redis connection
	s.initializeRedisConnection()
	
	// Initialize services that use Redis
	s.rampart = s.createRampartService()
	s.foundation = s.createFoundationService()
	
	// Start services
	err := s.rampart.Start(s.ctx)
	require.NoError(s.T(), err)
	
	err = s.foundation.Start(s.ctx)
	require.NoError(s.T(), err)
}

// TearDownSuite cleans up the Redis integration test environment
func (s *FortressRedisIntegrationSuite) TearDownSuite() {
	// Clean up test data
	s.cleanupTestData()
	
	// Stop services
	if s.rampart != nil {
		s.rampart.Stop(s.ctx)
	}
	if s.foundation != nil {
		s.foundation.Stop(s.ctx)
	}
	
	// Close Redis connection
	if s.redisClient != nil {
		s.redisClient.Close()
	}
	
	if s.cancel != nil {
		s.cancel()
	}
}

// SetupTest prepares each test case
func (s *FortressRedisIntegrationSuite) SetupTest() {
	// Clean test keys before each test
	s.cleanupTestKeys()
}

// TestRedisConnection tests basic Redis connectivity
func (s *FortressRedisIntegrationSuite) TestRedisConnection() {
	s.T().Run("Redis_Connectivity", func(t *testing.T) {
		// Test direct Redis connection
		pong, err := s.redisClient.Ping(s.ctx).Result()
		require.NoError(t, err)
		assert.Equal(t, "PONG", pong)
		
		// Test through Foundation service cache
		testKey := s.testPrefix + "connectivity_test"
		testValue := "connection_test_value"
		
		err = s.foundation.CacheSet(s.ctx, testKey, testValue, nil)
		require.NoError(t, err)
		
		retrievedValue, err := s.foundation.CacheGet(s.ctx, testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, retrievedValue)
	})
}

// TestCacheOperations tests Redis caching functionality
func (s *FortressRedisIntegrationSuite) TestCacheOperations() {
	s.T().Run("Basic_Cache_Operations", func(t *testing.T) {
		// Test string operations
		key := s.testPrefix + "string_test"
		value := "test_string_value"
		
		err := s.foundation.CacheSet(s.ctx, key, value, nil)
		require.NoError(t, err)
		
		retrievedValue, err := s.foundation.CacheGet(s.ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrievedValue)
		
		// Test with TTL
		ttlKey := s.testPrefix + "ttl_test"
		ttlValue := "test_ttl_value"
		ttl := time.Second * 2
		
		err = s.foundation.CacheSet(s.ctx, ttlKey, ttlValue, &ttl)
		require.NoError(t, err)
		
		// Value should be available immediately
		retrievedValue, err = s.foundation.CacheGet(s.ctx, ttlKey)
		require.NoError(t, err)
		assert.Equal(t, ttlValue, retrievedValue)
		
		// Wait for expiration
		time.Sleep(ttl + time.Millisecond*100)
		
		_, err = s.foundation.CacheGet(s.ctx, ttlKey)
		assert.Error(t, err, "Key should have expired")
	})
	
	s.T().Run("Complex_Data_Caching", func(t *testing.T) {
		// Test caching complex email data
		email := s.emailFixtures.HTMLEmail()
		emailKey := s.testPrefix + "email:" + email.ID
		
		// Serialize email to JSON for caching
		emailData, err := json.Marshal(email)
		require.NoError(t, err)
		
		err = s.foundation.CacheSet(s.ctx, emailKey, string(emailData), nil)
		require.NoError(t, err)
		
		retrievedData, err := s.foundation.CacheGet(s.ctx, emailKey)
		require.NoError(t, err)
		
		var retrievedEmail interfaces.Email
		err = json.Unmarshal([]byte(retrievedData.(string)), &retrievedEmail)
		require.NoError(t, err)
		
		assert.Equal(t, email.ID, retrievedEmail.ID)
		assert.Equal(t, email.Subject, retrievedEmail.Subject)
		assert.Equal(t, email.From, retrievedEmail.From)
	})
}

// TestRateLimiting tests Redis-based rate limiting
func (s *FortressRedisIntegrationSuite) TestRateLimiting() {
	s.T().Run("Rate_Limit_Basic", func(t *testing.T) {
		rateLimit := &interfaces.RateLimit{
			RequestsPerSecond: 5,
			BurstSize:         3,
			WindowDuration:    time.Second,
		}
		
		testKey := "test_client_" + fmt.Sprintf("%d", time.Now().Unix())
		
		// Test allowed requests within limit
		for i := 0; i < 5; i++ {
			result, err := s.rampart.CheckRateLimit(s.ctx, testKey, rateLimit)
			require.NoError(t, err)
			assert.True(t, result.Allowed, "Request %d should be allowed", i+1)
			assert.Greater(t, result.Remaining, int64(0), "Should have remaining requests")
		}
		
		// Test rate limiting kicks in
		result, err := s.rampart.CheckRateLimit(s.ctx, testKey, rateLimit)
		require.NoError(t, err)
		assert.False(t, result.Allowed, "Request should be rate limited")
		assert.Equal(t, int64(0), result.Remaining)
	})
	
	s.T().Run("Rate_Limit_Window_Reset", func(t *testing.T) {
		rateLimit := &interfaces.RateLimit{
			RequestsPerSecond: 2,
			BurstSize:         2,
			WindowDuration:    time.Second,
		}
		
		testKey := "test_reset_" + fmt.Sprintf("%d", time.Now().Unix())
		
		// Exhaust rate limit
		for i := 0; i < 2; i++ {
			result, err := s.rampart.CheckRateLimit(s.ctx, testKey, rateLimit)
			require.NoError(t, err)
			assert.True(t, result.Allowed)
		}
		
		// Should be rate limited
		result, err := s.rampart.CheckRateLimit(s.ctx, testKey, rateLimit)
		require.NoError(t, err)
		assert.False(t, result.Allowed)
		
		// Wait for window to reset
		time.Sleep(time.Second + time.Millisecond*100)
		
		// Should be allowed again
		result, err = s.rampart.CheckRateLimit(s.ctx, testKey, rateLimit)
		require.NoError(t, err)
		assert.True(t, result.Allowed, "Should be allowed after window reset")
	})
}

// TestSessionStorage tests Redis-based session management
func (s *FortressRedisIntegrationSuite) TestSessionStorage() {
	s.T().Run("Session_Management", func(t *testing.T) {
		sessionID := "test_session_" + fmt.Sprintf("%d", time.Now().Unix())
		sessionData := map[string]interface{}{
			"user_id":   "test_user_123",
			"username":  "testuser",
			"role":      "admin",
			"login_at":  time.Now().Unix(),
			"ip_address": "127.0.0.1",
		}
		
		// Store session data
		sessionKey := s.testPrefix + "session:" + sessionID
		sessionJSON, err := json.Marshal(sessionData)
		require.NoError(t, err)
		
		ttl := time.Hour * 24 // 24 hour session
		err = s.foundation.CacheSet(s.ctx, sessionKey, string(sessionJSON), &ttl)
		require.NoError(t, err)
		
		// Retrieve session data
		retrievedData, err := s.foundation.CacheGet(s.ctx, sessionKey)
		require.NoError(t, err)
		
		var retrievedSession map[string]interface{}
		err = json.Unmarshal([]byte(retrievedData.(string)), &retrievedSession)
		require.NoError(t, err)
		
		assert.Equal(t, sessionData["user_id"], retrievedSession["user_id"])
		assert.Equal(t, sessionData["username"], retrievedSession["username"])
		assert.Equal(t, sessionData["role"], retrievedSession["role"])
		
		// Test session deletion
		err = s.foundation.CacheDelete(s.ctx, sessionKey)
		require.NoError(t, err)
		
		_, err = s.foundation.CacheGet(s.ctx, sessionKey)
		assert.Error(t, err, "Session should be deleted")
	})
}

// TestEmailMetadataCache tests caching email metadata for performance
func (s *FortressRedisIntegrationSuite) TestEmailMetadataCache() {
	s.T().Run("Email_Metadata_Caching", func(t *testing.T) {
		emails := s.emailFixtures.EmailsWithDifferentSizes()
		
		// Cache email metadata
		for _, email := range emails {
			metadata := map[string]interface{}{
				"id":           email.ID,
				"from":         email.From,
				"to":           email.To,
				"subject":      email.Subject,
				"received_at":  email.ReceivedAt,
				"size":         email.Size,
				"has_attachments": len(email.Attachments) > 0,
			}
			
			metadataKey := s.testPrefix + "email_meta:" + email.ID
			metadataJSON, err := json.Marshal(metadata)
			require.NoError(t, err)
			
			ttl := time.Hour // Cache for 1 hour
			err = s.foundation.CacheSet(s.ctx, metadataKey, string(metadataJSON), &ttl)
			require.NoError(t, err)
		}
		
		// Verify cached metadata
		for _, email := range emails {
			metadataKey := s.testPrefix + "email_meta:" + email.ID
			
			retrievedData, err := s.foundation.CacheGet(s.ctx, metadataKey)
			require.NoError(t, err)
			
			var metadata map[string]interface{}
			err = json.Unmarshal([]byte(retrievedData.(string)), &metadata)
			require.NoError(t, err)
			
			assert.Equal(t, email.ID, metadata["id"])
			assert.Equal(t, email.From, metadata["from"])
			assert.Equal(t, email.Subject, metadata["subject"])
		}
		
		// Test bulk cleanup
		pattern := s.testPrefix + "email_meta:*"
		err := s.foundation.CacheClear(s.ctx, pattern)
		require.NoError(t, err)
		
		// Verify cleanup worked
		for _, email := range emails {
			metadataKey := s.testPrefix + "email_meta:" + email.ID
			_, err := s.foundation.CacheGet(s.ctx, metadataKey)
			assert.Error(t, err, "Metadata should be cleared")
		}
	})
}

// TestRedisPerformance tests Redis performance under load
func (s *FortressRedisIntegrationSuite) TestRedisPerformance() {
	s.T().Run("Cache_Performance", func(t *testing.T) {
		operationCount := 1000
		keyPrefix := s.testPrefix + "perf_test:"
		
		// Test write performance
		startTime := time.Now()
		
		for i := 0; i < operationCount; i++ {
			key := fmt.Sprintf("%s%d", keyPrefix, i)
			value := fmt.Sprintf("test_value_%d", i)
			
			err := s.foundation.CacheSet(s.ctx, key, value, nil)
			require.NoError(t, err)
		}
		
		writeTime := time.Since(startTime)
		writeRate := float64(operationCount) / writeTime.Seconds()
		
		t.Logf("Redis write performance: %d operations in %v (%.2f ops/sec)",
			operationCount, writeTime, writeRate)
		
		assert.Greater(t, writeRate, float64(1000),
			"Should achieve at least 1000 writes/sec")
		
		// Test read performance
		startTime = time.Now()
		
		for i := 0; i < operationCount; i++ {
			key := fmt.Sprintf("%s%d", keyPrefix, i)
			
			_, err := s.foundation.CacheGet(s.ctx, key)
			require.NoError(t, err)
		}
		
		readTime := time.Since(startTime)
		readRate := float64(operationCount) / readTime.Seconds()
		
		t.Logf("Redis read performance: %d operations in %v (%.2f ops/sec)",
			operationCount, readTime, readRate)
		
		assert.Greater(t, readRate, float64(2000),
			"Should achieve at least 2000 reads/sec")
	})
}

// TestRedisConcurrency tests concurrent Redis access
func (s *FortressRedisIntegrationSuite) TestRedisConcurrency() {
	s.T().Run("Concurrent_Operations", func(t *testing.T) {
		concurrency := 50
		operationsPerWorker := 20
		keyPrefix := s.testPrefix + "concurrent:"
		
		// Test concurrent cache operations
		s.testUtils.FortressTestConcurrentExecution(concurrency, func(workerID int) {
			for i := 0; i < operationsPerWorker; i++ {
				key := fmt.Sprintf("%s%d_%d", keyPrefix, workerID, i)
				value := fmt.Sprintf("worker_%d_value_%d", workerID, i)
				
				// Write
				err := s.foundation.CacheSet(s.ctx, key, value, nil)
				assert.NoError(s.T(), err, "Worker %d should write successfully", workerID)
				
				// Read back
				retrievedValue, err := s.foundation.CacheGet(s.ctx, key)
				assert.NoError(s.T(), err, "Worker %d should read successfully", workerID)
				assert.Equal(s.T(), value, retrievedValue, "Worker %d should get correct value", workerID)
			}
		})
		
		// Verify all operations completed successfully
		totalOperations := concurrency * operationsPerWorker
		
		// Count existing keys
		keys, err := s.redisClient.Keys(s.ctx, keyPrefix+"*").Result()
		require.NoError(t, err)
		
		assert.Equal(t, totalOperations, len(keys),
			"Should have %d keys from concurrent operations", totalOperations)
	})
}

// TestRedisFailover tests Redis connection resilience
func (s *FortressRedisIntegrationSuite) TestRedisFailover() {
	s.T().Run("Connection_Resilience", func(t *testing.T) {
		// Test operations with short timeout
		timeoutCtx, cancel := context.WithTimeout(s.ctx, time.Millisecond*100)
		defer cancel()
		
		key := s.testPrefix + "timeout_test"
		value := "timeout_test_value"
		
		// This may timeout depending on Redis latency
		err := s.foundation.CacheSet(timeoutCtx, key, value, nil)
		if err != nil {
			// Operation may timeout, which is expected behavior
			assert.Contains(t, err.Error(), "context deadline exceeded")
			t.Log("Cache operation properly timed out as expected")
		} else {
			// Operation succeeded within timeout
			t.Log("Cache operation completed within timeout")
		}
		
		// Test that connection recovers with normal timeout
		err = s.foundation.CacheSet(s.ctx, key, value, nil)
		require.NoError(t, err, "Should recover and work with normal timeout")
		
		retrievedValue, err := s.foundation.CacheGet(s.ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, retrievedValue)
	})
}

// TestRedisSecurityScanning tests security-related Redis operations
func (s *FortressRedisIntegrationSuite) TestRedisSecurityScanning() {
	s.T().Run("Security_Data_Storage", func(t *testing.T) {
		email := s.emailFixtures.EmailWithSecurityHeaders()
		
		// Simulate security scan result storage
		scanResult := &interfaces.ScanResult{
			EmailID:   email.ID,
			Status:    interfaces.ScanStatusClean,
			Score:     0.1,
			Issues:    []string{},
			Timestamp: time.Now(),
			Duration:  time.Millisecond * 50,
			Details: map[string]interface{}{
				"spf_status":   "pass",
				"dkim_status":  "valid",
				"spam_score":   0.1,
				"virus_status": "clean",
			},
		}
		
		// Store scan result in cache for fast retrieval
		scanKey := s.testPrefix + "scan:" + email.ID
		scanJSON, err := json.Marshal(scanResult)
		require.NoError(t, err)
		
		ttl := time.Hour * 24 // Cache scan results for 24 hours
		err = s.foundation.CacheSet(s.ctx, scanKey, string(scanJSON), &ttl)
		require.NoError(t, err)
		
		// Retrieve and verify scan result
		retrievedData, err := s.foundation.CacheGet(s.ctx, scanKey)
		require.NoError(t, err)
		
		var retrievedScan interfaces.ScanResult
		err = json.Unmarshal([]byte(retrievedData.(string)), &retrievedScan)
		require.NoError(t, err)
		
		assert.Equal(t, scanResult.EmailID, retrievedScan.EmailID)
		assert.Equal(t, scanResult.Status, retrievedScan.Status)
		assert.Equal(t, scanResult.Score, retrievedScan.Score)
	})
}

// Helper methods

func (s *FortressRedisIntegrationSuite) overrideConfigFromEnv() {
	if address := os.Getenv("FORTRESS_TEST_REDIS_ADDRESS"); address != "" {
		s.config.Address = address
	}
	if password := os.Getenv("FORTRESS_TEST_REDIS_PASSWORD"); password != "" {
		s.config.Password = password
	}
	if db := os.Getenv("FORTRESS_TEST_REDIS_DB"); db != "" {
		// Convert to int if needed, default to 1 for tests
		s.config.DB = 1
	}
}

func (s *FortressRedisIntegrationSuite) initializeRedisConnection() {
	s.redisClient = redis.NewClient(&redis.Options{
		Addr:         s.config.Address,
		Password:     s.config.Password,
		DB:           s.config.DB,
		MaxRetries:   s.config.MaxRetries,
		PoolSize:     s.config.PoolSize,
		MinIdleConns: s.config.MinIdleConns,
		DialTimeout:  s.config.DialTimeout,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	})
	
	// Test connection
	_, err := s.redisClient.Ping(s.ctx).Result()
	require.NoError(s.T(), err, "Should be able to connect to Redis")
}

func (s *FortressRedisIntegrationSuite) cleanupTestData() {
	// Clean up all test keys
	keys, err := s.redisClient.Keys(s.ctx, s.testPrefix+"*").Result()
	if err != nil {
		s.T().Logf("Warning: Error getting test keys: %v", err)
		return
	}
	
	if len(keys) > 0 {
		err = s.redisClient.Del(s.ctx, keys...).Err()
		if err != nil {
			s.T().Logf("Warning: Error cleaning up test keys: %v", err)
		}
	}
}

func (s *FortressRedisIntegrationSuite) cleanupTestKeys() {
	s.cleanupTestData() // Reuse the same cleanup logic
}

func (s *FortressRedisIntegrationSuite) createRampartService() interfaces.Rampart {
	return &RedisRampartService{
		redis:  s.redisClient,
		config: s.config,
	}
}

func (s *FortressRedisIntegrationSuite) createFoundationService() interfaces.Foundation {
	return &RedisFoundationService{
		redis:  s.redisClient,
		config: s.config,
	}
}

// RedisFoundationService implements cache operations with real Redis
type RedisFoundationService struct {
	redis  *redis.Client
	config *interfaces.RedisConfig
}

func (r *RedisFoundationService) CacheGet(ctx context.Context, key string) (interface{}, error) {
	fullKey := r.config.Prefix + key
	result, err := r.redis.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("key not found: %s", key)
		}
		return nil, err
	}
	return result, nil
}

func (r *RedisFoundationService) CacheSet(ctx context.Context, key string, value interface{}, ttl *time.Duration) error {
	fullKey := r.config.Prefix + key
	var expiration time.Duration
	if ttl != nil {
		expiration = *ttl
	}
	return r.redis.Set(ctx, fullKey, value, expiration).Err()
}

func (r *RedisFoundationService) CacheDelete(ctx context.Context, key string) error {
	fullKey := r.config.Prefix + key
	return r.redis.Del(ctx, fullKey).Err()
}

func (r *RedisFoundationService) CacheClear(ctx context.Context, pattern string) error {
	fullPattern := r.config.Prefix + pattern
	keys, err := r.redis.Keys(ctx, fullPattern).Result()
	if err != nil {
		return err
	}
	
	if len(keys) > 0 {
		return r.redis.Del(ctx, keys...).Err()
	}
	return nil
}

// Implement other Foundation methods with mocks
func (r *RedisFoundationService) Connect(ctx context.Context, config *interfaces.DatabaseConfig) error { return nil }
func (r *RedisFoundationService) Disconnect(ctx context.Context) error { return nil }
func (r *RedisFoundationService) Migrate(ctx context.Context, version string) error { return nil }
func (r *RedisFoundationService) Query(ctx context.Context, query string, args ...interface{}) (*interfaces.QueryResult, error) { return &interfaces.QueryResult{}, nil }
func (r *RedisFoundationService) QueryOne(ctx context.Context, query string, args ...interface{}) (map[string]interface{}, error) { return make(map[string]interface{}), nil }
func (r *RedisFoundationService) Exec(ctx context.Context, query string, args ...interface{}) error { return nil }
func (r *RedisFoundationService) BeginTransaction(ctx context.Context) (interfaces.Transaction, error) { return &MockTransaction{}, nil }
func (r *RedisFoundationService) Transaction(ctx context.Context, fn func(tx interfaces.Transaction) error) error { return fn(&MockTransaction{}) }
func (r *RedisFoundationService) StoreFile(ctx context.Context, path string, data []byte) error { return nil }
func (r *RedisFoundationService) RetrieveFile(ctx context.Context, path string) ([]byte, error) { return nil, fmt.Errorf("file not found") }
func (r *RedisFoundationService) DeleteFile(ctx context.Context, path string) error { return nil }
func (r *RedisFoundationService) ListFiles(ctx context.Context, pattern string) ([]string, error) { return []string{}, nil }
func (r *RedisFoundationService) CreateBackup(ctx context.Context, config *interfaces.BackupConfig) error { return nil }
func (r *RedisFoundationService) RestoreBackup(ctx context.Context, backupID string) error { return nil }
func (r *RedisFoundationService) ListBackups(ctx context.Context) ([]*interfaces.BackupInfo, error) { return []*interfaces.BackupInfo{}, nil }
func (r *RedisFoundationService) Start(ctx context.Context) error { return nil }
func (r *RedisFoundationService) Stop(ctx context.Context) error { return nil }
func (r *RedisFoundationService) Health(ctx context.Context) *interfaces.HealthStatus {
	_, err := r.redis.Ping(ctx).Result()
	status := interfaces.HealthStatusHealthy
	message := "Redis connection healthy"
	
	if err != nil {
		status = interfaces.HealthStatusUnhealthy
		message = fmt.Sprintf("Redis connection failed: %v", err)
	}
	
	return &interfaces.HealthStatus{
		Service:   "foundation",
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
		Duration:  time.Millisecond * 10,
	}
}

// RedisRampartService implements rate limiting with real Redis
type RedisRampartService struct {
	redis  *redis.Client
	config *interfaces.RedisConfig
}

func (r *RedisRampartService) CheckRateLimit(ctx context.Context, key string, limit *interfaces.RateLimit) (*interfaces.RateLimitResult, error) {
	fullKey := r.config.Prefix + "ratelimit:" + key
	
	// Simple sliding window rate limiting implementation
	now := time.Now().Unix()
	windowStart := now - int64(limit.WindowDuration.Seconds())
	
	// Use Redis sorted set for sliding window
	pipe := r.redis.Pipeline()
	
	// Remove old entries
	pipe.ZRemRangeByScore(ctx, fullKey, "-inf", fmt.Sprintf("%d", windowStart))
	
	// Count current requests
	countCmd := pipe.ZCard(ctx, fullKey)
	
	// Add current request
	pipe.ZAdd(ctx, fullKey, redis.Z{Score: float64(now), Member: fmt.Sprintf("%d", now)})
	
	// Set expiration
	pipe.Expire(ctx, fullKey, limit.WindowDuration)
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}
	
	currentCount := countCmd.Val()
	allowed := currentCount < int64(limit.RequestsPerSecond)
	remaining := int64(limit.RequestsPerSecond) - currentCount
	if remaining < 0 {
		remaining = 0
	}
	
	return &interfaces.RateLimitResult{
		Allowed:   allowed,
		Remaining: remaining,
		ResetTime: time.Unix(now+int64(limit.WindowDuration.Seconds()), 0),
		RetryAfter: limit.WindowDuration,
	}, nil
}

// Implement other Rampart methods with mocks
func (r *RedisRampartService) ResetRateLimit(ctx context.Context, key string) error {
	fullKey := r.config.Prefix + "ratelimit:" + key
	return r.redis.Del(ctx, fullKey).Err()
}
func (r *RedisRampartService) GetRateLimitStatus(ctx context.Context, key string) (*interfaces.RateLimitStatus, error) { return &interfaces.RateLimitStatus{}, nil }
func (r *RedisRampartService) ValidateRequest(ctx context.Context, req *interfaces.Request) (*interfaces.SecurityResult, error) { return &interfaces.SecurityResult{Valid: true}, nil }
func (r *RedisRampartService) ScanEmail(ctx context.Context, email *interfaces.Email) (*interfaces.ScanResult, error) { return &interfaces.ScanResult{Status: interfaces.ScanStatusClean}, nil }
func (r *RedisRampartService) CheckBlacklist(ctx context.Context, value string, listType interfaces.BlacklistType) (bool, error) { return false, nil }
func (r *RedisRampartService) DetectAnomalies(ctx context.Context, data map[string]interface{}) (*interfaces.AnomalyResult, error) { return &interfaces.AnomalyResult{}, nil }
func (r *RedisRampartService) ReportThreat(ctx context.Context, threat *interfaces.ThreatReport) error { return nil }
func (r *RedisRampartService) ApplySecurityPolicy(ctx context.Context, policy *interfaces.SecurityPolicy, target interface{}) error { return nil }
func (r *RedisRampartService) ValidateCompliance(ctx context.Context, req *interfaces.ComplianceRequest) (*interfaces.ComplianceResult, error) { return &interfaces.ComplianceResult{}, nil }
func (r *RedisRampartService) Start(ctx context.Context) error { return nil }
func (r *RedisRampartService) Stop(ctx context.Context) error { return nil }
func (r *RedisRampartService) Health(ctx context.Context) *interfaces.HealthStatus {
	return &interfaces.HealthStatus{Service: "rampart", Status: interfaces.HealthStatusHealthy}
}

// MockTransaction for Foundation methods that don't use Redis
type MockTransaction struct{}
func (m *MockTransaction) Query(ctx context.Context, query string, args ...interface{}) (*interfaces.QueryResult, error) { return &interfaces.QueryResult{}, nil }
func (m *MockTransaction) Exec(ctx context.Context, query string, args ...interface{}) error { return nil }
func (m *MockTransaction) Commit() error { return nil }
func (m *MockTransaction) Rollback() error { return nil }

// TestFortressRedisIntegration runs the Redis integration test suite
func TestFortressRedisIntegration(t *testing.T) {
	// Skip if no Redis available
	if os.Getenv("FORTRESS_TEST_REDIS_ADDRESS") == "" {
		t.Skip("Skipping Redis integration tests - no Redis configured")
	}
	
	suite.Run(t, new(FortressRedisIntegrationSuite))
}