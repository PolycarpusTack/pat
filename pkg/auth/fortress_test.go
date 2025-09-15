package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFortressApiKeyService tests the fortress API key service
func TestFortressApiKeyService(t *testing.T) {
	// Create mock repositories
	mockApiKeyRepo := &mockApiKeyRepository{
		apiKeys: make(map[string]*ApiKey),
	}
	mockAuditRepo := &mockAuditRepository{
		logs: make([]*AuditLog, 0),
	}
	mockRateLimiter := NewFortressRateLimiter()

	// Create service
	service := NewFortressApiKeyService(mockApiKeyRepo, mockAuditRepo, mockRateLimiter)

	t.Run("Generate API Key", func(t *testing.T) {
		userID := "test-user-123"
		keyName := "Test API Key"
		permissions := []string{"fortress:email:read", "fortress:email:write"}
		rateLimit := 100
		expiresAt := time.Now().Add(30 * 24 * time.Hour)

		keyString, apiKey, err := service.CommanderGenerateApiKey(
			context.Background(),
			userID,
			keyName,
			permissions,
			rateLimit,
			&expiresAt,
		)

		require.NoError(t, err)
		require.NotEmpty(t, keyString)
		require.NotNil(t, apiKey)

		// Verify key format
		assert.True(t, len(keyString) > 50, "API key should be long enough")
		assert.True(t, len(keyString) < 200, "API key should not be too long")
		assert.Contains(t, keyString, "pat_", "API key should have pat_ prefix")

		// Verify API key properties
		assert.Equal(t, userID, apiKey.UserID)
		assert.Equal(t, keyName, apiKey.Name)
		assert.Equal(t, permissions, apiKey.Permissions)
		assert.Equal(t, rateLimit, apiKey.RateLimit)
		assert.True(t, apiKey.IsActive)
		assert.NotEmpty(t, apiKey.KeyHash)
		assert.NotEmpty(t, apiKey.KeyPreview)
	})

	t.Run("Validate API Key", func(t *testing.T) {
		// Generate a key first
		userID := "test-user-456"
		keyName := "Validation Test Key"
		permissions := []string{"fortress:email:read"}
		rateLimit := 50

		keyString, apiKey, err := service.CommanderGenerateApiKey(
			context.Background(),
			userID,
			keyName,
			permissions,
			rateLimit,
			nil,
		)

		require.NoError(t, err)

		// Test valid key
		result, err := service.GuardValidateApiKey(
			context.Background(),
			keyString,
			"192.168.1.1",
			"Test-User-Agent",
		)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.IsValid)
		assert.Equal(t, apiKey.ID, result.ApiKey.ID)

		// Test invalid key
		result, err = service.GuardValidateApiKey(
			context.Background(),
			"invalid-key-string",
			"192.168.1.1",
			"Test-User-Agent",
		)

		require.NoError(t, err)
		assert.False(t, result.IsValid)
		assert.Equal(t, "invalid_key_format", result.FailReason)
	})

	t.Run("Revoke API Key", func(t *testing.T) {
		// Generate a key first
		userID := "test-user-789"
		keyName := "Revocation Test Key"
		permissions := []string{"fortress:email:read"}

		keyString, apiKey, err := service.CommanderGenerateApiKey(
			context.Background(),
			userID,
			keyName,
			permissions,
			100,
			nil,
		)

		require.NoError(t, err)

		// Revoke the key
		err = service.GuardRevokeApiKey(
			context.Background(),
			apiKey.ID,
			userID,
			"Test revocation",
		)

		require.NoError(t, err)

		// Verify key is revoked
		storedKey := mockApiKeyRepo.apiKeys[apiKey.ID]
		assert.False(t, storedKey.IsActive)

		// Test validation of revoked key
		result, err := service.GuardValidateApiKey(
			context.Background(),
			keyString,
			"192.168.1.1",
			"Test-User-Agent",
		)

		require.NoError(t, err)
		assert.False(t, result.IsValid)
		assert.Equal(t, "key_inactive", result.FailReason)
	})
}

// TestFortressRoleManager tests the fortress role manager
func TestFortressRoleManager(t *testing.T) {
	mockAuditRepo := &mockAuditRepository{
		logs: make([]*AuditLog, 0),
	}

	roleManager := NewFortressRoleManager(mockAuditRepo)

	t.Run("Role Definitions", func(t *testing.T) {
		// Test role definitions exist
		roleDef, exists := roleManager.GetFortressRoleDefinition(RoleCommander)
		assert.True(t, exists)
		assert.Equal(t, "Fortress Commander", roleDef.Name)
		assert.Equal(t, 100, roleDef.Level)
		assert.True(t, roleDef.RequiresMFA)

		roleDef, exists = roleManager.GetFortressRoleDefinition(RoleObserver)
		assert.True(t, exists)
		assert.Equal(t, "Fortress Observer", roleDef.Name)
		assert.Equal(t, 40, roleDef.Level)
		assert.False(t, roleDef.RequiresMFA)
	})

	t.Run("Permission Validation", func(t *testing.T) {
		// Create test users with different roles
		commanderUser := &User{
			ID:    "commander-user",
			Roles: []string{"super_admin"}, // Maps to commander
		}

		guardianUser := &User{
			ID:    "guardian-user",
			Roles: []string{"admin"}, // Maps to guardian
		}

		observerUser := &User{
			ID:    "observer-user",
			Roles: []string{"user"}, // Maps to observer
		}

		// Test commander permissions (should have all)
		assert.True(t, roleManager.GuardValidatePermission(commanderUser, PermFortressEmailDelete))
		assert.True(t, roleManager.GuardValidatePermission(commanderUser, PermFortressUserWrite))
		assert.True(t, roleManager.GuardValidatePermission(commanderUser, PermFortressSystemWrite))

		// Test guardian permissions
		assert.True(t, roleManager.GuardValidatePermission(guardianUser, PermFortressEmailWrite))
		assert.True(t, roleManager.GuardValidatePermission(guardianUser, PermFortressUserWrite))
		assert.False(t, roleManager.GuardValidatePermission(guardianUser, PermFortressUserBan)) // Guardian can't ban

		// Test observer permissions (read-only)
		assert.True(t, roleManager.GuardValidatePermission(observerUser, PermFortressEmailRead))
		assert.False(t, roleManager.GuardValidatePermission(observerUser, PermFortressEmailWrite))
		assert.False(t, roleManager.GuardValidatePermission(observerUser, PermFortressUserWrite))
	})

	t.Run("Role Validation", func(t *testing.T) {
		adminUser := &User{
			ID:    "admin-user",
			Roles: []string{"admin"},
		}

		// Admin should validate as guardian
		assert.True(t, roleManager.SentinelValidateRole(adminUser, RoleGuardian))
		
		// Admin should also validate as sentinel (lower level)
		assert.True(t, roleManager.SentinelValidateRole(adminUser, RoleSentinel))
		
		// Admin should NOT validate as commander (higher level)
		assert.False(t, roleManager.SentinelValidateRole(adminUser, RoleCommander))
	})
}

// TestFortressSessionManager tests the fortress session manager
func TestFortressSessionManager(t *testing.T) {
	mockSessionRepo := &mockSessionRepository{
		sessions: make(map[string]*Session),
	}
	mockBlacklist := &mockTokenBlacklist{
		blacklistedTokens: make(map[string]time.Time),
	}
	mockAuditRepo := &mockAuditRepository{
		logs: make([]*AuditLog, 0),
	}

	config := DefaultFortressSessionConfig()
	sessionManager := NewFortressSessionManager(mockSessionRepo, mockBlacklist, mockAuditRepo, config)

	t.Run("Create Session", func(t *testing.T) {
		userID := "test-user-session"
		deviceID := "test-device-123"
		ipAddress := "192.168.1.100"
		userAgent := "Test-Browser/1.0"

		session, err := sessionManager.GuardCreateSession(
			context.Background(),
			userID,
			deviceID,
			ipAddress,
			userAgent,
			false, // rememberMe
		)

		require.NoError(t, err)
		require.NotNil(t, session)

		assert.Equal(t, userID, session.UserID)
		assert.Equal(t, deviceID, session.DeviceID)
		assert.Equal(t, ipAddress, session.IPAddress)
		assert.Equal(t, userAgent, session.UserAgent)
		assert.True(t, session.IsActive)
		assert.NotEmpty(t, session.RefreshToken)
	})

	t.Run("Validate Session", func(t *testing.T) {
		// Create a session first
		userID := "test-user-validate"
		deviceID := "test-device-456"
		ipAddress := "192.168.1.101"
		userAgent := "Test-Browser/2.0"

		session, err := sessionManager.GuardCreateSession(
			context.Background(),
			userID,
			deviceID,
			ipAddress,
			userAgent,
			false,
		)

		require.NoError(t, err)

		// Validate the session
		sessionInfo, err := sessionManager.SentinelValidateSession(
			context.Background(),
			session.ID,
			session.RefreshToken,
			ipAddress,
			userAgent,
		)

		require.NoError(t, err)
		assert.True(t, sessionInfo.IsValid)
		assert.NotNil(t, sessionInfo.SecurityInfo)
		assert.Equal(t, ipAddress, sessionInfo.SecurityInfo.IPAddress)
		assert.Equal(t, userAgent, sessionInfo.SecurityInfo.UserAgent)
	})

	t.Run("Terminate Session", func(t *testing.T) {
		// Create a session first
		userID := "test-user-terminate"
		deviceID := "test-device-789"
		ipAddress := "192.168.1.102"
		userAgent := "Test-Browser/3.0"

		session, err := sessionManager.GuardCreateSession(
			context.Background(),
			userID,
			deviceID,
			ipAddress,
			userAgent,
			false,
		)

		require.NoError(t, err)

		// Terminate the session
		err = sessionManager.SentinelTerminateSession(
			context.Background(),
			session.ID,
			"test_termination",
		)

		require.NoError(t, err)

		// Verify session is terminated
		_, exists := mockSessionRepo.sessions[session.ID]
		assert.False(t, exists)
	})
}

// TestFortressTokenBlacklist tests the fortress token blacklist
func TestFortressTokenBlacklist(t *testing.T) {
	mockAuditRepo := &mockAuditRepository{
		logs: make([]*AuditLog, 0),
	}

	blacklist := NewFortressTokenBlacklist(mockAuditRepo)

	t.Run("Blacklist Token", func(t *testing.T) {
		tokenID := "test-token-123"
		expiresAt := time.Now().Add(1 * time.Hour)

		err := blacklist.BlacklistToken(tokenID, expiresAt)
		require.NoError(t, err)

		// Check if token is blacklisted
		isBlacklisted, err := blacklist.IsBlacklisted(tokenID)
		require.NoError(t, err)
		assert.True(t, isBlacklisted)
	})

	t.Run("Token Expiry", func(t *testing.T) {
		tokenID := "test-token-expired"
		expiresAt := time.Now().Add(-1 * time.Hour) // Already expired

		err := blacklist.BlacklistToken(tokenID, expiresAt)
		require.NoError(t, err)

		// Check if expired token is considered not blacklisted
		isBlacklisted, err := blacklist.IsBlacklisted(tokenID)
		require.NoError(t, err)
		assert.False(t, isBlacklisted)
	})

	t.Run("Remove from Blacklist", func(t *testing.T) {
		tokenID := "test-token-remove"
		expiresAt := time.Now().Add(1 * time.Hour)

		// Add to blacklist
		err := blacklist.BlacklistToken(tokenID, expiresAt)
		require.NoError(t, err)

		// Verify it's blacklisted
		isBlacklisted, err := blacklist.IsBlacklisted(tokenID)
		require.NoError(t, err)
		assert.True(t, isBlacklisted)

		// Remove from blacklist
		err = blacklist.SentinelRemoveFromBlacklist(tokenID, "test_removal")
		require.NoError(t, err)

		// Verify it's no longer blacklisted
		isBlacklisted, err = blacklist.IsBlacklisted(tokenID)
		require.NoError(t, err)
		assert.False(t, isBlacklisted)
	})

	t.Run("Emergency Blacklist", func(t *testing.T) {
		pattern := "suspicious-pattern"
		duration := 2 * time.Hour
		reason := "Security incident"

		err := blacklist.CommanderEmergencyBlacklist(pattern, duration, reason)
		require.NoError(t, err)

		// Verify emergency blacklist was created
		blacklistedTokens := blacklist.WatchtowerListBlacklistedTokens()
		found := false
		for tokenID := range blacklistedTokens {
			if len(tokenID) > 10 && tokenID[:10] == "emergency:" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})
}

// Mock implementations for testing

type mockApiKeyRepository struct {
	apiKeys map[string]*ApiKey
}

func (m *mockApiKeyRepository) Create(ctx context.Context, apiKey *ApiKey) error {
	m.apiKeys[apiKey.ID] = apiKey
	return nil
}

func (m *mockApiKeyRepository) GetByID(ctx context.Context, id string) (*ApiKey, error) {
	if apiKey, exists := m.apiKeys[id]; exists {
		return apiKey, nil
	}
	return nil, fmt.Errorf("api key not found")
}

func (m *mockApiKeyRepository) GetByKeyHash(ctx context.Context, keyHash string) (*ApiKey, error) {
	for _, apiKey := range m.apiKeys {
		if apiKey.KeyHash == keyHash {
			return apiKey, nil
		}
	}
	return nil, fmt.Errorf("api key not found")
}

func (m *mockApiKeyRepository) Update(ctx context.Context, apiKey *ApiKey) error {
	m.apiKeys[apiKey.ID] = apiKey
	return nil
}

func (m *mockApiKeyRepository) Delete(ctx context.Context, id string) error {
	delete(m.apiKeys, id)
	return nil
}

func (m *mockApiKeyRepository) ListByUserID(ctx context.Context, userID string) ([]*ApiKey, error) {
	var result []*ApiKey
	for _, apiKey := range m.apiKeys {
		if apiKey.UserID == userID {
			result = append(result, apiKey)
		}
	}
	return result, nil
}

func (m *mockApiKeyRepository) UpdateLastUsed(ctx context.Context, id string, lastUsed time.Time) error {
	if apiKey, exists := m.apiKeys[id]; exists {
		apiKey.LastUsedAt = &lastUsed
		return nil
	}
	return fmt.Errorf("api key not found")
}

type mockSessionRepository struct {
	sessions map[string]*Session
}

func (m *mockSessionRepository) Create(ctx context.Context, session *Session) error {
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionRepository) GetByID(ctx context.Context, id string) (*Session, error) {
	if session, exists := m.sessions[id]; exists {
		return session, nil
	}
	return nil, fmt.Errorf("session not found")
}

func (m *mockSessionRepository) GetByRefreshToken(ctx context.Context, refreshToken string) (*Session, error) {
	for _, session := range m.sessions {
		if session.RefreshToken == refreshToken {
			return session, nil
		}
	}
	return nil, fmt.Errorf("session not found")
}

func (m *mockSessionRepository) Update(ctx context.Context, session *Session) error {
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionRepository) Delete(ctx context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

func (m *mockSessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	for id, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *mockSessionRepository) GetActiveSessions(ctx context.Context, userID string) ([]*Session, error) {
	var result []*Session
	for _, session := range m.sessions {
		if session.UserID == userID && session.IsActive {
			result = append(result, session)
		}
	}
	return result, nil
}

type mockTokenBlacklist struct {
	blacklistedTokens map[string]time.Time
}

func (m *mockTokenBlacklist) IsBlacklisted(tokenID string) (bool, error) {
	expiresAt, exists := m.blacklistedTokens[tokenID]
	if !exists {
		return false, nil
	}
	return time.Now().Before(expiresAt), nil
}

func (m *mockTokenBlacklist) BlacklistToken(tokenID string, expiresAt time.Time) error {
	m.blacklistedTokens[tokenID] = expiresAt
	return nil
}

type mockAuditRepository struct {
	logs []*AuditLog
}

func (m *mockAuditRepository) Create(ctx context.Context, log *AuditLog) error {
	m.logs = append(m.logs, log)
	return nil
}

func (m *mockAuditRepository) List(ctx context.Context, tenantID string, filters map[string]interface{}, limit, offset int) ([]*AuditLog, int, error) {
	return m.logs, len(m.logs), nil
}

// Benchmark tests for performance validation
func BenchmarkFortressApiKeyValidation(b *testing.B) {
	mockApiKeyRepo := &mockApiKeyRepository{
		apiKeys: make(map[string]*ApiKey),
	}
	mockAuditRepo := &mockAuditRepository{
		logs: make([]*AuditLog, 0),
	}
	mockRateLimiter := NewFortressRateLimiter()

	service := NewFortressApiKeyService(mockApiKeyRepo, mockAuditRepo, mockRateLimiter)

	// Generate a test API key
	keyString, _, err := service.CommanderGenerateApiKey(
		context.Background(),
		"bench-user",
		"Benchmark Key",
		[]string{"fortress:email:read"},
		1000,
		nil,
	)
	require.NoError(b, err)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := service.GuardValidateApiKey(
				context.Background(),
				keyString,
				"192.168.1.1",
				"Benchmark-Agent",
			)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkFortressTokenBlacklist(b *testing.B) {
	mockAuditRepo := &mockAuditRepository{
		logs: make([]*AuditLog, 0),
	}

	blacklist := NewFortressTokenBlacklist(mockAuditRepo)

	// Pre-populate with some tokens
	for i := 0; i < 1000; i++ {
		tokenID := fmt.Sprintf("benchmark-token-%d", i)
		expiresAt := time.Now().Add(1 * time.Hour)
		blacklist.BlacklistToken(tokenID, expiresAt)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		tokenCounter := 0
		for pb.Next() {
			tokenID := fmt.Sprintf("benchmark-token-%d", tokenCounter%1000)
			_, err := blacklist.IsBlacklisted(tokenID)
			if err != nil {
				b.Error(err)
			}
			tokenCounter++
		}
	})
}