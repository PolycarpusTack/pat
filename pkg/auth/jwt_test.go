package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKeyPair() ([]byte, []byte, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Encode private key to PEM
	privateKeyBytes, err := x509.MarshalPKCS1PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Generate public key
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPEM, publicKeyPEM, nil
}

func TestNewJWTManager(t *testing.T) {
	tests := []struct {
		name        string
		privateKey  []byte
		publicKey   []byte
		issuer      string
		audience    string
		wantErr     bool
	}{
		{
			name:     "valid keys",
			issuer:   "test-issuer",
			audience: "test-audience",
			wantErr:  false,
		},
		{
			name:       "invalid private key",
			privateKey: []byte("invalid"),
			publicKey:  []byte("invalid"),
			issuer:     "test-issuer",
			audience:   "test-audience",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var privateKeyPEM, publicKeyPEM []byte
			var err error

			if !tt.wantErr && tt.privateKey == nil && tt.publicKey == nil {
				privateKeyPEM, publicKeyPEM, err = generateTestKeyPair()
				require.NoError(t, err)
			} else {
				privateKeyPEM = tt.privateKey
				publicKeyPEM = tt.publicKey
			}

			manager, err := NewJWTManager(privateKeyPEM, publicKeyPEM, tt.issuer, tt.audience)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
				assert.Equal(t, tt.issuer, manager.issuer)
				assert.Equal(t, tt.audience, manager.audience)
			}
		})
	}
}

func TestJWTManager_GenerateTokenPair(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestKeyPair()
	require.NoError(t, err)

	manager, err := NewJWTManager(privateKeyPEM, publicKeyPEM, "test-issuer", "test-audience")
	require.NoError(t, err)

	userID := "test-user-id"
	email := "test@example.com"
	name := "Test User"
	tenantID := "test-tenant"
	roles := []string{"user", "admin"}
	permissions := []string{"read", "write"}
	deviceID := "test-device"
	ipAddress := "192.168.1.1"

	accessToken, refreshToken, err := manager.GenerateTokenPair(
		userID, email, name, tenantID, roles, permissions, deviceID, ipAddress,
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)

	// Validate access token structure
	token, err := jwt.ParseWithClaims(accessToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return manager.publicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(*Claims)
	require.True(t, ok)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, name, claims.Name)
	assert.Equal(t, tenantID, claims.TenantID)
	assert.Equal(t, roles, claims.Roles)
	assert.Equal(t, permissions, claims.Permissions)
	assert.Equal(t, deviceID, claims.DeviceID)
	assert.Equal(t, ipAddress, claims.IPAddress)
}

func TestJWTManager_ValidateToken(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestKeyPair()
	require.NoError(t, err)

	manager, err := NewJWTManager(privateKeyPEM, publicKeyPEM, "test-issuer", "test-audience")
	require.NoError(t, err)

	// Generate a valid token
	accessToken, _, err := manager.GenerateTokenPair(
		"user-id", "test@example.com", "Test User", "tenant-id",
		[]string{"user"}, []string{"read"}, "device-id", "127.0.0.1",
	)
	require.NoError(t, err)

	// Test valid token
	claims, err := manager.ValidateToken(accessToken)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, "user-id", claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)

	// Test invalid token
	_, err = manager.ValidateToken("invalid-token")
	assert.Error(t, err)

	// Test expired token
	expiredClaims := Claims{
		UserID: "user-id",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodRS256, expiredClaims)
	expiredTokenString, err := expiredToken.SignedString(manager.privateKey)
	require.NoError(t, err)

	_, err = manager.ValidateToken(expiredTokenString)
	assert.Error(t, err)
}

func TestJWTManager_RefreshToken(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestKeyPair()
	require.NoError(t, err)

	manager, err := NewJWTManager(privateKeyPEM, publicKeyPEM, "test-issuer", "test-audience")
	require.NoError(t, err)

	user := &User{
		ID:       "user-id",
		Email:    "test@example.com",
		Name:     "Test User",
		TenantID: "tenant-id",
		Roles:    []string{"user"},
	}

	// Generate tokens
	_, refreshToken, err := manager.GenerateTokenPair(
		user.ID, user.Email, user.Name, user.TenantID,
		user.Roles, user.GetPermissions(), "device-id", "127.0.0.1",
	)
	require.NoError(t, err)

	// Test refresh
	newAccessToken, err := manager.RefreshToken(refreshToken, user)
	assert.NoError(t, err)
	assert.NotEmpty(t, newAccessToken)

	// Validate new access token
	claims, err := manager.ValidateToken(newAccessToken)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
}

func TestExtractTokenFromHeader(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantToken  string
		wantErr    bool
	}{
		{
			name:       "valid bearer token",
			authHeader: "Bearer test-token-123",
			wantToken:  "test-token-123",
			wantErr:    false,
		},
		{
			name:       "empty header",
			authHeader: "",
			wantToken:  "",
			wantErr:    true,
		},
		{
			name:       "missing bearer prefix",
			authHeader: "test-token-123",
			wantToken:  "",
			wantErr:    true,
		},
		{
			name:       "bearer without token",
			authHeader: "Bearer ",
			wantToken:  "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractTokenFromHeader(tt.authHeader)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantToken, token)
			}
		})
	}
}

func TestJWTManager_ValidateTokenWithBlacklist(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := generateTestKeyPair()
	require.NoError(t, err)

	manager, err := NewJWTManager(privateKeyPEM, publicKeyPEM, "test-issuer", "test-audience")
	require.NoError(t, err)

	// Mock blacklist
	blacklist := &mockTokenBlacklist{
		blacklistedTokens: make(map[string]bool),
	}

	// Generate token
	accessToken, _, err := manager.GenerateTokenPair(
		"user-id", "test@example.com", "Test User", "tenant-id",
		[]string{"user"}, []string{"read"}, "device-id", "127.0.0.1",
	)
	require.NoError(t, err)

	// Test valid token
	claims, err := manager.ValidateTokenWithBlacklist(accessToken, blacklist)
	assert.NoError(t, err)
	assert.NotNil(t, claims)

	// Blacklist the token
	token, _ := jwt.ParseWithClaims(accessToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return manager.publicKey, nil
	})
	tokenClaims := token.Claims.(*Claims)
	blacklist.BlacklistToken(tokenClaims.ID, time.Now().Add(time.Hour))

	// Test blacklisted token
	_, err = manager.ValidateTokenWithBlacklist(accessToken, blacklist)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

// Mock token blacklist for testing
type mockTokenBlacklist struct {
	blacklistedTokens map[string]bool
}

func (m *mockTokenBlacklist) IsBlacklisted(tokenID string) (bool, error) {
	return m.blacklistedTokens[tokenID], nil
}

func (m *mockTokenBlacklist) BlacklistToken(tokenID string, expiresAt time.Time) error {
	m.blacklistedTokens[tokenID] = true
	return nil
}

func BenchmarkJWTManager_GenerateTokenPair(b *testing.B) {
	privateKeyPEM, publicKeyPEM, err := generateTestKeyPair()
	require.NoError(b, err)

	manager, err := NewJWTManager(privateKeyPEM, publicKeyPEM, "test-issuer", "test-audience")
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := manager.GenerateTokenPair(
			"user-id", "test@example.com", "Test User", "tenant-id",
			[]string{"user"}, []string{"read"}, "device-id", "127.0.0.1",
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWTManager_ValidateToken(b *testing.B) {
	privateKeyPEM, publicKeyPEM, err := generateTestKeyPair()
	require.NoError(b, err)

	manager, err := NewJWTManager(privateKeyPEM, publicKeyPEM, "test-issuer", "test-audience")
	require.NoError(b, err)

	// Generate token once
	accessToken, _, err := manager.GenerateTokenPair(
		"user-id", "test@example.com", "Test User", "tenant-id",
		[]string{"user"}, []string{"read"}, "device-id", "127.0.0.1",
	)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.ValidateToken(accessToken)
		if err != nil {
			b.Fatal(err)
		}
	}
}