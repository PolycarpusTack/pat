package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents JWT claims with RBAC support
type Claims struct {
	UserID       string   `json:"user_id"`
	Email        string   `json:"email"`
	Name         string   `json:"name"`
	Roles        []string `json:"roles"`
	Permissions  []string `json:"permissions"`
	TenantID     string   `json:"tenant_id"`
	SessionID    string   `json:"session_id"`
	DeviceID     string   `json:"device_id,omitempty"`
	IPAddress    string   `json:"ip_address,omitempty"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token operations
type JWTManager struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	issuer         string
	audience       string
	accessExpiry   time.Duration
	refreshExpiry  time.Duration
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(privateKeyPEM, publicKeyPEM []byte, issuer, audience string) (*JWTManager, error) {
	// Parse private key
	privateBlock, _ := pem.Decode(privateKeyPEM)
	if privateBlock == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		// Try PKCS8 format
		parsedKey, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		
		var ok bool
		privateKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	// Parse public key
	publicBlock, _ := pem.Decode(publicKeyPEM)
	if publicBlock == nil {
		return nil, fmt.Errorf("failed to parse public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	return &JWTManager{
		privateKey:    privateKey,
		publicKey:     rsaPublicKey,
		issuer:        issuer,
		audience:      audience,
		accessExpiry:  15 * time.Minute,
		refreshExpiry: 7 * 24 * time.Hour,
	}, nil
}

// GenerateTokenPair generates access and refresh tokens
func (j *JWTManager) GenerateTokenPair(userID, email, name, tenantID string, roles []string, permissions []string, deviceID, ipAddress string) (accessToken, refreshToken string, err error) {
	sessionID := uuid.New().String()
	now := time.Now()

	// Access token claims
	accessClaims := Claims{
		UserID:      userID,
		Email:       email,
		Name:        name,
		Roles:       roles,
		Permissions: permissions,
		TenantID:    tenantID,
		SessionID:   sessionID,
		DeviceID:    deviceID,
		IPAddress:   ipAddress,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID,
			Audience:  []string{j.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	// Create access token
	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken, err = accessTokenObj.SignedString(j.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	// Refresh token claims (minimal data)
	refreshClaims := Claims{
		UserID:    userID,
		TenantID:  tenantID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID,
			Audience:  []string{j.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(j.refreshExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	// Create refresh token
	refreshTokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshToken, err = refreshTokenObj.SignedString(j.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// ValidateToken validates and parses a JWT token
func (j *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// RefreshToken generates a new access token using a refresh token
func (j *JWTManager) RefreshToken(refreshTokenString string, user *User) (string, error) {
	refreshClaims, err := j.ValidateToken(refreshTokenString)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Verify this is a refresh token (should have minimal claims)
	if len(refreshClaims.Permissions) > 0 || len(refreshClaims.Roles) > 0 {
		return "", fmt.Errorf("invalid refresh token format")
	}

	// Generate new access token
	accessToken, _, err := j.GenerateTokenPair(
		user.ID,
		user.Email,
		user.Name,
		user.TenantID,
		user.Roles,
		user.GetPermissions(),
		refreshClaims.DeviceID,
		refreshClaims.IPAddress,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	return accessToken, nil
}

// ExtractTokenFromHeader extracts JWT token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is empty")
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) {
		return "", fmt.Errorf("invalid authorization header format")
	}

	if authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", fmt.Errorf("authorization header must start with 'Bearer '")
	}

	token := authHeader[len(bearerPrefix):]
	if token == "" {
		return "", fmt.Errorf("token is empty")
	}

	return token, nil
}

// TokenBlacklist interface for token revocation
type TokenBlacklist interface {
	IsBlacklisted(tokenID string) (bool, error)
	BlacklistToken(tokenID string, expiresAt time.Time) error
}

// ValidateTokenWithBlacklist validates token and checks blacklist
func (j *JWTManager) ValidateTokenWithBlacklist(tokenString string, blacklist TokenBlacklist) (*Claims, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Check if token is blacklisted
	if blacklist != nil {
		isBlacklisted, err := blacklist.IsBlacklisted(claims.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to check token blacklist: %w", err)
		}
		if isBlacklisted {
			return nil, fmt.Errorf("token has been revoked")
		}
	}

	return claims, nil
}