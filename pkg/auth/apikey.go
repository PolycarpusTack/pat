package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"
)

// FortressApiKeyService provides fortress-grade API key authentication
type FortressApiKeyService struct {
	apiKeyRepo   ApiKeyRepository
	auditRepo    AuditRepository
	rateLimiter  *FortressRateLimiter
}

// NewFortressApiKeyService creates a new fortress API key service
func NewFortressApiKeyService(apiKeyRepo ApiKeyRepository, auditRepo AuditRepository, rateLimiter *FortressRateLimiter) *FortressApiKeyService {
	return &FortressApiKeyService{
		apiKeyRepo:  apiKeyRepo,
		auditRepo:   auditRepo,
		rateLimiter: rateLimiter,
	}
}

// ApiKeyValidationResult represents the result of API key validation
type ApiKeyValidationResult struct {
	ApiKey      *ApiKey
	User        *User
	IsValid     bool
	FailReason  string
	RateLimited bool
}

// GuardValidateApiKey validates an API key with fortress-grade security
func (faks *FortressApiKeyService) GuardValidateApiKey(ctx context.Context, keyString string, ipAddress string, userAgent string) (*ApiKeyValidationResult, error) {
	result := &ApiKeyValidationResult{
		IsValid: false,
	}

	// Extract and validate key format
	keyID, keySecret, err := faks.extractKeyComponents(keyString)
	if err != nil {
		result.FailReason = "invalid_key_format"
		return result, nil // Don't return error to prevent information disclosure
	}

	// Check rate limiting first
	rateLimitKey := fmt.Sprintf("api_key:%s", keyID)
	if faks.rateLimiter != nil {
		allowed, remaining := faks.rateLimiter.SentinelCheckRate(rateLimitKey, 1000, time.Hour) // 1000 requests per hour default
		if !allowed {
			result.RateLimited = true
			result.FailReason = "rate_limited"
			faks.logSecurityEvent(ctx, "", "api_key.rate_limited", keyID, ipAddress, userAgent, map[string]interface{}{
				"remaining": remaining,
			})
			return result, nil
		}
	}

	// Get API key from repository
	apiKey, err := faks.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		if err == sql.ErrNoRows {
			result.FailReason = "key_not_found"
		} else {
			result.FailReason = "internal_error"
		}
		faks.logSecurityEvent(ctx, "", "api_key.validation_failed", keyID, ipAddress, userAgent, map[string]interface{}{
			"reason": result.FailReason,
		})
		return result, nil
	}

	// Check if key is active
	if !apiKey.IsActive {
		result.FailReason = "key_inactive"
		faks.logSecurityEvent(ctx, apiKey.UserID, "api_key.inactive_used", keyID, ipAddress, userAgent, nil)
		return result, nil
	}

	// Check expiration
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		result.FailReason = "key_expired"
		faks.logSecurityEvent(ctx, apiKey.UserID, "api_key.expired_used", keyID, ipAddress, userAgent, nil)
		return result, nil
	}

	// Validate key secret using constant-time comparison
	if !faks.sentinelValidateKeySecret(keySecret, apiKey.KeyHash) {
		result.FailReason = "invalid_key"
		faks.logSecurityEvent(ctx, apiKey.UserID, "api_key.invalid_secret", keyID, ipAddress, userAgent, nil)
		return result, nil
	}

	// Update last used timestamp
	now := time.Now()
	apiKey.LastUsedAt = &now
	if err := faks.apiKeyRepo.UpdateLastUsed(ctx, apiKey.ID, now); err != nil {
		// Log error but don't fail validation
		faks.logSecurityEvent(ctx, apiKey.UserID, "api_key.update_last_used_failed", keyID, ipAddress, userAgent, map[string]interface{}{
			"error": err.Error(),
		})
	}

	result.ApiKey = apiKey
	result.IsValid = true

	// Log successful validation
	faks.logSecurityEvent(ctx, apiKey.UserID, "api_key.validated", keyID, ipAddress, userAgent, nil)

	return result, nil
}

// CommanderGenerateApiKey generates a new API key with fortress-grade security
func (faks *FortressApiKeyService) CommanderGenerateApiKey(ctx context.Context, userID string, name string, permissions []string, rateLimit int, expiresAt *time.Time) (string, *ApiKey, error) {
	// Generate key ID (UUID)
	keyID := uuid.New().String()

	// Generate secure key secret (32 bytes)
	keySecret := make([]byte, 32)
	if _, err := rand.Read(keySecret); err != nil {
		return "", nil, fmt.Errorf("failed to generate key secret: %w", err)
	}

	// Encode key secret to base64
	keySecretB64 := base64.RawURLEncoding.EncodeToString(keySecret)

	// Create full key string: pat_keyID_keySecret
	fullKey := fmt.Sprintf("pat_%s_%s", keyID, keySecretB64)

	// Hash the key secret for storage
	keyHash, err := faks.guardHashKeySecret(keySecretB64)
	if err != nil {
		return "", nil, fmt.Errorf("failed to hash key secret: %w", err)
	}

	// Create key preview (first 8 chars of secret)
	keyPreview := fmt.Sprintf("pat_%s_%s...", keyID, keySecretB64[:8])

	// Create API key object
	apiKey := &ApiKey{
		ID:          keyID,
		UserID:      userID,
		Name:        name,
		KeyHash:     keyHash,
		KeyPreview:  keyPreview,
		Permissions: permissions,
		RateLimit:   rateLimit,
		IsActive:    true,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Save to repository
	if err := faks.apiKeyRepo.Create(ctx, apiKey); err != nil {
		return "", nil, fmt.Errorf("failed to create API key: %w", err)
	}

	// Log creation
	faks.logSecurityEvent(ctx, userID, "api_key.created", keyID, "", "", map[string]interface{}{
		"name":        name,
		"permissions": permissions,
		"rate_limit":  rateLimit,
		"expires_at":  expiresAt,
	})

	return fullKey, apiKey, nil
}

// GuardRevokeApiKey revokes an API key
func (faks *FortressApiKeyService) GuardRevokeApiKey(ctx context.Context, keyID string, userID string, reason string) error {
	// Get API key
	apiKey, err := faks.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to get API key: %w", err)
	}

	// Verify ownership
	if apiKey.UserID != userID {
		return fmt.Errorf("unauthorized: API key does not belong to user")
	}

	// Deactivate key
	apiKey.IsActive = false
	apiKey.UpdatedAt = time.Now()

	if err := faks.apiKeyRepo.Update(ctx, apiKey); err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	// Log revocation
	faks.logSecurityEvent(ctx, userID, "api_key.revoked", keyID, "", "", map[string]interface{}{
		"reason": reason,
	})

	return nil
}

// GuardRotateApiKey rotates an API key (creates new, deactivates old)
func (faks *FortressApiKeyService) GuardRotateApiKey(ctx context.Context, keyID string, userID string) (string, *ApiKey, error) {
	// Get existing API key
	existingKey, err := faks.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get existing API key: %w", err)
	}

	// Verify ownership
	if existingKey.UserID != userID {
		return "", nil, fmt.Errorf("unauthorized: API key does not belong to user")
	}

	// Create new API key with same properties
	newKey, newApiKey, err := faks.CommanderGenerateApiKey(
		ctx,
		userID,
		existingKey.Name+" (rotated)",
		existingKey.Permissions,
		existingKey.RateLimit,
		existingKey.ExpiresAt,
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create rotated API key: %w", err)
	}

	// Deactivate old key
	existingKey.IsActive = false
	existingKey.UpdatedAt = time.Now()

	if err := faks.apiKeyRepo.Update(ctx, existingKey); err != nil {
		// Log error but don't fail rotation
		faks.logSecurityEvent(ctx, userID, "api_key.rotation_cleanup_failed", keyID, "", "", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Log rotation
	faks.logSecurityEvent(ctx, userID, "api_key.rotated", keyID, "", "", map[string]interface{}{
		"old_key_id": keyID,
		"new_key_id": newApiKey.ID,
	})

	return newKey, newApiKey, nil
}

// SentinelListApiKeys lists API keys for a user
func (faks *FortressApiKeyService) SentinelListApiKeys(ctx context.Context, userID string) ([]*ApiKey, error) {
	return faks.apiKeyRepo.ListByUserID(ctx, userID)
}

// extractKeyComponents extracts key ID and secret from key string
func (faks *FortressApiKeyService) extractKeyComponents(keyString string) (string, string, error) {
	// Expected format: pat_keyID_keySecret
	if !strings.HasPrefix(keyString, "pat_") {
		return "", "", fmt.Errorf("invalid key prefix")
	}

	parts := strings.Split(keyString, "_")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid key format")
	}

	keyID := parts[1]
	keySecret := parts[2]

	// Validate key ID is a valid UUID
	if _, err := uuid.Parse(keyID); err != nil {
		return "", "", fmt.Errorf("invalid key ID format")
	}

	// Validate key secret length (should be 43 chars for base64-encoded 32 bytes)
	if len(keySecret) < 32 {
		return "", "", fmt.Errorf("invalid key secret length")
	}

	return keyID, keySecret, nil
}

// guardHashKeySecret hashes a key secret using scrypt
func (faks *FortressApiKeyService) guardHashKeySecret(keySecret string) (string, error) {
	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Use scrypt to hash the key secret
	hash, err := scrypt.Key([]byte(keySecret), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("failed to hash key: %w", err)
	}

	// Combine salt and hash
	combined := append(salt, hash...)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(combined), nil
}

// sentinelValidateKeySecret validates a key secret against its hash using constant-time comparison
func (faks *FortressApiKeyService) sentinelValidateKeySecret(keySecret, keyHash string) bool {
	// Decode the stored hash
	combined, err := base64.StdEncoding.DecodeString(keyHash)
	if err != nil || len(combined) != 48 { // 16 bytes salt + 32 bytes hash
		return false
	}

	salt := combined[:16]
	hash := combined[16:]

	// Hash the provided key secret
	candidateHash, err := scrypt.Key([]byte(keySecret), salt, 32768, 8, 1, 32)
	if err != nil {
		return false
	}

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(hash, candidateHash) == 1
}

// logSecurityEvent logs a security event for audit purposes
func (faks *FortressApiKeyService) logSecurityEvent(ctx context.Context, userID, action, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
	if faks.auditRepo == nil {
		return
	}

	auditLog := &AuditLog{
		ID:         uuid.New().String(),
		UserID:     userID,
		TenantID:   "", // Will be populated by caller if available
		Action:     action,
		Resource:   "api_key",
		ResourceID: resourceID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Metadata:   metadata,
		CreatedAt:  time.Now(),
	}

	// Fire and forget - don't block on audit logging
	go func() {
		if err := faks.auditRepo.Create(context.Background(), auditLog); err != nil {
			// Log error but don't fail the operation
			fmt.Printf("Failed to create audit log: %v\n", err)
		}
	}()
}

// FortressRateLimiter provides fortress-grade rate limiting
type FortressRateLimiter struct {
	// Implementation would use Redis or in-memory store
	// This is a placeholder for the interface
}

// SentinelCheckRate checks if a request is within rate limits
func (frl *FortressRateLimiter) SentinelCheckRate(key string, limit int, window time.Duration) (allowed bool, remaining int) {
	// Placeholder implementation
	// In production, this would use a sliding window or token bucket algorithm
	return true, limit - 1
}

// WatchtowerCleanup cleans up expired rate limit entries
func (frl *FortressRateLimiter) WatchtowerCleanup() {
	// Placeholder for cleanup logic
}

// NewFortressRateLimiter creates a new rate limiter
func NewFortressRateLimiter() *FortressRateLimiter {
	return &FortressRateLimiter{}
}