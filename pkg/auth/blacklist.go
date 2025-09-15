package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FortressTokenBlacklist provides fortress-grade token blacklisting
type FortressTokenBlacklist struct {
	blacklistedTokens map[string]time.Time
	mutex             sync.RWMutex
	auditRepo         AuditRepository
	cleanupInterval   time.Duration
	maxTokens         int
}

// BlacklistedToken represents a blacklisted token entry
type BlacklistedToken struct {
	ID         string    `json:"id" db:"id"`
	TokenID    string    `json:"token_id" db:"token_id"`
	UserID     string    `json:"user_id" db:"user_id"`
	TokenType  string    `json:"token_type" db:"token_type"` // "access", "refresh", "api_key"
	Reason     string    `json:"reason" db:"reason"`
	ExpiresAt  time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// NewFortressTokenBlacklist creates a new fortress token blacklist
func NewFortressTokenBlacklist(auditRepo AuditRepository) *FortressTokenBlacklist {
	ftb := &FortressTokenBlacklist{
		blacklistedTokens: make(map[string]time.Time),
		auditRepo:         auditRepo,
		cleanupInterval:   1 * time.Hour,
		maxTokens:         10000, // Prevent memory exhaustion
	}

	// Start cleanup routine
	go ftb.watchtowerCleanupRoutine()

	return ftb
}

// IsBlacklisted checks if a token is blacklisted
func (ftb *FortressTokenBlacklist) IsBlacklisted(tokenID string) (bool, error) {
	if tokenID == "" {
		return false, fmt.Errorf("token ID cannot be empty")
	}

	ftb.mutex.RLock()
	expiresAt, exists := ftb.blacklistedTokens[tokenID]
	ftb.mutex.RUnlock()

	if !exists {
		return false, nil
	}

	// Check if blacklist entry has expired
	if time.Now().After(expiresAt) {
		// Remove expired entry
		ftb.mutex.Lock()
		delete(ftb.blacklistedTokens, tokenID)
		ftb.mutex.Unlock()
		return false, nil
	}

	return true, nil
}

// BlacklistToken adds a token to the blacklist
func (ftb *FortressTokenBlacklist) BlacklistToken(tokenID string, expiresAt time.Time) error {
	if tokenID == "" {
		return fmt.Errorf("token ID cannot be empty")
	}

	ftb.mutex.Lock()
	defer ftb.mutex.Unlock()

	// Check if we're at capacity
	if len(ftb.blacklistedTokens) >= ftb.maxTokens {
		// Trigger cleanup of expired tokens
		ftb.cleanupExpiredTokensUnsafe()
		
		// If still at capacity, remove oldest entries
		if len(ftb.blacklistedTokens) >= ftb.maxTokens {
			ftb.removeOldestTokensUnsafe(ftb.maxTokens / 10) // Remove 10%
		}
	}

	ftb.blacklistedTokens[tokenID] = expiresAt

	// Log blacklist event
	ftb.logBlacklistEvent("fortress.token.blacklisted", tokenID, "", map[string]interface{}{
		"expires_at": expiresAt,
	})

	return nil
}

// GuardBlacklistUserTokens blacklists all tokens for a user
func (ftb *FortressTokenBlacklist) GuardBlacklistUserTokens(userID string, reason string, duration time.Duration) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	expiresAt := time.Now().Add(duration)
	
	// Create a wildcard entry for the user
	userTokenPattern := fmt.Sprintf("user:%s:*", userID)
	
	ftb.mutex.Lock()
	ftb.blacklistedTokens[userTokenPattern] = expiresAt
	ftb.mutex.Unlock()

	// Log user token blacklist event
	ftb.logBlacklistEvent("fortress.token.user_blacklisted", userTokenPattern, userID, map[string]interface{}{
		"reason":     reason,
		"duration":   duration,
		"expires_at": expiresAt,
	})

	return nil
}

// SentinelRemoveFromBlacklist removes a token from the blacklist
func (ftb *FortressTokenBlacklist) SentinelRemoveFromBlacklist(tokenID string, reason string) error {
	if tokenID == "" {
		return fmt.Errorf("token ID cannot be empty")
	}

	ftb.mutex.Lock()
	_, existed := ftb.blacklistedTokens[tokenID]
	delete(ftb.blacklistedTokens, tokenID)
	ftb.mutex.Unlock()

	if existed {
		// Log removal event
		ftb.logBlacklistEvent("fortress.token.unblacklisted", tokenID, "", map[string]interface{}{
			"reason": reason,
		})
	}

	return nil
}

// WatchtowerListBlacklistedTokens returns a list of blacklisted tokens (for monitoring)
func (ftb *FortressTokenBlacklist) WatchtowerListBlacklistedTokens() map[string]time.Time {
	ftb.mutex.RLock()
	defer ftb.mutex.RUnlock()

	// Create a copy to avoid external modification
	result := make(map[string]time.Time, len(ftb.blacklistedTokens))
	for tokenID, expiresAt := range ftb.blacklistedTokens {
		result[tokenID] = expiresAt
	}

	return result
}

// WatchtowerCleanupExpiredTokens manually triggers cleanup of expired tokens
func (ftb *FortressTokenBlacklist) WatchtowerCleanupExpiredTokens() int {
	ftb.mutex.Lock()
	defer ftb.mutex.Unlock()

	return ftb.cleanupExpiredTokensUnsafe()
}

// watchtowerCleanupRoutine runs periodic cleanup of expired tokens
func (ftb *FortressTokenBlacklist) watchtowerCleanupRoutine() {
	ticker := time.NewTicker(ftb.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cleaned := ftb.WatchtowerCleanupExpiredTokens()
		if cleaned > 0 {
			ftb.logBlacklistEvent("fortress.token.cleanup", "", "", map[string]interface{}{
				"cleaned_tokens": cleaned,
			})
		}
	}
}

// cleanupExpiredTokensUnsafe removes expired tokens (must be called with mutex held)
func (ftb *FortressTokenBlacklist) cleanupExpiredTokensUnsafe() int {
	now := time.Now()
	cleaned := 0

	for tokenID, expiresAt := range ftb.blacklistedTokens {
		if now.After(expiresAt) {
			delete(ftb.blacklistedTokens, tokenID)
			cleaned++
		}
	}

	return cleaned
}

// removeOldestTokensUnsafe removes the oldest tokens (must be called with mutex held)
func (ftb *FortressTokenBlacklist) removeOldestTokensUnsafe(count int) {
	if len(ftb.blacklistedTokens) <= count {
		return
	}

	// Find tokens sorted by expiration time
	type tokenExpiry struct {
		tokenID   string
		expiresAt time.Time
	}

	tokens := make([]tokenExpiry, 0, len(ftb.blacklistedTokens))
	for tokenID, expiresAt := range ftb.blacklistedTokens {
		tokens = append(tokens, tokenExpiry{tokenID: tokenID, expiresAt: expiresAt})
	}

	// Sort by expiration time (earliest first)
	for i := 0; i < len(tokens)-1; i++ {
		for j := i + 1; j < len(tokens); j++ {
			if tokens[i].expiresAt.After(tokens[j].expiresAt) {
				tokens[i], tokens[j] = tokens[j], tokens[i]
			}
		}
	}

	// Remove oldest tokens
	for i := 0; i < count && i < len(tokens); i++ {
		delete(ftb.blacklistedTokens, tokens[i].tokenID)
	}
}

// logBlacklistEvent logs a blacklist event for audit purposes
func (ftb *FortressTokenBlacklist) logBlacklistEvent(action, tokenID, userID string, metadata map[string]interface{}) {
	if ftb.auditRepo == nil {
		return
	}

	auditLog := &AuditLog{
		ID:         uuid.New().String(),
		UserID:     userID,
		TenantID:   "", // Will be populated by caller if available
		Action:     action,
		Resource:   "fortress_token_blacklist",
		ResourceID: tokenID,
		IPAddress:  "",
		UserAgent:  "",
		Metadata:   metadata,
		CreatedAt:  time.Now(),
	}

	// Fire and forget - don't block on audit logging
	go func() {
		if err := ftb.auditRepo.Create(context.Background(), auditLog); err != nil {
			// Log error but don't fail the operation
			fmt.Printf("Failed to create blacklist audit log: %v\n", err)
		}
	}()
}

// FortressTokenBlacklistConfig provides configuration for the blacklist
type FortressTokenBlacklistConfig struct {
	MaxTokens       int           `json:"max_tokens"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// DefaultFortressTokenBlacklistConfig returns default configuration
func DefaultFortressTokenBlacklistConfig() *FortressTokenBlacklistConfig {
	return &FortressTokenBlacklistConfig{
		MaxTokens:       10000,
		CleanupInterval: 1 * time.Hour,
	}
}

// GetStats returns statistics about the blacklist
func (ftb *FortressTokenBlacklist) GetStats() map[string]interface{} {
	ftb.mutex.RLock()
	defer ftb.mutex.RUnlock()

	now := time.Now()
	activeTokens := 0
	expiredTokens := 0

	for _, expiresAt := range ftb.blacklistedTokens {
		if now.After(expiresAt) {
			expiredTokens++
		} else {
			activeTokens++
		}
	}

	return map[string]interface{}{
		"total_tokens":   len(ftb.blacklistedTokens),
		"active_tokens":  activeTokens,
		"expired_tokens": expiredTokens,
		"max_capacity":   ftb.maxTokens,
		"capacity_used":  float64(len(ftb.blacklistedTokens)) / float64(ftb.maxTokens) * 100,
	}
}

// CommanderEmergencyBlacklist adds emergency blacklist functionality
func (ftb *FortressTokenBlacklist) CommanderEmergencyBlacklist(pattern string, duration time.Duration, reason string) error {
	if pattern == "" {
		return fmt.Errorf("blacklist pattern cannot be empty")
	}

	expiresAt := time.Now().Add(duration)
	emergencyTokenID := fmt.Sprintf("emergency:%s:%d", pattern, time.Now().Unix())

	ftb.mutex.Lock()
	ftb.blacklistedTokens[emergencyTokenID] = expiresAt
	ftb.mutex.Unlock()

	// Log emergency blacklist event
	ftb.logBlacklistEvent("fortress.token.emergency_blacklist", emergencyTokenID, "", map[string]interface{}{
		"pattern":    pattern,
		"reason":     reason,
		"duration":   duration,
		"expires_at": expiresAt,
		"emergency":  true,
	})

	return nil
}

// Enhanced pattern matching for blacklist checks
func (ftb *FortressTokenBlacklist) isTokenMatchingPattern(tokenID string, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	// User-based patterns
	if strings.HasPrefix(pattern, "user:") && strings.HasSuffix(pattern, ":*") {
		userID := pattern[5 : len(pattern)-2] // Extract user ID
		return strings.Contains(tokenID, userID)
	}

	// Exact match
	return tokenID == pattern
}

// Enhanced IsBlacklisted with pattern matching
func (ftb *FortressTokenBlacklist) IsBlacklistedWithPatterns(tokenID string) (bool, error) {
	if tokenID == "" {
		return false, fmt.Errorf("token ID cannot be empty")
	}

	ftb.mutex.RLock()
	defer ftb.mutex.RUnlock()

	now := time.Now()

	// Check all blacklist entries for matches
	for pattern, expiresAt := range ftb.blacklistedTokens {
		// Skip expired entries
		if now.After(expiresAt) {
			continue
		}

		// Check if token matches pattern
		if ftb.isTokenMatchingPattern(tokenID, pattern) {
			return true, nil
		}
	}

	return false, nil
}