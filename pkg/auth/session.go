package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FortressSessionManager provides fortress-grade session management
type FortressSessionManager struct {
	sessionRepo     SessionRepository
	blacklistRepo   TokenBlacklist
	auditRepo       AuditRepository
	maxSessions     int
	sessionTimeout  time.Duration
	slidingExpiry   time.Duration
	requireSecure   bool
	sameSitePolicy  string
}

// SessionSecurityConfig configures session security settings
type SessionSecurityConfig struct {
	MaxConcurrentSessions int           `json:"max_concurrent_sessions"`
	SessionTimeout        time.Duration `json:"session_timeout"`
	SlidingExpiry        time.Duration `json:"sliding_expiry"`
	RequireSecure        bool          `json:"require_secure"`
	SameSitePolicy       string        `json:"same_site_policy"`
	SecureCookies        bool          `json:"secure_cookies"`
	HttpOnlyCookies      bool          `json:"http_only_cookies"`
	EnableIPValidation   bool          `json:"enable_ip_validation"`
	EnableUAValidation   bool          `json:"enable_ua_validation"`
}

// DefaultFortressSessionConfig returns default fortress session configuration
func DefaultFortressSessionConfig() *SessionSecurityConfig {
	return &SessionSecurityConfig{
		MaxConcurrentSessions: 5,
		SessionTimeout:        24 * time.Hour,
		SlidingExpiry:        30 * time.Minute,
		RequireSecure:        true,
		SameSitePolicy:       "Strict",
		SecureCookies:        true,
		HttpOnlyCookies:      true,
		EnableIPValidation:   true,
		EnableUAValidation:   false, // Can be fingerprinted, disabled by default
	}
}

// NewFortressSessionManager creates a new fortress session manager
func NewFortressSessionManager(
	sessionRepo SessionRepository,
	blacklistRepo TokenBlacklist,
	auditRepo AuditRepository,
	config *SessionSecurityConfig,
) *FortressSessionManager {
	if config == nil {
		config = DefaultFortressSessionConfig()
	}

	return &FortressSessionManager{
		sessionRepo:    sessionRepo,
		blacklistRepo:  blacklistRepo,
		auditRepo:      auditRepo,
		maxSessions:    config.MaxConcurrentSessions,
		sessionTimeout: config.SessionTimeout,
		slidingExpiry:  config.SlidingExpiry,
		requireSecure:  config.RequireSecure,
		sameSitePolicy: config.SameSitePolicy,
	}
}

// FortressSessionInfo contains session information with security metadata
type FortressSessionInfo struct {
	Session      *Session              `json:"session"`
	IsValid      bool                  `json:"is_valid"`
	SecurityInfo *SessionSecurityInfo  `json:"security_info"`
	Warnings     []string              `json:"warnings,omitempty"`
}

// SessionSecurityInfo contains security-related session information
type SessionSecurityInfo struct {
	IPAddress        string    `json:"ip_address"`
	UserAgent        string    `json:"user_agent"`
	DeviceFingerprint string   `json:"device_fingerprint,omitempty"`
	Location         string    `json:"location,omitempty"`
	LastActivity     time.Time `json:"last_activity"`
	CreatedAt        time.Time `json:"created_at"`
	IsSecure         bool      `json:"is_secure"`
	IsSuspicious     bool      `json:"is_suspicious"`
}

// GuardCreateSession creates a new fortress session with enhanced security
func (fsm *FortressSessionManager) GuardCreateSession(ctx context.Context, userID string, deviceID string, ipAddress string, userAgent string, rememberMe bool) (*Session, error) {
	// Validate input
	if userID == "" || ipAddress == "" {
		return nil, fmt.Errorf("invalid session parameters")
	}

	// Check concurrent session limits
	activeSessions, err := fsm.sessionRepo.GetActiveSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check active sessions: %w", err)
	}

	if len(activeSessions) >= fsm.maxSessions {
		// Terminate oldest session to make room
		oldestSession := fsm.findOldestSession(activeSessions)
		if oldestSession != nil {
			fsm.SentinelTerminateSession(ctx, oldestSession.ID, "session_limit_exceeded")
		}
	}

	// Generate secure refresh token
	refreshToken, err := fsm.generateSecureToken(64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Calculate expiry based on remember me setting
	var expiresAt time.Time
	if rememberMe {
		expiresAt = time.Now().Add(30 * 24 * time.Hour) // 30 days
	} else {
		expiresAt = time.Now().Add(fsm.sessionTimeout)
	}

	// Create session
	session := &Session{
		ID:           uuid.New().String(),
		UserID:       userID,
		DeviceID:     deviceID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		RefreshToken: fsm.hashToken(refreshToken),
		IsActive:     true,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Save session
	if err := fsm.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Store unhashed token in session for return (will not be persisted)
	session.RefreshToken = refreshToken

	// Log session creation
	fsm.logSecurityEvent(ctx, userID, "fortress.session.created", session.ID, ipAddress, userAgent, map[string]interface{}{
		"device_id":   deviceID,
		"remember_me": rememberMe,
		"expires_at":  expiresAt,
	})

	return session, nil
}

// SentinelValidateSession validates a session with comprehensive security checks
func (fsm *FortressSessionManager) SentinelValidateSession(ctx context.Context, sessionID string, refreshToken string, ipAddress string, userAgent string) (*FortressSessionInfo, error) {
	// Get session from repository
	session, err := fsm.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return &FortressSessionInfo{IsValid: false}, nil
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	sessionInfo := &FortressSessionInfo{
		Session: session,
		IsValid: false,
		SecurityInfo: &SessionSecurityInfo{
			IPAddress:    session.IPAddress,
			UserAgent:    session.UserAgent,
			LastActivity: session.UpdatedAt,
			CreatedAt:    session.CreatedAt,
		},
		Warnings: []string{},
	}

	// Check if session is active
	if !session.IsActive {
		sessionInfo.Warnings = append(sessionInfo.Warnings, "session_inactive")
		return sessionInfo, nil
	}

	// Check expiration
	if session.ExpiresAt.Before(time.Now()) {
		sessionInfo.Warnings = append(sessionInfo.Warnings, "session_expired")
		// Auto-cleanup expired session
		fsm.SentinelTerminateSession(ctx, sessionID, "expired")
		return sessionInfo, nil
	}

	// Validate refresh token
	if !fsm.validateTokenHash(refreshToken, session.RefreshToken) {
		sessionInfo.Warnings = append(sessionInfo.Warnings, "invalid_refresh_token")
		fsm.logSecurityEvent(ctx, session.UserID, "fortress.session.invalid_token", sessionID, ipAddress, userAgent, nil)
		return sessionInfo, nil
	}

	// Security validations
	securityWarnings := fsm.performSecurityChecks(session, ipAddress, userAgent)
	sessionInfo.Warnings = append(sessionInfo.Warnings, securityWarnings...)

	// Update session security info
	sessionInfo.SecurityInfo.IsSecure = len(securityWarnings) == 0
	sessionInfo.SecurityInfo.IsSuspicious = len(securityWarnings) > 1

	// If session passes all checks, update last activity
	if len(securityWarnings) == 0 {
		session.UpdatedAt = time.Now()
		// Extend expiry with sliding window if within grace period
		if time.Until(session.ExpiresAt) < fsm.slidingExpiry {
			session.ExpiresAt = time.Now().Add(fsm.sessionTimeout)
		}

		if err := fsm.sessionRepo.Update(ctx, session); err != nil {
			// Log error but don't fail validation
			fsm.logSecurityEvent(ctx, session.UserID, "fortress.session.update_failed", sessionID, ipAddress, userAgent, map[string]interface{}{
				"error": err.Error(),
			})
		}

		sessionInfo.IsValid = true
	}

	return sessionInfo, nil
}

// GuardRefreshSession refreshes a session and generates new tokens
func (fsm *FortressSessionManager) GuardRefreshSession(ctx context.Context, sessionID string, refreshToken string) (*Session, error) {
	// Validate current session
	sessionInfo, err := fsm.SentinelValidateSession(ctx, sessionID, refreshToken, "", "")
	if err != nil {
		return nil, fmt.Errorf("session validation failed: %w", err)
	}

	if !sessionInfo.IsValid {
		return nil, fmt.Errorf("invalid session")
	}

	// Generate new refresh token
	newRefreshToken, err := fsm.generateSecureToken(64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	// Update session
	session := sessionInfo.Session
	oldTokenHash := session.RefreshToken
	session.RefreshToken = fsm.hashToken(newRefreshToken)
	session.UpdatedAt = time.Now()
	session.ExpiresAt = time.Now().Add(fsm.sessionTimeout)

	if err := fsm.sessionRepo.Update(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	// Blacklist old refresh token
	if fsm.blacklistRepo != nil {
		tokenID := fsm.generateTokenID(oldTokenHash)
		fsm.blacklistRepo.BlacklistToken(tokenID, time.Now().Add(24*time.Hour))
	}

	// Store unhashed token for return
	session.RefreshToken = newRefreshToken

	// Log session refresh
	fsm.logSecurityEvent(ctx, session.UserID, "fortress.session.refreshed", sessionID, "", "", nil)

	return session, nil
}

// SentinelTerminateSession terminates a session
func (fsm *FortressSessionManager) SentinelTerminateSession(ctx context.Context, sessionID string, reason string) error {
	// Get session for audit logging
	session, err := fsm.sessionRepo.GetByID(ctx, sessionID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to get session for termination: %w", err)
	}

	// Delete session
	if err := fsm.sessionRepo.Delete(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Blacklist refresh token if session exists
	if session != nil {
		if fsm.blacklistRepo != nil {
			tokenID := fsm.generateTokenID(session.RefreshToken)
			fsm.blacklistRepo.BlacklistToken(tokenID, time.Now().Add(24*time.Hour))
		}

		// Log session termination
		fsm.logSecurityEvent(ctx, session.UserID, "fortress.session.terminated", sessionID, "", "", map[string]interface{}{
			"reason": reason,
		})
	}

	return nil
}

// CommanderTerminateAllSessions terminates all sessions for a user
func (fsm *FortressSessionManager) CommanderTerminateAllSessions(ctx context.Context, userID string, reason string) error {
	// Get all active sessions for the user
	sessions, err := fsm.sessionRepo.GetActiveSessions(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Terminate each session
	for _, session := range sessions {
		if err := fsm.SentinelTerminateSession(ctx, session.ID, reason); err != nil {
			// Log error but continue with other sessions
			fsm.logSecurityEvent(ctx, userID, "fortress.session.termination_failed", session.ID, "", "", map[string]interface{}{
				"error":  err.Error(),
				"reason": reason,
			})
		}
	}

	// Bulk delete from repository
	if err := fsm.sessionRepo.DeleteByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to bulk delete user sessions: %w", err)
	}

	// Log bulk termination
	fsm.logSecurityEvent(ctx, userID, "fortress.session.terminated_all", "", "", "", map[string]interface{}{
		"reason":        reason,
		"session_count": len(sessions),
	})

	return nil
}

// WatchtowerListActiveSessions lists active sessions for a user
func (fsm *FortressSessionManager) WatchtowerListActiveSessions(ctx context.Context, userID string) ([]*FortressSessionInfo, error) {
	sessions, err := fsm.sessionRepo.GetActiveSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}

	var sessionInfos []*FortressSessionInfo
	for _, session := range sessions {
		securityInfo := &SessionSecurityInfo{
			IPAddress:    session.IPAddress,
			UserAgent:    session.UserAgent,
			LastActivity: session.UpdatedAt,
			CreatedAt:    session.CreatedAt,
			IsSecure:     true, // Assume secure unless proven otherwise
		}

		sessionInfo := &FortressSessionInfo{
			Session:      session,
			IsValid:      session.IsActive && session.ExpiresAt.After(time.Now()),
			SecurityInfo: securityInfo,
		}

		sessionInfos = append(sessionInfos, sessionInfo)
	}

	return sessionInfos, nil
}

// WatchtowerCleanupExpiredSessions removes expired sessions
func (fsm *FortressSessionManager) WatchtowerCleanupExpiredSessions(ctx context.Context) (int, error) {
	// This would typically be implemented in the repository layer
	// For now, return 0 as placeholder
	return 0, nil
}

// performSecurityChecks performs various security checks on session
func (fsm *FortressSessionManager) performSecurityChecks(session *Session, currentIP, currentUA string) []string {
	var warnings []string

	// IP address validation
	if fsm.requireSecure && currentIP != "" {
		if !fsm.validateIPAddress(session.IPAddress, currentIP) {
			warnings = append(warnings, "ip_address_mismatch")
		}
	}

	// User agent validation (basic)
	if currentUA != "" && session.UserAgent != "" {
		if !fsm.validateUserAgent(session.UserAgent, currentUA) {
			warnings = append(warnings, "user_agent_suspicious")
		}
	}

	// Session age check
	if time.Since(session.CreatedAt) > 30*24*time.Hour { // 30 days
		warnings = append(warnings, "session_too_old")
	}

	// Activity check
	if time.Since(session.UpdatedAt) > 7*24*time.Hour { // 7 days
		warnings = append(warnings, "session_inactive_too_long")
	}

	return warnings
}

// validateIPAddress performs IP address validation
func (fsm *FortressSessionManager) validateIPAddress(originalIP, currentIP string) bool {
	if originalIP == currentIP {
		return true
	}

	// Parse IPs
	origIP := net.ParseIP(originalIP)
	currIP := net.ParseIP(currentIP)

	if origIP == nil || currIP == nil {
		return false
	}

	// Allow same subnet for IPv4 (relaxed validation)
	if origIP.To4() != nil && currIP.To4() != nil {
		origNet := &net.IPNet{IP: origIP.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
		return origNet.Contains(currIP)
	}

	// Strict validation for IPv6
	return false
}

// validateUserAgent performs basic user agent validation
func (fsm *FortressSessionManager) validateUserAgent(originalUA, currentUA string) bool {
	// Basic check - allow minor version differences
	if originalUA == currentUA {
		return true
	}

	// Extract browser and major version
	origBrowser := fsm.extractBrowserInfo(originalUA)
	currBrowser := fsm.extractBrowserInfo(currentUA)

	return origBrowser == currBrowser
}

// extractBrowserInfo extracts basic browser information from user agent
func (fsm *FortressSessionManager) extractBrowserInfo(userAgent string) string {
	ua := strings.ToLower(userAgent)
	
	if strings.Contains(ua, "chrome") {
		return "chrome"
	} else if strings.Contains(ua, "firefox") {
		return "firefox"
	} else if strings.Contains(ua, "safari") {
		return "safari"
	} else if strings.Contains(ua, "edge") {
		return "edge"
	}
	
	return "unknown"
}

// findOldestSession finds the oldest session from a list
func (fsm *FortressSessionManager) findOldestSession(sessions []*Session) *Session {
	if len(sessions) == 0 {
		return nil
	}

	oldest := sessions[0]
	for _, session := range sessions[1:] {
		if session.UpdatedAt.Before(oldest.UpdatedAt) {
			oldest = session
		}
	}

	return oldest
}

// generateSecureToken generates a secure random token
func (fsm *FortressSessionManager) generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// hashToken creates a SHA-256 hash of a token
func (fsm *FortressSessionManager) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// validateTokenHash validates a token against its hash
func (fsm *FortressSessionManager) validateTokenHash(token, hash string) bool {
	expectedHash := fsm.hashToken(token)
	return expectedHash == hash
}

// generateTokenID generates a consistent token ID for blacklisting
func (fsm *FortressSessionManager) generateTokenID(tokenHash string) string {
	return fmt.Sprintf("session_token_%s", tokenHash[:16])
}

// logSecurityEvent logs a security event for audit purposes
func (fsm *FortressSessionManager) logSecurityEvent(ctx context.Context, userID, action, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
	if fsm.auditRepo == nil {
		return
	}

	auditLog := &AuditLog{
		ID:         uuid.New().String(),
		UserID:     userID,
		TenantID:   "", // Will be populated by caller if available
		Action:     action,
		Resource:   "fortress_session",
		ResourceID: resourceID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Metadata:   metadata,
		CreatedAt:  time.Now(),
	}

	// Fire and forget - don't block on audit logging
	go func() {
		if err := fsm.auditRepo.Create(context.Background(), auditLog); err != nil {
			// Log error but don't fail the operation
			fmt.Printf("Failed to create audit log: %v\n", err)
		}
	}()
}