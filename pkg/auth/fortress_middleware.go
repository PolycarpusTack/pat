package auth

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// FortressAuthMiddleware provides fortress-grade authentication middleware
type FortressAuthMiddleware struct {
	jwtManager      *JWTManager
	blacklist       TokenBlacklist
	userService     UserService
	tenantService   TenantService
	apiKeyService   *FortressApiKeyService
	sessionManager  *FortressSessionManager
	roleManager     *FortressRoleManager
	auditRepo       AuditRepository
	rateLimiters    map[string]*rate.Limiter
	rlMutex         sync.RWMutex
	securityConfig  *SecurityConfig
}

// SecurityConfig defines fortress security settings
type SecurityConfig struct {
	EnableRateLimit        bool          `json:"enable_rate_limit"`
	MaxRequestsPerMinute   int           `json:"max_requests_per_minute"`
	MaxRequestsPerHour     int           `json:"max_requests_per_hour"`
	EnableSecurityHeaders  bool          `json:"enable_security_headers"`
	EnableAuditLogging     bool          `json:"enable_audit_logging"`
	BlockSuspiciousIPs     bool          `json:"block_suspicious_ips"`
	RequireMFAForAdmin     bool          `json:"require_mfa_for_admin"`
	SessionTimeout         time.Duration `json:"session_timeout"`
	JWTTimeout             time.Duration `json:"jwt_timeout"`
	BruteForceThreshold    int           `json:"brute_force_threshold"`
	BruteForceWindow       time.Duration `json:"brute_force_window"`
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		EnableRateLimit:        true,
		MaxRequestsPerMinute:   100,
		MaxRequestsPerHour:     1000,
		EnableSecurityHeaders:  true,
		EnableAuditLogging:     true,
		BlockSuspiciousIPs:     true,
		RequireMFAForAdmin:     true,
		SessionTimeout:         24 * time.Hour,
		JWTTimeout:             15 * time.Minute,
		BruteForceThreshold:    5,
		BruteForceWindow:       15 * time.Minute,
	}
}

// NewFortressAuthMiddleware creates a new fortress authentication middleware
func NewFortressAuthMiddleware(
	jwtManager *JWTManager,
	blacklist TokenBlacklist,
	userService UserService,
	tenantService TenantService,
	apiKeyService *FortressApiKeyService,
	sessionManager *FortressSessionManager,
	roleManager *FortressRoleManager,
	auditRepo AuditRepository,
	config *SecurityConfig,
) *FortressAuthMiddleware {
	if config == nil {
		config = DefaultSecurityConfig()
	}

	return &FortressAuthMiddleware{
		jwtManager:     jwtManager,
		blacklist:      blacklist,
		userService:    userService,
		tenantService:  tenantService,
		apiKeyService:  apiKeyService,
		sessionManager: sessionManager,
		roleManager:    roleManager,
		auditRepo:      auditRepo,
		rateLimiters:   make(map[string]*rate.Limiter),
		securityConfig: config,
	}
}

// GuardRequireAuth middleware that requires fortress authentication
func (fam *FortressAuthMiddleware) GuardRequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Apply security headers first
		if fam.securityConfig.EnableSecurityHeaders {
			fam.applySecurityHeaders(c)
		}

		// Apply rate limiting first
		if fam.securityConfig.EnableRateLimit {
			if !fam.watchtowerCheckRateLimit(c) {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "Rate limit exceeded",
					"code":  "FORTRESS_RATE_LIMIT_EXCEEDED",
				})
				c.Abort()
				return
			}
		}

		// Check for API key authentication first
		apiKey := c.GetHeader("X-API-Key")
		if apiKey != "" {
			fam.handleAPIKeyAuth(c, apiKey)
			return
		}

		// Handle JWT authentication
		token, err := ExtractTokenFromHeader(c.GetHeader("Authorization"))
		if err != nil {
			fam.logSecurityEvent(c, "", "fortress.auth.no_token", "", map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Missing or invalid authorization header",
				"code":  "FORTRESS_AUTH_REQUIRED",
			})
			c.Abort()
			return
		}

		claims, err := fam.jwtManager.ValidateTokenWithBlacklist(token, fam.blacklist)
		if err != nil {
			fam.logSecurityEvent(c, "", "fortress.auth.invalid_token", "", map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
				"code":  "FORTRESS_TOKEN_INVALID",
			})
			c.Abort()
			return
		}

		// Get user from database to ensure they still exist and are active
		user, err := fam.userService.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil {
			fam.logSecurityEvent(c, claims.UserID, "fortress.auth.user_not_found", claims.UserID, map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User account not found",
				"code":  "FORTRESS_USER_NOT_FOUND",
			})
			c.Abort()
			return
		}

		if !user.IsActive {
			fam.logSecurityEvent(c, user.ID, "fortress.auth.user_inactive", user.ID, nil)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User account is inactive",
				"code":  "FORTRESS_USER_INACTIVE",
			})
			c.Abort()
			return
		}

		// Get tenant information
		tenant, err := fam.tenantService.GetTenantByID(c.Request.Context(), claims.TenantID)
		if err != nil {
			fam.logSecurityEvent(c, user.ID, "fortress.auth.tenant_not_found", claims.TenantID, map[string]interface{}{
				"error": err.Error(),
			})
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Tenant not found",
				"code":  "FORTRESS_TENANT_NOT_FOUND",
			})
			c.Abort()
			return
		}

		if !tenant.IsActive {
			fam.logSecurityEvent(c, user.ID, "fortress.auth.tenant_inactive", tenant.ID, nil)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Tenant account is inactive",
				"code":  "FORTRESS_TENANT_INACTIVE",
			})
			c.Abort()
			return
		}

		// Check MFA requirements for high-privilege roles
		if fam.securityConfig.RequireMFAForAdmin && fam.requiresMFACheck(user) && !user.MFAEnabled {
			fam.logSecurityEvent(c, user.ID, "fortress.auth.mfa_required", user.ID, nil)
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Multi-factor authentication required for this role",
				"code":  "FORTRESS_MFA_REQUIRED",
			})
			c.Abort()
			return
		}

		// Add fortress context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)
		c.Set(string(TenantContextKey), tenant)
		c.Set("fortress_auth_method", "jwt")
		c.Set("fortress_security_level", fam.calculateSecurityLevel(user, claims))

		// Log successful authentication
		fam.logSecurityEvent(c, user.ID, "fortress.auth.success", user.ID, map[string]interface{}{
			"method": "jwt",
			"roles":  user.Roles,
		})

		c.Next()
	}
}

// SentinelRequirePermission middleware that requires specific fortress permission
func (fam *FortressAuthMiddleware) SentinelRequirePermission(permission FortressPermission) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(string(UserContextKey))
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"code":  "FORTRESS_AUTH_REQUIRED",
			})
			c.Abort()
			return
		}

		u := user.(*User)

		// Use fortress role manager for permission validation
		if !fam.roleManager.GuardValidatePermission(u, permission) {
			fam.logSecurityEvent(c, u.ID, "fortress.auth.permission_denied", string(permission), map[string]interface{}{
				"required_permission": permission,
				"user_roles":          u.Roles,
			})
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Fortress permission required: %s", permission),
				"code":  "FORTRESS_PERMISSION_DENIED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GuardRequireRole middleware that requires specific fortress role
func (fam *FortressAuthMiddleware) GuardRequireRole(role FortressRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(string(UserContextKey))
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"code":  "FORTRESS_AUTH_REQUIRED",
			})
			c.Abort()
			return
		}

		u := user.(*User)
		if !fam.roleManager.SentinelValidateRole(u, role) {
			fam.logSecurityEvent(c, u.ID, "fortress.auth.role_denied", string(role), map[string]interface{}{
				"required_role": role,
				"user_roles":    u.Roles,
			})
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Fortress role required: %s", role),
				"code":  "FORTRESS_ROLE_DENIED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// WatchtowerOptionalAuth middleware that optionally extracts user info
func (fam *FortressAuthMiddleware) WatchtowerOptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Try API key first
		apiKey := c.GetHeader("X-API-Key")
		if apiKey != "" {
			if result, err := fam.apiKeyService.GuardValidateApiKey(c.Request.Context(), apiKey, c.ClientIP(), c.Request.UserAgent()); err == nil && result.IsValid {
				if user, err := fam.userService.GetUserByID(c.Request.Context(), result.ApiKey.UserID); err == nil {
					c.Set(string(UserContextKey), user)
					c.Set("fortress_auth_method", "api_key")
				}
			}
			c.Next()
			return
		}

		token, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			c.Next()
			return
		}

		claims, err := fam.jwtManager.ValidateTokenWithBlacklist(token, fam.blacklist)
		if err != nil {
			c.Next()
			return
		}

		user, err := fam.userService.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil {
			c.Next()
			return
		}

		if !user.IsActive {
			c.Next()
			return
		}

		tenant, err := fam.tenantService.GetTenantByID(c.Request.Context(), claims.TenantID)
		if err != nil {
			c.Next()
			return
		}

		if !tenant.IsActive {
			c.Next()
			return
		}

		// Add to context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)
		c.Set(string(TenantContextKey), tenant)
		c.Set("fortress_auth_method", "jwt")

		c.Next()
	}
}

// GuardAPIKeyAuth middleware for fortress API key authentication
func (fam *FortressAuthMiddleware) GuardAPIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Fortress API key required",
				"code":  "FORTRESS_API_KEY_REQUIRED",
			})
			c.Abort()
			return
		}

		fam.handleAPIKeyAuth(c, apiKey)
	}
}

// WatchtowerRateLimit applies rate limiting
func (fam *FortressAuthMiddleware) WatchtowerRateLimit(requestsPerMinute int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !fam.watchtowerCheckRateLimit(c) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"code":  "FORTRESS_RATE_LIMIT_EXCEEDED",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// handleAPIKeyAuth handles API key authentication
func (fam *FortressAuthMiddleware) handleAPIKeyAuth(c *gin.Context, apiKey string) {
	result, err := fam.apiKeyService.GuardValidateApiKey(
		c.Request.Context(),
		apiKey,
		c.ClientIP(),
		c.Request.UserAgent(),
	)

	if err != nil {
		fam.logSecurityEvent(c, "", "fortress.auth.api_key_error", "", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Authentication service unavailable",
			"code":  "FORTRESS_AUTH_SERVICE_ERROR",
		})
		c.Abort()
		return
	}

	if !result.IsValid {
		if result.RateLimited {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "API key rate limit exceeded",
				"code":  "FORTRESS_API_KEY_RATE_LIMITED",
			})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key",
				"code":  "FORTRESS_API_KEY_INVALID",
			})
		}
		c.Abort()
		return
	}

	// Get user associated with API key
	user, err := fam.userService.GetUserByID(c.Request.Context(), result.ApiKey.UserID)
	if err != nil {
		fam.logSecurityEvent(c, result.ApiKey.UserID, "fortress.auth.api_key_user_not_found", result.ApiKey.UserID, map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "API key user not found",
			"code":  "FORTRESS_API_KEY_USER_NOT_FOUND",
		})
		c.Abort()
		return
	}

	if !user.IsActive {
		fam.logSecurityEvent(c, user.ID, "fortress.auth.api_key_user_inactive", user.ID, nil)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "API key user is inactive",
			"code":  "FORTRESS_API_KEY_USER_INACTIVE",
		})
		c.Abort()
		return
	}

	// Get tenant if specified
	var tenant *Tenant
	if user.TenantID != "" {
		tenant, err = fam.tenantService.GetTenantByID(c.Request.Context(), user.TenantID)
		if err != nil || !tenant.IsActive {
			fam.logSecurityEvent(c, user.ID, "fortress.auth.api_key_tenant_invalid", user.TenantID, map[string]interface{}{
				"error": err,
			})
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "API key tenant is invalid or inactive",
				"code":  "FORTRESS_API_KEY_TENANT_INVALID",
			})
			c.Abort()
			return
		}
	}

	// Set context
	c.Set(string(UserContextKey), user)
	if tenant != nil {
		c.Set(string(TenantContextKey), tenant)
	}
	c.Set("fortress_auth_method", "api_key")
	c.Set("fortress_api_key", result.ApiKey)
	c.Set("fortress_security_level", fam.calculateAPIKeySecurityLevel(result.ApiKey))

	// Log successful authentication
	fam.logSecurityEvent(c, user.ID, "fortress.auth.api_key_success", result.ApiKey.ID, map[string]interface{}{
		"api_key_name": result.ApiKey.Name,
		"permissions":  result.ApiKey.Permissions,
	})

	c.Next()
}

// watchtowerCheckRateLimit checks rate limits for requests
func (fam *FortressAuthMiddleware) watchtowerCheckRateLimit(c *gin.Context) bool {
	if !fam.securityConfig.EnableRateLimit {
		return true
	}

	clientIP := c.ClientIP()
	key := fmt.Sprintf("rate_limit:%s", clientIP)

	fam.rlMutex.RLock()
	limiter, exists := fam.rateLimiters[key]
	fam.rlMutex.RUnlock()

	if !exists {
		fam.rlMutex.Lock()
		limiter, exists = fam.rateLimiters[key]
		if !exists {
			// Create rate limiter: requests per minute
			limiter = rate.NewLimiter(rate.Limit(fam.securityConfig.MaxRequestsPerMinute)/60, fam.securityConfig.MaxRequestsPerMinute)
			fam.rateLimiters[key] = limiter
		}
		fam.rlMutex.Unlock()
	}

	if !limiter.Allow() {
		fam.logSecurityEvent(c, "", "fortress.rate_limit.exceeded", clientIP, map[string]interface{}{
			"limit": fam.securityConfig.MaxRequestsPerMinute,
		})
		return false
	}

	return true
}

// applySecurityHeaders applies fortress security headers
func (fam *FortressAuthMiddleware) applySecurityHeaders(c *gin.Context) {
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header().Set("X-Frame-Options", "DENY")
	c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
	c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:")
	c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	c.Writer.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	c.Writer.Header().Set("X-Fortress-Protected", "true")
	c.Writer.Header().Set("X-Fortress-Version", "2.0")
}

// requiresMFACheck determines if user requires MFA
func (fam *FortressAuthMiddleware) requiresMFACheck(user *User) bool {
	// Check if user has high-privilege roles requiring MFA
	fortressRoles := fam.roleManager.convertLegacyRoles(user.Roles)
	for _, role := range fortressRoles {
		if roleDef, exists := fam.roleManager.GetFortressRoleDefinition(role); exists {
			if roleDef.RequiresMFA {
				return true
			}
		}
	}
	return false
}

// calculateSecurityLevel calculates security level for JWT auth
func (fam *FortressAuthMiddleware) calculateSecurityLevel(user *User, claims *Claims) string {
	score := 0

	// MFA enabled
	if user.MFAEnabled {
		score += 30
	}

	// Recent token
	if time.Since(claims.IssuedAt.Time) < 5*time.Minute {
		score += 20
	}

	// High-privilege role
	fortressRoles := fam.roleManager.convertLegacyRoles(user.Roles)
	for _, role := range fortressRoles {
		if roleDef, exists := fam.roleManager.GetFortressRoleDefinition(role); exists {
			if roleDef.Level >= 80 {
				score += 25
			}
		}
	}

	// Verified email
	if user.EmailVerified {
		score += 15
	}

	// Account age (older = more secure)
	if time.Since(user.CreatedAt) > 30*24*time.Hour {
		score += 10
	}

	if score >= 80 {
		return "high"
	} else if score >= 50 {
		return "medium"
	}
	return "low"
}

// calculateAPIKeySecurityLevel calculates security level for API key auth
func (fam *FortressAuthMiddleware) calculateAPIKeySecurityLevel(apiKey *ApiKey) string {
	score := 0

	// Recent activity
	if apiKey.LastUsedAt != nil && time.Since(*apiKey.LastUsedAt) < time.Hour {
		score += 20
	}

	// Limited permissions (more secure)
	if len(apiKey.Permissions) <= 3 {
		score += 25
	}

	// Has expiration (more secure)
	if apiKey.ExpiresAt != nil {
		score += 20
	}

	// Rate limited
	if apiKey.RateLimit > 0 && apiKey.RateLimit <= 100 {
		score += 20
	}

	// Key age (newer for API keys is better)
	if time.Since(apiKey.CreatedAt) < 30*24*time.Hour {
		score += 15
	}

	if score >= 70 {
		return "high"
	} else if score >= 40 {
		return "medium"
	}
	return "low"
}

// logSecurityEvent logs a security event for audit purposes
func (fam *FortressAuthMiddleware) logSecurityEvent(c *gin.Context, userID, action, resourceID string, metadata map[string]interface{}) {
	if fam.auditRepo == nil || !fam.securityConfig.EnableAuditLogging {
		return
	}

	// Extract tenant ID if available
	tenantID := ""
	if tenant, exists := c.Get(string(TenantContextKey)); exists {
		if t, ok := tenant.(*Tenant); ok {
			tenantID = t.ID
		}
	}

	auditLog := &AuditLog{
		ID:         uuid.New().String(),
		UserID:     userID,
		TenantID:   tenantID,
		Action:     action,
		Resource:   "fortress_auth",
		ResourceID: resourceID,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
		Metadata:   metadata,
		CreatedAt:  time.Now(),
	}

	// Fire and forget - don't block on audit logging
	go func() {
		if err := fam.auditRepo.Create(context.Background(), auditLog); err != nil {
			// Log error but don't fail the operation
			fmt.Printf("Failed to create audit log: %v\n", err)
		}
	}()
}

// WatchtowerCleanupRateLimiters cleans up old rate limiters
func (fam *FortressAuthMiddleware) WatchtowerCleanupRateLimiters() {
	// This would typically run as a background job
	// Clean up rate limiters that haven't been used recently
	fam.rlMutex.Lock()
	defer fam.rlMutex.Unlock()

	// Implementation would track last access times and clean up
	// For now, this is a placeholder
}

// FortressCORSMiddleware provides secure CORS middleware
func FortressCORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow specific origins in production
		allowedOrigins := []string{
			"http://localhost:3000",
			"https://pat.yourdomain.com",
			"https://fortress.yourdomain.com",
		}

		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		}

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-API-Key, X-Fortress-Token")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// FortressSecurityHeadersMiddleware adds fortress security headers
func FortressSecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Writer.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Writer.Header().Set("X-Fortress-Protected", "true")
		c.Writer.Header().Set("X-Fortress-Version", "2.0")

		c.Next()
	}
}