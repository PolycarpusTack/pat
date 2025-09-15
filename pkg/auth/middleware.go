package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ContextKey represents context keys for auth data
type ContextKey string

const (
	UserContextKey   ContextKey = "user"
	ClaimsContextKey ContextKey = "claims"
	TenantContextKey ContextKey = "tenant"
)

// AuthMiddleware provides authentication middleware
type AuthMiddleware struct {
	jwtManager    *JWTManager
	blacklist     TokenBlacklist
	userService   UserService
	tenantService TenantService
}

// UserService interface for user operations
type UserService interface {
	GetUserByID(ctx context.Context, userID string) (*User, error)
	UpdateLastLogin(ctx context.Context, userID string, loginTime time.Time) error
}

// TenantService interface for tenant operations
type TenantService interface {
	GetTenantByID(ctx context.Context, tenantID string) (*Tenant, error)
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(jwtManager *JWTManager, blacklist TokenBlacklist, userService UserService, tenantService TenantService) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager:    jwtManager,
		blacklist:     blacklist,
		userService:   userService,
		tenantService: tenantService,
	}
}

// RequireAuth middleware that requires authentication
func (am *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := ExtractTokenFromHeader(c.GetHeader("Authorization"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Missing or invalid authorization header",
			})
			c.Abort()
			return
		}

		claims, err := am.jwtManager.ValidateTokenWithBlacklist(token, am.blacklist)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		// Get user from database to ensure they still exist and are active
		user, err := am.userService.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not found",
			})
			c.Abort()
			return
		}

		if !user.IsActive {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User account is inactive",
			})
			c.Abort()
			return
		}

		// Get tenant information
		tenant, err := am.tenantService.GetTenantByID(c.Request.Context(), claims.TenantID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Tenant not found",
			})
			c.Abort()
			return
		}

		if !tenant.IsActive {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Tenant account is inactive",
			})
			c.Abort()
			return
		}

		// Add to context
		c.Set(string(UserContextKey), user)
		c.Set(string(ClaimsContextKey), claims)
		c.Set(string(TenantContextKey), tenant)
		
		c.Next()
	}
}

// RequirePermission middleware that requires specific permission
func (am *AuthMiddleware) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(string(UserContextKey))
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		u := user.(*User)
		
		// Super admin has all permissions
		if u.HasPermission(PermAll) {
			c.Next()
			return
		}

		if !u.HasPermission(permission) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Permission required: %s", permission),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole middleware that requires specific role
func (am *AuthMiddleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(string(UserContextKey))
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		u := user.(*User)
		if !u.HasRole(role) && !u.HasRole("super_admin") {
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Role required: %s", role),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// OptionalAuth middleware that optionally extracts user info
func (am *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		token, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			c.Next()
			return
		}

		claims, err := am.jwtManager.ValidateTokenWithBlacklist(token, am.blacklist)
		if err != nil {
			c.Next()
			return
		}

		user, err := am.userService.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil {
			c.Next()
			return
		}

		if !user.IsActive {
			c.Next()
			return
		}

		tenant, err := am.tenantService.GetTenantByID(c.Request.Context(), claims.TenantID)
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

		c.Next()
	}
}

// APIKeyAuth middleware for API key authentication
func (am *AuthMiddleware) APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "API key required",
			})
			c.Abort()
			return
		}

		// Validate API key (implementation would check against database)
		// This is a placeholder - implement proper API key validation
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid API key",
		})
		c.Abort()
	}
}

// RateLimiter middleware for rate limiting
type RateLimiter struct {
	// Implementation details would go here
	// This is a placeholder for rate limiting functionality
}

func (am *AuthMiddleware) RateLimit(requestsPerMinute int) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Rate limiting implementation would go here
		// For now, just continue
		c.Next()
	}
}

// CORS middleware
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Allow specific origins in production
		allowedOrigins := []string{
			"http://localhost:3000",
			"https://pat.yourdomain.com",
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
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-API-Key")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// SecurityHeaders middleware adds security headers
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		c.Next()
	}
}

// GetUserFromContext extracts user from gin context
func GetUserFromContext(c *gin.Context) (*User, error) {
	user, exists := c.Get(string(UserContextKey))
	if !exists {
		return nil, fmt.Errorf("user not found in context")
	}

	u, ok := user.(*User)
	if !ok {
		return nil, fmt.Errorf("invalid user type in context")
	}

	return u, nil
}

// GetClaimsFromContext extracts claims from gin context
func GetClaimsFromContext(c *gin.Context) (*Claims, error) {
	claims, exists := c.Get(string(ClaimsContextKey))
	if !exists {
		return nil, fmt.Errorf("claims not found in context")
	}

	c, ok := claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type in context")
	}

	return c, nil
}

// GetTenantFromContext extracts tenant from gin context
func GetTenantFromContext(c *gin.Context) (*Tenant, error) {
	tenant, exists := c.Get(string(TenantContextKey))
	if !exists {
		return nil, fmt.Errorf("tenant not found in context")
	}

	t, ok := tenant.(*Tenant)
	if !ok {
		return nil, fmt.Errorf("invalid tenant type in context")
	}

	return t, nil
}