package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// FortressAuthExample demonstrates how to set up and use the fortress authentication system
type FortressAuthExample struct {
	authMiddleware   *FortressAuthMiddleware
	authService      *AuthService
	apiKeyService    *FortressApiKeyService
	sessionManager   *FortressSessionManager
	roleManager      *FortressRoleManager
	blacklist        *FortressTokenBlacklist
	jwtManager       *JWTManager
}

// NewFortressAuthExample creates a complete fortress authentication example
func NewFortressAuthExample() (*FortressAuthExample, error) {
	// Generate RSA key pair for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Convert keys to PEM format
	privateKeyPEM, publicKeyPEM, err := convertKeysToPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert keys to PEM: %w", err)
	}

	// Create JWT manager
	jwtManager, err := NewJWTManager(
		privateKeyPEM,
		publicKeyPEM,
		"fortress-pat-platform",
		"fortress-pat-client",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT manager: %w", err)
	}

	// Create mock repositories for example
	userRepo := &ExampleUserRepository{users: make(map[string]*User)}
	sessionRepo := &ExampleSessionRepository{sessions: make(map[string]*Session)}
	apiKeyRepo := &ExampleApiKeyRepository{apiKeys: make(map[string]*ApiKey)}
	auditRepo := &ExampleAuditRepository{logs: make([]*AuditLog, 0)}
	tenantRepo := &ExampleTenantRepository{tenants: make(map[string]*Tenant)}

	// Create fortress components
	blacklist := NewFortressTokenBlacklist(auditRepo)
	roleManager := NewFortressRoleManager(auditRepo)
	rateLimiter := NewFortressRateLimiter()
	apiKeyService := NewFortressApiKeyService(apiKeyRepo, auditRepo, rateLimiter)
	sessionManager := NewFortressSessionManager(sessionRepo, blacklist, auditRepo, nil)

	// Create auth service
	authService := NewAuthService(
		userRepo,
		sessionRepo,
		apiKeyRepo,
		auditRepo,
		tenantRepo,
		jwtManager,
		blacklist,
	)

	// Create fortress middleware
	securityConfig := DefaultSecurityConfig()
	authMiddleware := NewFortressAuthMiddleware(
		jwtManager,
		blacklist,
		authService,
		authService,
		apiKeyService,
		sessionManager,
		roleManager,
		auditRepo,
		securityConfig,
	)

	// Create sample data
	if err := createSampleData(userRepo, tenantRepo, apiKeyService, roleManager); err != nil {
		return nil, fmt.Errorf("failed to create sample data: %w", err)
	}

	return &FortressAuthExample{
		authMiddleware: authMiddleware,
		authService:   authService,
		apiKeyService: apiKeyService,
		sessionManager: sessionManager,
		roleManager:   roleManager,
		blacklist:     blacklist,
		jwtManager:    jwtManager,
	}, nil
}

// SetupRoutes demonstrates how to set up routes with fortress authentication
func (fae *FortressAuthExample) SetupRoutes() *gin.Engine {
	r := gin.New()

	// Apply fortress middleware globally
	r.Use(FortressSecurityHeadersMiddleware())
	r.Use(FortressCORSMiddleware())

	// Health check endpoint (no auth required)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":   "healthy",
			"fortress": "operational",
			"version":  "2.0.0",
		})
	})

	// Authentication endpoints
	auth := r.Group("/auth")
	{
		auth.POST("/login", fae.handleLogin)
		auth.POST("/register", fae.handleRegister)
		auth.POST("/refresh", fae.handleRefresh)
		auth.POST("/logout", fae.authMiddleware.GuardRequireAuth(), fae.handleLogout)
	}

	// Protected API endpoints
	api := r.Group("/api/v3")
	api.Use(fae.authMiddleware.GuardRequireAuth())
	{
		// Email endpoints - require email permissions
		emails := api.Group("/emails")
		emails.Use(fae.authMiddleware.SentinelRequirePermission(PermFortressEmailRead))
		{
			emails.GET("/", fae.handleListEmails)
			emails.GET("/:id", fae.handleGetEmail)
			
			// Write operations require write permission
			emails.POST("/", 
				fae.authMiddleware.SentinelRequirePermission(PermFortressEmailWrite),
				fae.handleCreateEmail,
			)
			emails.DELETE("/:id", 
				fae.authMiddleware.SentinelRequirePermission(PermFortressEmailDelete),
				fae.handleDeleteEmail,
			)
		}

		// User management - require Guardian role or higher
		users := api.Group("/users")
		users.Use(fae.authMiddleware.GuardRequireRole(RoleGuardian))
		{
			users.GET("/", fae.handleListUsers)
			users.POST("/", fae.handleCreateUser)
			users.PUT("/:id", fae.handleUpdateUser)
		}

		// System management - require Commander role
		system := api.Group("/system")
		system.Use(fae.authMiddleware.GuardRequireRole(RoleCommander))
		{
			system.GET("/stats", fae.handleSystemStats)
			system.POST("/maintenance", fae.handleMaintenanceMode)
		}
	}

	// API key management
	apiKeys := r.Group("/api-keys")
	apiKeys.Use(fae.authMiddleware.GuardRequireAuth())
	{
		apiKeys.GET("/", fae.handleListApiKeys)
		apiKeys.POST("/", fae.handleCreateApiKey)
		apiKeys.DELETE("/:id", fae.handleDeleteApiKey)
		apiKeys.POST("/:id/rotate", fae.handleRotateApiKey)
	}

	// Admin endpoints
	admin := r.Group("/admin")
	admin.Use(fae.authMiddleware.GuardRequireRole(RoleGuardian))
	{
		admin.GET("/audit-logs", fae.handleAuditLogs)
		admin.GET("/sessions", fae.handleActiveSessions)
		admin.POST("/users/:id/roles", fae.handleAssignRole)
		admin.DELETE("/sessions/:id", fae.handleTerminateSession)
	}

	return r
}

// Handler implementations

func (fae *FortressAuthExample) handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	response, err := fae.authService.Login(
		c.Request.Context(),
		&req,
		c.ClientIP(),
		c.Request.UserAgent(),
	)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (fae *FortressAuthExample) handleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	user, err := fae.authService.Register(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, user)
}

func (fae *FortressAuthExample) handleRefresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	response, err := fae.authService.RefreshTokens(c.Request.Context(), req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (fae *FortressAuthExample) handleLogout(c *gin.Context) {
	claims, err := GetClaimsFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
		return
	}

	err = fae.authService.Logout(c.Request.Context(), claims.SessionID, claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

func (fae *FortressAuthExample) handleListEmails(c *gin.Context) {
	user, _ := GetUserFromContext(c)
	
	c.JSON(http.StatusOK, gin.H{
		"emails": []gin.H{
			{
				"id":      "email-1",
				"subject": "Welcome to Fortress Pat",
				"from":    "fortress@pat.com",
				"to":      user.Email,
			},
		},
		"fortress_security_level": c.GetString("fortress_security_level"),
	})
}

func (fae *FortressAuthExample) handleGetEmail(c *gin.Context) {
	emailID := c.Param("id")
	user, _ := GetUserFromContext(c)

	c.JSON(http.StatusOK, gin.H{
		"id":      emailID,
		"subject": "Fortress Security Alert",
		"from":    "security@pat.com",
		"to":      user.Email,
		"body":    "Your fortress is secure.",
	})
}

func (fae *FortressAuthExample) handleCreateEmail(c *gin.Context) {
	var req struct {
		Subject string `json:"subject" binding:"required"`
		To      string `json:"to" binding:"required"`
		Body    string `json:"body"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	emailID := uuid.New().String()
	c.JSON(http.StatusCreated, gin.H{
		"id":      emailID,
		"subject": req.Subject,
		"to":      req.To,
		"body":    req.Body,
		"status":  "created",
	})
}

func (fae *FortressAuthExample) handleDeleteEmail(c *gin.Context) {
	emailID := c.Param("id")
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Email %s deleted by fortress security", emailID),
	})
}

func (fae *FortressAuthExample) handleListUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"users": []gin.H{
			{
				"id":    "user-1",
				"email": "commander@fortress.com",
				"roles": []string{"commander"},
			},
			{
				"id":    "user-2", 
				"email": "guardian@fortress.com",
				"roles": []string{"guardian"},
			},
		},
	})
}

func (fae *FortressAuthExample) handleCreateUser(c *gin.Context) {
	var req struct {
		Email string   `json:"email" binding:"required"`
		Name  string   `json:"name" binding:"required"`
		Roles []string `json:"roles"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	userID := uuid.New().String()
	c.JSON(http.StatusCreated, gin.H{
		"id":    userID,
		"email": req.Email,
		"name":  req.Name,
		"roles": req.Roles,
	})
}

func (fae *FortressAuthExample) handleUpdateUser(c *gin.Context) {
	userID := c.Param("id")
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("User %s updated by fortress guardian", userID),
	})
}

func (fae *FortressAuthExample) handleSystemStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"fortress": gin.H{
			"version":           "2.0.0",
			"active_sessions":   42,
			"blacklisted_tokens": len(fae.blacklist.WatchtowerListBlacklistedTokens()),
			"security_level":    "maximum",
		},
	})
}

func (fae *FortressAuthExample) handleMaintenanceMode(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Fortress maintenance mode activated by commander",
	})
}

func (fae *FortressAuthExample) handleListApiKeys(c *gin.Context) {
	user, _ := GetUserFromContext(c)
	
	apiKeys, err := fae.apiKeyService.SentinelListApiKeys(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list API keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"api_keys": apiKeys})
}

func (fae *FortressAuthExample) handleCreateApiKey(c *gin.Context) {
	var req struct {
		Name        string    `json:"name" binding:"required"`
		Permissions []string  `json:"permissions"`
		RateLimit   int       `json:"rate_limit"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	user, _ := GetUserFromContext(c)
	
	keyString, apiKey, err := fae.apiKeyService.CommanderGenerateApiKey(
		c.Request.Context(),
		user.ID,
		req.Name,
		req.Permissions,
		req.RateLimit,
		req.ExpiresAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"api_key": keyString,
		"details": apiKey,
		"warning": "Store this API key securely. It will not be displayed again.",
	})
}

func (fae *FortressAuthExample) handleDeleteApiKey(c *gin.Context) {
	keyID := c.Param("id")
	user, _ := GetUserFromContext(c)

	err := fae.apiKeyService.GuardRevokeApiKey(
		c.Request.Context(),
		keyID,
		user.ID,
		"User requested deletion",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key deleted"})
}

func (fae *FortressAuthExample) handleRotateApiKey(c *gin.Context) {
	keyID := c.Param("id")
	user, _ := GetUserFromContext(c)

	newKeyString, newApiKey, err := fae.apiKeyService.GuardRotateApiKey(
		c.Request.Context(),
		keyID,
		user.ID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rotate API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"new_api_key": newKeyString,
		"details":     newApiKey,
		"warning":     "Store this new API key securely. The old key has been deactivated.",
	})
}

func (fae *FortressAuthExample) handleAuditLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"audit_logs": []gin.H{
			{
				"action":    "fortress.auth.success",
				"user_id":   "user-123",
				"timestamp": time.Now(),
			},
		},
	})
}

func (fae *FortressAuthExample) handleActiveSessions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"active_sessions": []gin.H{
			{
				"session_id": "session-123",
				"user_id":    "user-123",
				"ip_address": "192.168.1.100",
				"last_activity": time.Now(),
			},
		},
	})
}

func (fae *FortressAuthExample) handleAssignRole(c *gin.Context) {
	userID := c.Param("id")
	var req struct {
		Role   string `json:"role" binding:"required"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Role %s assigned to user %s", req.Role, userID),
	})
}

func (fae *FortressAuthExample) handleTerminateSession(c *gin.Context) {
	sessionID := c.Param("id")

	err := fae.sessionManager.SentinelTerminateSession(
		c.Request.Context(),
		sessionID,
		"Admin termination",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to terminate session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Session %s terminated by fortress guardian", sessionID),
	})
}

// Utility functions

func convertKeysToPEM(privateKey *rsa.PrivateKey) ([]byte, []byte, error) {
	// Convert private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Convert public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPEM, publicKeyPEM, nil
}

func createSampleData(userRepo *ExampleUserRepository, tenantRepo *ExampleTenantRepository, apiKeyService *FortressApiKeyService, roleManager *FortressRoleManager) error {
	// Create sample tenant
	tenant := &Tenant{
		ID:       "fortress-tenant-1",
		Name:     "Fortress Corporation",
		Domain:   "fortress.com",
		Settings: make(map[string]interface{}),
		PlanType: "enterprise",
		IsActive: true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	tenantRepo.tenants[tenant.ID] = tenant

	// Create sample users
	users := []*User{
		{
			ID:            "commander-user-1",
			Email:         "commander@fortress.com", 
			Name:          "Fortress Commander",
			PasswordHash:  "$2a$12$example_hash", // In practice, use proper bcrypt
			TenantID:      tenant.ID,
			Roles:         []string{"super_admin"},
			IsActive:      true,
			EmailVerified: true,
			Settings:      make(map[string]interface{}),
			MFAEnabled:    true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
		{
			ID:            "guardian-user-1",
			Email:         "guardian@fortress.com",
			Name:          "Fortress Guardian",
			PasswordHash:  "$2a$12$example_hash",
			TenantID:      tenant.ID,
			Roles:         []string{"admin"},
			IsActive:      true,
			EmailVerified: true,
			Settings:      make(map[string]interface{}),
			MFAEnabled:    true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
		{
			ID:            "sentinel-user-1",
			Email:         "sentinel@fortress.com",
			Name:          "Fortress Sentinel",
			PasswordHash:  "$2a$12$example_hash",
			TenantID:      tenant.ID,
			Roles:         []string{"moderator"},
			IsActive:      true,
			EmailVerified: true,
			Settings:      make(map[string]interface{}),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
	}

	for _, user := range users {
		userRepo.users[user.ID] = user
	}

	log.Printf("✅ Fortress authentication system initialized with %d users and fortress security roles", len(users))
	return nil
}

// Example repository implementations (in production, these would use actual databases)

type ExampleUserRepository struct {
	users map[string]*User
}

func (r *ExampleUserRepository) Create(ctx context.Context, user *User) error {
	r.users[user.ID] = user
	return nil
}

func (r *ExampleUserRepository) GetByID(ctx context.Context, id string) (*User, error) {
	if user, exists := r.users[id]; exists {
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (r *ExampleUserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	for _, user := range r.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (r *ExampleUserRepository) Update(ctx context.Context, user *User) error {
	r.users[user.ID] = user
	return nil
}

func (r *ExampleUserRepository) Delete(ctx context.Context, id string) error {
	delete(r.users, id)
	return nil
}

func (r *ExampleUserRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]*User, int, error) {
	var result []*User
	for _, user := range r.users {
		if tenantID == "" || user.TenantID == tenantID {
			result = append(result, user)
		}
	}
	return result, len(result), nil
}

func (r *ExampleUserRepository) UpdateLastLogin(ctx context.Context, userID string, loginTime time.Time) error {
	if user, exists := r.users[userID]; exists {
		user.LastLoginAt = &loginTime
		return nil
	}
	return fmt.Errorf("user not found")
}

func (r *ExampleUserRepository) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	if user, exists := r.users[userID]; exists {
		user.PasswordHash = passwordHash
		return nil
	}
	return fmt.Errorf("user not found")
}

func (r *ExampleUserRepository) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	if user, exists := r.users[userID]; exists {
		user.EmailVerified = verified
		return nil
	}
	return fmt.Errorf("user not found")
}

func (r *ExampleUserRepository) SetMFASecret(ctx context.Context, userID, secret string) error {
	if user, exists := r.users[userID]; exists {
		user.MFASecret = secret
		return nil
	}
	return fmt.Errorf("user not found")
}

func (r *ExampleUserRepository) GetRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	if user, exists := r.users[userID]; exists {
		return user.RecoveryCodes, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (r *ExampleUserRepository) UpdateRecoveryCodes(ctx context.Context, userID string, codes []string) error {
	if user, exists := r.users[userID]; exists {
		user.RecoveryCodes = codes
		return nil
	}
	return fmt.Errorf("user not found")
}

type ExampleSessionRepository struct {
	sessions map[string]*Session
}

func (r *ExampleSessionRepository) Create(ctx context.Context, session *Session) error {
	r.sessions[session.ID] = session
	return nil
}

func (r *ExampleSessionRepository) GetByID(ctx context.Context, id string) (*Session, error) {
	if session, exists := r.sessions[id]; exists {
		return session, nil
	}
	return nil, fmt.Errorf("session not found")
}

func (r *ExampleSessionRepository) GetByRefreshToken(ctx context.Context, refreshToken string) (*Session, error) {
	for _, session := range r.sessions {
		if session.RefreshToken == refreshToken {
			return session, nil
		}
	}
	return nil, fmt.Errorf("session not found")
}

func (r *ExampleSessionRepository) Update(ctx context.Context, session *Session) error {
	r.sessions[session.ID] = session
	return nil
}

func (r *ExampleSessionRepository) Delete(ctx context.Context, id string) error {
	delete(r.sessions, id)
	return nil
}

func (r *ExampleSessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	for id, session := range r.sessions {
		if session.UserID == userID {
			delete(r.sessions, id)
		}
	}
	return nil
}

func (r *ExampleSessionRepository) GetActiveSessions(ctx context.Context, userID string) ([]*Session, error) {
	var result []*Session
	for _, session := range r.sessions {
		if session.UserID == userID && session.IsActive {
			result = append(result, session)
		}
	}
	return result, nil
}

type ExampleApiKeyRepository struct {
	apiKeys map[string]*ApiKey
}

func (r *ExampleApiKeyRepository) Create(ctx context.Context, apiKey *ApiKey) error {
	r.apiKeys[apiKey.ID] = apiKey
	return nil
}

func (r *ExampleApiKeyRepository) GetByID(ctx context.Context, id string) (*ApiKey, error) {
	if apiKey, exists := r.apiKeys[id]; exists {
		return apiKey, nil
	}
	return nil, fmt.Errorf("api key not found")
}

func (r *ExampleApiKeyRepository) GetByKeyHash(ctx context.Context, keyHash string) (*ApiKey, error) {
	for _, apiKey := range r.apiKeys {
		if apiKey.KeyHash == keyHash {
			return apiKey, nil
		}
	}
	return nil, fmt.Errorf("api key not found")
}

func (r *ExampleApiKeyRepository) Update(ctx context.Context, apiKey *ApiKey) error {
	r.apiKeys[apiKey.ID] = apiKey
	return nil
}

func (r *ExampleApiKeyRepository) Delete(ctx context.Context, id string) error {
	delete(r.apiKeys, id)
	return nil
}

func (r *ExampleApiKeyRepository) ListByUserID(ctx context.Context, userID string) ([]*ApiKey, error) {
	var result []*ApiKey
	for _, apiKey := range r.apiKeys {
		if apiKey.UserID == userID {
			result = append(result, apiKey)
		}
	}
	return result, nil
}

func (r *ExampleApiKeyRepository) UpdateLastUsed(ctx context.Context, id string, lastUsed time.Time) error {
	if apiKey, exists := r.apiKeys[id]; exists {
		apiKey.LastUsedAt = &lastUsed
		return nil
	}
	return fmt.Errorf("api key not found")
}

type ExampleAuditRepository struct {
	logs []*AuditLog
}

func (r *ExampleAuditRepository) Create(ctx context.Context, log *AuditLog) error {
	r.logs = append(r.logs, log)
	return nil
}

func (r *ExampleAuditRepository) List(ctx context.Context, tenantID string, filters map[string]interface{}, limit, offset int) ([]*AuditLog, int, error) {
	return r.logs, len(r.logs), nil
}

type ExampleTenantRepository struct {
	tenants map[string]*Tenant
}

func (r *ExampleTenantRepository) Create(ctx context.Context, tenant *Tenant) error {
	r.tenants[tenant.ID] = tenant
	return nil
}

func (r *ExampleTenantRepository) GetByID(ctx context.Context, id string) (*Tenant, error) {
	if tenant, exists := r.tenants[id]; exists {
		return tenant, nil
	}
	return nil, fmt.Errorf("tenant not found")
}

func (r *ExampleTenantRepository) GetByDomain(ctx context.Context, domain string) (*Tenant, error) {
	for _, tenant := range r.tenants {
		if tenant.Domain == domain {
			return tenant, nil
		}
	}
	return nil, fmt.Errorf("tenant not found")
}

func (r *ExampleTenantRepository) Update(ctx context.Context, tenant *Tenant) error {
	r.tenants[tenant.ID] = tenant
	return nil
}

func (r *ExampleTenantRepository) Delete(ctx context.Context, id string) error {
	delete(r.tenants, id)
	return nil
}

// Example main function to demonstrate usage
func ExampleMain() {
	// Create fortress authentication system
	fortress, err := NewFortressAuthExample()
	if err != nil {
		log.Fatalf("Failed to create fortress auth system: %v", err)
	}

	// Set up routes
	r := fortress.SetupRoutes()

	// Start server
	log.Println("🏰 Fortress Pat Authentication System starting on :8080")
	log.Println("🛡️  Security Level: MAXIMUM")
	log.Println("🔐 Roles Available: Commander, Guardian, Sentinel, Observer")
	log.Println("⚡ Rate Limiting: ENABLED")
	log.Println("📊 Audit Logging: ENABLED")
	
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}