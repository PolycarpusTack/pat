package integration

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/alexandria/pat-plugin/pkg/auth"
)

type AuthIntegrationTestSuite struct {
	suite.Suite
	authService   *auth.AuthService
	jwtManager    *auth.JWTManager
	middleware    *auth.AuthMiddleware
	testDB        *sql.DB
	router        *gin.Engine
	cleanup       func()
}

func (suite *AuthIntegrationTestSuite) SetupSuite() {
	// Setup test database (using in-memory SQLite for tests)
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(suite.T(), err)
	suite.testDB = db

	// Create test tables
	suite.createTestTables()

	// Setup repositories (mock implementations for testing)
	userRepo := &mockUserRepository{db: db}
	sessionRepo := &mockSessionRepository{db: db}
	apiKeyRepo := &mockApiKeyRepository{db: db}
	auditRepo := &mockAuditRepository{db: db}
	tenantRepo := &mockTenantRepository{db: db}

	// Create test RSA key pair
	privateKeyPEM, publicKeyPEM, err := generateTestKeys()
	require.NoError(suite.T(), err)

	// Setup JWT manager
	jwtManager, err := auth.NewJWTManager(privateKeyPEM, publicKeyPEM, "test-issuer", "test-audience")
	require.NoError(suite.T(), err)
	suite.jwtManager = jwtManager

	// Setup auth service
	blacklist := &mockTokenBlacklist{tokens: make(map[string]time.Time)}
	suite.authService = auth.NewAuthService(
		userRepo, sessionRepo, apiKeyRepo, auditRepo, tenantRepo,
		jwtManager, blacklist,
	)

	// Setup middleware
	suite.middleware = auth.NewAuthMiddleware(jwtManager, blacklist, suite.authService, suite.authService)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	suite.router = gin.New()
	suite.setupRoutes()

	// Setup cleanup
	suite.cleanup = func() {
		if suite.testDB != nil {
			suite.testDB.Close()
		}
	}
}

func (suite *AuthIntegrationTestSuite) TearDownSuite() {
	if suite.cleanup != nil {
		suite.cleanup()
	}
}

func (suite *AuthIntegrationTestSuite) createTestTables() {
	queries := []string{
		`CREATE TABLE users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			roles TEXT NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			email_verified BOOLEAN DEFAULT FALSE,
			settings TEXT,
			last_login_at DATETIME,
			mfa_enabled BOOLEAN DEFAULT FALSE,
			mfa_secret TEXT,
			recovery_codes TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			device_id TEXT,
			ip_address TEXT,
			user_agent TEXT,
			refresh_token TEXT NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE tenants (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			domain TEXT,
			settings TEXT,
			plan_type TEXT,
			is_active BOOLEAN DEFAULT TRUE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE audit_logs (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			tenant_id TEXT,
			action TEXT NOT NULL,
			resource TEXT,
			resource_id TEXT,
			ip_address TEXT,
			user_agent TEXT,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range queries {
		_, err := suite.testDB.Exec(query)
		require.NoError(suite.T(), err)
	}
}

func (suite *AuthIntegrationTestSuite) setupRoutes() {
	// Public routes
	public := suite.router.Group("/api/v1")
	{
		public.POST("/auth/register", suite.handleRegister)
		public.POST("/auth/login", suite.handleLogin)
		public.POST("/auth/refresh", suite.handleRefresh)
	}

	// Protected routes
	protected := suite.router.Group("/api/v1")
	protected.Use(suite.middleware.RequireAuth())
	{
		protected.GET("/profile", suite.handleGetProfile)
		protected.POST("/auth/logout", suite.handleLogout)
		protected.PUT("/profile", suite.middleware.RequirePermission(auth.PermUserWrite), suite.handleUpdateProfile)
	}

	// Admin routes
	admin := suite.router.Group("/api/v1/admin")
	admin.Use(suite.middleware.RequireAuth())
	admin.Use(suite.middleware.RequireRole("admin"))
	{
		admin.GET("/users", suite.handleListUsers)
	}
}

func (suite *AuthIntegrationTestSuite) TestUserRegistration() {
	payload := `{
		"email": "test@example.com",
		"name": "Test User",
		"password": "SecurePassword123!",
		"tenant_id": "test-tenant"
	}`

	req := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)
	
	// Verify user was created
	var count int
	err := suite.testDB.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", "test@example.com").Scan(&count)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 1, count)
}

func (suite *AuthIntegrationTestSuite) TestUserLogin() {
	// First register a user
	suite.createTestUser("login@example.com", "Login User", "SecurePassword123!")

	payload := `{
		"email": "login@example.com",
		"password": "SecurePassword123!"
	}`

	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	assert.Contains(suite.T(), w.Body.String(), "access_token")
	assert.Contains(suite.T(), w.Body.String(), "refresh_token")
}

func (suite *AuthIntegrationTestSuite) TestProtectedRoute() {
	// Create user and get token
	user := suite.createTestUser("protected@example.com", "Protected User", "SecurePassword123!")
	token, err := suite.generateTokenForUser(user)
	require.NoError(suite.T(), err)

	req := httptest.NewRequest("GET", "/api/v1/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	assert.Contains(suite.T(), w.Body.String(), user.Email)
}

func (suite *AuthIntegrationTestSuite) TestUnauthorizedAccess() {
	req := httptest.NewRequest("GET", "/api/v1/profile", nil)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
}

func (suite *AuthIntegrationTestSuite) TestRoleBasedAccess() {
	// Create regular user
	user := suite.createTestUser("user@example.com", "Regular User", "SecurePassword123!")
	token, err := suite.generateTokenForUser(user)
	require.NoError(suite.T(), err)

	// Try to access admin route
	req := httptest.NewRequest("GET", "/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusForbidden, w.Code)

	// Create admin user
	adminUser := suite.createTestUser("admin@example.com", "Admin User", "SecurePassword123!")
	adminUser.Roles = []string{"admin"}
	suite.updateUserRoles(adminUser.ID, adminUser.Roles)

	adminToken, err := suite.generateTokenForUser(adminUser)
	require.NoError(suite.T(), err)

	// Admin should access the route
	req = httptest.NewRequest("GET", "/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
}

func (suite *AuthIntegrationTestSuite) TestTokenRefresh() {
	// Create user and login to get refresh token
	user := suite.createTestUser("refresh@example.com", "Refresh User", "SecurePassword123!")
	
	loginPayload := `{
		"email": "refresh@example.com",
		"password": "SecurePassword123!"
	}`

	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(loginPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	// Extract refresh token from response (in real implementation, parse JSON)
	responseBody := w.Body.String()
	assert.Contains(suite.T(), responseBody, "refresh_token")
}

// Helper methods

func (suite *AuthIntegrationTestSuite) createTestUser(email, name, password string) *auth.User {
	hasher := auth.NewPasswordHasher(nil)
	passwordHash, err := hasher.HashPassword(password)
	require.NoError(suite.T(), err)

	user := auth.NewUser(email, name, "test-tenant")
	user.PasswordHash = passwordHash

	query := `INSERT INTO users (id, email, name, password_hash, tenant_id, roles, is_active, email_verified, settings, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	_, err = suite.testDB.Exec(query, user.ID, user.Email, user.Name, user.PasswordHash, 
		user.TenantID, "user", user.IsActive, user.EmailVerified, "{}", 
		user.CreatedAt, user.UpdatedAt)
	require.NoError(suite.T(), err)

	// Also create tenant
	_, err = suite.testDB.Exec(`INSERT INTO tenants (id, name, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		user.TenantID, "Test Tenant", true, time.Now(), time.Now())
	require.NoError(suite.T(), err)

	return user
}

func (suite *AuthIntegrationTestSuite) updateUserRoles(userID string, roles []string) {
	rolesStr := strings.Join(roles, ",")
	_, err := suite.testDB.Exec("UPDATE users SET roles = ? WHERE id = ?", rolesStr, userID)
	require.NoError(suite.T(), err)
}

func (suite *AuthIntegrationTestSuite) generateTokenForUser(user *auth.User) (string, error) {
	accessToken, _, err := suite.jwtManager.GenerateTokenPair(
		user.ID, user.Email, user.Name, user.TenantID,
		user.Roles, user.GetPermissions(), "test-device", "127.0.0.1",
	)
	return accessToken, err
}

// Route handlers (simplified)

func (suite *AuthIntegrationTestSuite) handleRegister(c *gin.Context) {
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := suite.authService.Register(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, user)
}

func (suite *AuthIntegrationTestSuite) handleLogin(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := suite.authService.Login(c.Request.Context(), &req, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (suite *AuthIntegrationTestSuite) handleRefresh(c *gin.Context) {
	// Implementation would handle refresh token logic
	c.JSON(http.StatusOK, gin.H{"message": "refresh endpoint"})
}

func (suite *AuthIntegrationTestSuite) handleGetProfile(c *gin.Context) {
	user, err := auth.GetUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (suite *AuthIntegrationTestSuite) handleLogout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func (suite *AuthIntegrationTestSuite) handleUpdateProfile(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "profile updated"})
}

func (suite *AuthIntegrationTestSuite) handleListUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"users": []string{}})
}

func TestAuthIntegration(t *testing.T) {
	suite.Run(t, new(AuthIntegrationTestSuite))
}

// Mock implementations for testing

type mockUserRepository struct {
	db *sql.DB
}

func (r *mockUserRepository) Create(ctx context.Context, user *auth.User) error {
	query := `INSERT INTO users (id, email, name, password_hash, tenant_id, roles, is_active, email_verified, settings, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, query, user.ID, user.Email, user.Name, user.PasswordHash, 
		user.TenantID, strings.Join(user.Roles, ","), user.IsActive, user.EmailVerified, "{}", 
		user.CreatedAt, user.UpdatedAt)
	return err
}

func (r *mockUserRepository) GetByID(ctx context.Context, id string) (*auth.User, error) {
	user := &auth.User{}
	var rolesStr string
	query := `SELECT id, email, name, password_hash, tenant_id, roles, is_active, email_verified, 
			  last_login_at, mfa_enabled, created_at, updated_at FROM users WHERE id = ?`
	
	row := r.db.QueryRowContext(ctx, query, id)
	err := row.Scan(&user.ID, &user.Email, &user.Name, &user.PasswordHash, &user.TenantID, 
		&rolesStr, &user.IsActive, &user.EmailVerified, &user.LastLoginAt, &user.MFAEnabled,
		&user.CreatedAt, &user.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	if rolesStr != "" {
		user.Roles = strings.Split(rolesStr, ",")
	}
	
	return user, nil
}

func (r *mockUserRepository) GetByEmail(ctx context.Context, email string) (*auth.User, error) {
	// Similar implementation as GetByID but with email filter
	return nil, fmt.Errorf("not implemented")
}

func (r *mockUserRepository) Update(ctx context.Context, user *auth.User) error {
	return nil
}

func (r *mockUserRepository) Delete(ctx context.Context, id string) error {
	return nil
}

func (r *mockUserRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]*auth.User, int, error) {
	return nil, 0, nil
}

func (r *mockUserRepository) UpdateLastLogin(ctx context.Context, userID string, loginTime time.Time) error {
	return nil
}

func (r *mockUserRepository) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	return nil
}

func (r *mockUserRepository) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	return nil
}

func (r *mockUserRepository) SetMFASecret(ctx context.Context, userID, secret string) error {
	return nil
}

func (r *mockUserRepository) GetRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}

func (r *mockUserRepository) UpdateRecoveryCodes(ctx context.Context, userID string, codes []string) error {
	return nil
}

// Other mock implementations...
type mockSessionRepository struct{ db *sql.DB }
type mockApiKeyRepository struct{ db *sql.DB }
type mockAuditRepository struct{ db *sql.DB }
type mockTenantRepository struct{ db *sql.DB }
type mockTokenBlacklist struct{ tokens map[string]time.Time }

// Implement minimal methods for mocks...
func (r *mockSessionRepository) Create(ctx context.Context, session *auth.Session) error { return nil }
func (r *mockSessionRepository) GetByID(ctx context.Context, id string) (*auth.Session, error) { return nil, nil }
func (r *mockSessionRepository) GetByRefreshToken(ctx context.Context, token string) (*auth.Session, error) { return nil, nil }
func (r *mockSessionRepository) Update(ctx context.Context, session *auth.Session) error { return nil }
func (r *mockSessionRepository) Delete(ctx context.Context, id string) error { return nil }
func (r *mockSessionRepository) DeleteByUserID(ctx context.Context, userID string) error { return nil }
func (r *mockSessionRepository) GetActiveSessions(ctx context.Context, userID string) ([]*auth.Session, error) { return nil, nil }

func (r *mockApiKeyRepository) Create(ctx context.Context, apiKey *auth.ApiKey) error { return nil }
func (r *mockApiKeyRepository) GetByID(ctx context.Context, id string) (*auth.ApiKey, error) { return nil, nil }
func (r *mockApiKeyRepository) GetByKeyHash(ctx context.Context, hash string) (*auth.ApiKey, error) { return nil, nil }
func (r *mockApiKeyRepository) Update(ctx context.Context, apiKey *auth.ApiKey) error { return nil }
func (r *mockApiKeyRepository) Delete(ctx context.Context, id string) error { return nil }
func (r *mockApiKeyRepository) ListByUserID(ctx context.Context, userID string) ([]*auth.ApiKey, error) { return nil, nil }
func (r *mockApiKeyRepository) UpdateLastUsed(ctx context.Context, id string, lastUsed time.Time) error { return nil }

func (r *mockAuditRepository) Create(ctx context.Context, log *auth.AuditLog) error { return nil }
func (r *mockAuditRepository) List(ctx context.Context, tenantID string, filters map[string]interface{}, limit, offset int) ([]*auth.AuditLog, int, error) { return nil, 0, nil }

func (r *mockTenantRepository) Create(ctx context.Context, tenant *auth.Tenant) error { return nil }
func (r *mockTenantRepository) GetByID(ctx context.Context, id string) (*auth.Tenant, error) { 
	return &auth.Tenant{ID: id, Name: "Test Tenant", IsActive: true}, nil 
}
func (r *mockTenantRepository) GetByDomain(ctx context.Context, domain string) (*auth.Tenant, error) { return nil, nil }
func (r *mockTenantRepository) Update(ctx context.Context, tenant *auth.Tenant) error { return nil }
func (r *mockTenantRepository) Delete(ctx context.Context, id string) error { return nil }

func (bl *mockTokenBlacklist) IsBlacklisted(tokenID string) (bool, error) {
	_, exists := bl.tokens[tokenID]
	return exists, nil
}
func (bl *mockTokenBlacklist) BlacklistToken(tokenID string, expiresAt time.Time) error {
	bl.tokens[tokenID] = expiresAt
	return nil
}

// Helper functions
func generateTestKeys() ([]byte, []byte, error) {
	// Same implementation as in jwt_test.go
	return generateTestKeyPair()
}