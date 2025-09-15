package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// AuthService provides authentication services
type AuthService struct {
	userRepo      UserRepository
	sessionRepo   SessionRepository
	apiKeyRepo    ApiKeyRepository
	auditRepo     AuditRepository
	tenantRepo    TenantRepository
	jwtManager    *JWTManager
	hasher        *PasswordHasher
	validator     *PasswordValidator
	blacklist     TokenBlacklist
}

// UserRepository interface for user data operations
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, tenantID string, limit, offset int) ([]*User, int, error)
	UpdateLastLogin(ctx context.Context, userID string, loginTime time.Time) error
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	SetEmailVerified(ctx context.Context, userID string, verified bool) error
	SetMFASecret(ctx context.Context, userID, secret string) error
	GetRecoveryCodes(ctx context.Context, userID string) ([]string, error)
	UpdateRecoveryCodes(ctx context.Context, userID string, codes []string) error
}

// SessionRepository interface for session data operations
type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, id string) (*Session, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*Session, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
	GetActiveSessions(ctx context.Context, userID string) ([]*Session, error)
}

// ApiKeyRepository interface for API key operations
type ApiKeyRepository interface {
	Create(ctx context.Context, apiKey *ApiKey) error
	GetByID(ctx context.Context, id string) (*ApiKey, error)
	GetByKeyHash(ctx context.Context, keyHash string) (*ApiKey, error)
	Update(ctx context.Context, apiKey *ApiKey) error
	Delete(ctx context.Context, id string) error
	ListByUserID(ctx context.Context, userID string) ([]*ApiKey, error)
	UpdateLastUsed(ctx context.Context, id string, lastUsed time.Time) error
}

// AuditRepository interface for audit logging
type AuditRepository interface {
	Create(ctx context.Context, log *AuditLog) error
	List(ctx context.Context, tenantID string, filters map[string]interface{}, limit, offset int) ([]*AuditLog, int, error)
}

// TenantRepository interface for tenant operations
type TenantRepository interface {
	Create(ctx context.Context, tenant *Tenant) error
	GetByID(ctx context.Context, id string) (*Tenant, error)
	GetByDomain(ctx context.Context, domain string) (*Tenant, error)
	Update(ctx context.Context, tenant *Tenant) error
	Delete(ctx context.Context, id string) error
}

// NewAuthService creates a new authentication service
func NewAuthService(
	userRepo UserRepository,
	sessionRepo SessionRepository,
	apiKeyRepo ApiKeyRepository,
	auditRepo AuditRepository,
	tenantRepo TenantRepository,
	jwtManager *JWTManager,
	blacklist TokenBlacklist,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		apiKeyRepo:  apiKeyRepo,
		auditRepo:   auditRepo,
		tenantRepo:  tenantRepo,
		jwtManager:  jwtManager,
		hasher:      NewPasswordHasher(nil),
		validator:   DefaultPasswordValidator(),
		blacklist:   blacklist,
	}
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email      string `json:"email" binding:"required,email"`
	Password   string `json:"password" binding:"required"`
	MFACode    string `json:"mfa_code,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
	RememberMe bool   `json:"remember_me"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	ExpiresAt             time.Time `json:"expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	User                  *User     `json:"user"`
	RequiresMFA           bool      `json:"requires_mfa,omitempty"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Name     string `json:"name" binding:"required"`
	Password string `json:"password" binding:"required"`
	TenantID string `json:"tenant_id,omitempty"`
}

// Login authenticates a user and returns JWT tokens
func (as *AuthService) Login(ctx context.Context, req *LoginRequest, ipAddress, userAgent string) (*LoginResponse, error) {
	// Get user by email
	user, err := as.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			// Log failed login attempt
			as.logLoginAttempt(ctx, req.Email, ipAddress, userAgent, false, "user_not_found")
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Verify password
	valid, err := as.hasher.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("failed to verify password: %w", err)
	}

	if !valid {
		as.logLoginAttempt(ctx, req.Email, ipAddress, userAgent, false, "invalid_password")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		as.logLoginAttempt(ctx, req.Email, ipAddress, userAgent, false, "user_inactive")
		return nil, fmt.Errorf("user account is inactive")
	}

	// Check MFA if enabled
	if user.MFAEnabled {
		if req.MFACode == "" {
			return &LoginResponse{
				RequiresMFA: true,
			}, nil
		}

		// Verify TOTP code
		valid := totp.Validate(req.MFACode, user.MFASecret)
		if !valid {
			// Check if it's a recovery code
			if !as.verifyRecoveryCode(ctx, user.ID, req.MFACode) {
				as.logLoginAttempt(ctx, req.Email, ipAddress, userAgent, false, "invalid_mfa")
				return nil, fmt.Errorf("invalid MFA code")
			}
		}
	}

	// Generate JWT tokens
	accessToken, refreshToken, err := as.jwtManager.GenerateTokenPair(
		user.ID, user.Email, user.Name, user.TenantID, user.Roles, user.GetPermissions(),
		req.DeviceID, ipAddress,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Create session
	session := &Session{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		DeviceID:     req.DeviceID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		RefreshToken: refreshToken,
		IsActive:     true,
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err = as.sessionRepo.Create(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login
	err = as.userRepo.UpdateLastLogin(ctx, user.ID, time.Now())
	if err != nil {
		// Log error but don't fail login
		fmt.Printf("Failed to update last login: %v\n", err)
	}

	// Log successful login
	as.logLoginAttempt(ctx, req.Email, ipAddress, userAgent, true, "")

	// Log audit event
	as.logAuditEvent(ctx, user.ID, user.TenantID, "user.login", "session", session.ID, ipAddress, userAgent, nil)

	return &LoginResponse{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		ExpiresAt:             time.Now().Add(15 * time.Minute),
		RefreshTokenExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		User:                  user,
	}, nil
}

// Register creates a new user account
func (as *AuthService) Register(ctx context.Context, req *RegisterRequest) (*User, error) {
	// Validate password
	if err := as.validator.ValidatePassword(req.Password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Check if user already exists
	_, err := as.userRepo.GetByEmail(ctx, req.Email)
	if err == nil {
		return nil, fmt.Errorf("user already exists")
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	// Hash password
	passwordHash, err := as.hasher.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := NewUser(req.Email, req.Name, req.TenantID)
	user.PasswordHash = passwordHash

	err = as.userRepo.Create(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Log audit event
	as.logAuditEvent(ctx, user.ID, user.TenantID, "user.register", "user", user.ID, "", "", nil)

	return user, nil
}

// RefreshTokens generates new access token using refresh token
func (as *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	// Get session by refresh token
	session, err := as.sessionRepo.GetByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if !session.IsActive || session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token expired or inactive")
	}

	// Get user
	user, err := as.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	if !user.IsActive {
		return nil, fmt.Errorf("user account is inactive")
	}

	// Generate new access token
	accessToken, newRefreshToken, err := as.jwtManager.GenerateTokenPair(
		user.ID, user.Email, user.Name, user.TenantID, user.Roles, user.GetPermissions(),
		session.DeviceID, session.IPAddress,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update session
	session.RefreshToken = newRefreshToken
	session.UpdatedAt = time.Now()
	session.ExpiresAt = time.Now().Add(7 * 24 * time.Hour)

	err = as.sessionRepo.Update(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return &LoginResponse{
		AccessToken:           accessToken,
		RefreshToken:          newRefreshToken,
		ExpiresAt:             time.Now().Add(15 * time.Minute),
		RefreshTokenExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		User:                  user,
	}, nil
}

// Logout invalidates a user session
func (as *AuthService) Logout(ctx context.Context, sessionID string, userID string) error {
	// Delete session
	err := as.sessionRepo.Delete(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Log audit event
	as.logAuditEvent(ctx, userID, "", "user.logout", "session", sessionID, "", "", nil)

	return nil
}

// EnableMFA enables multi-factor authentication for a user
func (as *AuthService) EnableMFA(ctx context.Context, userID string) (string, []string, error) {
	// Generate secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Pat Email Platform",
		AccountName: userID,
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Generate recovery codes
	recoveryCodes, err := as.generateRecoveryCodes()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate recovery codes: %w", err)
	}

	// Update user with MFA secret and recovery codes
	err = as.userRepo.SetMFASecret(ctx, userID, key.Secret())
	if err != nil {
		return "", nil, fmt.Errorf("failed to set MFA secret: %w", err)
	}

	err = as.userRepo.UpdateRecoveryCodes(ctx, userID, recoveryCodes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to update recovery codes: %w", err)
	}

	return key.URL(), recoveryCodes, nil
}

// VerifyMFA verifies MFA setup
func (as *AuthService) VerifyMFA(ctx context.Context, userID, code string) error {
	user, err := as.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Verify TOTP code
	valid := totp.Validate(code, user.MFASecret)
	if !valid {
		return fmt.Errorf("invalid MFA code")
	}

	// Enable MFA for user
	user.MFAEnabled = true
	err = as.userRepo.Update(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to enable MFA: %w", err)
	}

	// Log audit event
	as.logAuditEvent(ctx, userID, user.TenantID, "user.enable_mfa", "user", userID, "", "", nil)

	return nil
}

// generateRecoveryCodes generates recovery codes for MFA
func (as *AuthService) generateRecoveryCodes() ([]string, error) {
	codes := make([]string, 8)
	for i := range codes {
		// Generate 8 bytes of random data
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		// Encode as base32 and format
		codes[i] = base32.StdEncoding.EncodeToString(bytes)[:8]
	}
	return codes, nil
}

// verifyRecoveryCode verifies and uses a recovery code
func (as *AuthService) verifyRecoveryCode(ctx context.Context, userID, code string) bool {
	recoveryCodes, err := as.userRepo.GetRecoveryCodes(ctx, userID)
	if err != nil {
		return false
	}

	// Check if code exists and remove it
	for i, recoveryCode := range recoveryCodes {
		if recoveryCode == code {
			// Remove the used code
			recoveryCodes = append(recoveryCodes[:i], recoveryCodes[i+1:]...)
			as.userRepo.UpdateRecoveryCodes(ctx, userID, recoveryCodes)
			return true
		}
	}

	return false
}

// logLoginAttempt logs a login attempt
func (as *AuthService) logLoginAttempt(ctx context.Context, email, ipAddress, userAgent string, successful bool, failReason string) {
	// Implementation would log to database
	// This is a placeholder
}

// logAuditEvent logs an audit event
func (as *AuthService) logAuditEvent(ctx context.Context, userID, tenantID, action, resource, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
	auditLog := &AuditLog{
		ID:         uuid.New().String(),
		UserID:     userID,
		TenantID:   tenantID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Metadata:   metadata,
		CreatedAt:  time.Now(),
	}

	as.auditRepo.Create(ctx, auditLog)
}

// User service methods (implement UserService interface)
func (as *AuthService) GetUserByID(ctx context.Context, userID string) (*User, error) {
	return as.userRepo.GetByID(ctx, userID)
}

func (as *AuthService) UpdateLastLogin(ctx context.Context, userID string, loginTime time.Time) error {
	return as.userRepo.UpdateLastLogin(ctx, userID, loginTime)
}

// Tenant service methods (implement TenantService interface)
func (as *AuthService) GetTenantByID(ctx context.Context, tenantID string) (*Tenant, error) {
	return as.tenantRepo.GetByID(ctx, tenantID)
}