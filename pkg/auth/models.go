package auth

import (
	"time"
	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID             string    `json:"id" db:"id"`
	Email          string    `json:"email" db:"email"`
	Name           string    `json:"name" db:"name"`
	PasswordHash   string    `json:"-" db:"password_hash"`
	TenantID       string    `json:"tenant_id" db:"tenant_id"`
	Roles          []string  `json:"roles" db:"roles"`
	IsActive       bool      `json:"is_active" db:"is_active"`
	EmailVerified  bool      `json:"email_verified" db:"email_verified"`
	Settings       map[string]interface{} `json:"settings" db:"settings"`
	LastLoginAt    *time.Time `json:"last_login_at" db:"last_login_at"`
	PasswordResetToken *string `json:"-" db:"password_reset_token"`
	PasswordResetExpires *time.Time `json:"-" db:"password_reset_expires"`
	EmailVerificationToken *string `json:"-" db:"email_verification_token"`
	MFAEnabled     bool      `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret      string    `json:"-" db:"mfa_secret"`
	RecoveryCodes  []string  `json:"-" db:"recovery_codes"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// NewUser creates a new user
func NewUser(email, name, tenantID string) *User {
	return &User{
		ID:            uuid.New().String(),
		Email:         email,
		Name:          name,
		TenantID:      tenantID,
		Roles:         []string{"user"},
		IsActive:      true,
		EmailVerified: false,
		Settings:      make(map[string]interface{}),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// GetPermissions returns user permissions based on roles
func (u *User) GetPermissions() []string {
	var permissions []string
	
	for _, role := range u.Roles {
		permissions = append(permissions, getRolePermissions(role)...)
	}
	
	// Remove duplicates
	permissionSet := make(map[string]bool)
	var uniquePermissions []string
	for _, perm := range permissions {
		if !permissionSet[perm] {
			permissionSet[perm] = true
			uniquePermissions = append(uniquePermissions, perm)
		}
	}
	
	return uniquePermissions
}

// HasRole checks if user has a specific role
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission checks if user has a specific permission
func (u *User) HasPermission(permission string) bool {
	permissions := u.GetPermissions()
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// Session represents a user session
type Session struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	DeviceID     string    `json:"device_id" db:"device_id"`
	IPAddress    string    `json:"ip_address" db:"ip_address"`
	UserAgent    string    `json:"user_agent" db:"user_agent"`
	RefreshToken string    `json:"-" db:"refresh_token"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// ApiKey represents an API key for programmatic access
type ApiKey struct {
	ID          string    `json:"id" db:"id"`
	UserID      string    `json:"user_id" db:"user_id"`
	Name        string    `json:"name" db:"name"`
	KeyHash     string    `json:"-" db:"key_hash"`
	KeyPreview  string    `json:"key_preview" db:"key_preview"`
	Permissions []string  `json:"permissions" db:"permissions"`
	RateLimit   int       `json:"rate_limit" db:"rate_limit"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	ExpiresAt   *time.Time `json:"expires_at" db:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at" db:"last_used_at"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Tenant represents a tenant in the multi-tenant system
type Tenant struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Domain      string    `json:"domain" db:"domain"`
	Settings    map[string]interface{} `json:"settings" db:"settings"`
	PlanType    string    `json:"plan_type" db:"plan_type"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Role definitions and permissions
var rolePermissions = map[string][]string{
	"super_admin": {
		"*", // All permissions
	},
	"admin": {
		"emails:read", "emails:write", "emails:delete",
		"users:read", "users:write", "users:delete",
		"workflows:read", "workflows:write", "workflows:delete",
		"plugins:read", "plugins:write", "plugins:install", "plugins:uninstall",
		"templates:read", "templates:write", "templates:delete",
		"webhooks:read", "webhooks:write", "webhooks:delete",
		"settings:read", "settings:write",
		"stats:read",
		"api_keys:read", "api_keys:write", "api_keys:delete",
	},
	"moderator": {
		"emails:read", "emails:write",
		"users:read",
		"workflows:read", "workflows:write",
		"templates:read", "templates:write",
		"webhooks:read", "webhooks:write",
		"stats:read",
	},
	"user": {
		"emails:read",
		"workflows:read",
		"templates:read",
		"stats:read",
	},
	"readonly": {
		"emails:read",
		"workflows:read",
		"templates:read",
		"stats:read",
	},
	"api_user": {
		"emails:read", "emails:write",
		"workflows:read", "workflows:write", "workflows:execute",
		"templates:read", "templates:write",
	},
}

// getRolePermissions returns permissions for a given role
func getRolePermissions(role string) []string {
	if perms, exists := rolePermissions[role]; exists {
		return perms
	}
	return []string{} // No permissions for unknown roles
}

// Permission constants
const (
	// Email permissions
	PermEmailRead   = "emails:read"
	PermEmailWrite  = "emails:write"
	PermEmailDelete = "emails:delete"

	// User permissions
	PermUserRead   = "users:read"
	PermUserWrite  = "users:write"
	PermUserDelete = "users:delete"

	// Workflow permissions
	PermWorkflowRead    = "workflows:read"
	PermWorkflowWrite   = "workflows:write"
	PermWorkflowDelete  = "workflows:delete"
	PermWorkflowExecute = "workflows:execute"

	// Plugin permissions
	PermPluginRead      = "plugins:read"
	PermPluginWrite     = "plugins:write"
	PermPluginInstall   = "plugins:install"
	PermPluginUninstall = "plugins:uninstall"

	// Template permissions
	PermTemplateRead   = "templates:read"
	PermTemplateWrite  = "templates:write"
	PermTemplateDelete = "templates:delete"

	// Webhook permissions
	PermWebhookRead   = "webhooks:read"
	PermWebhookWrite  = "webhooks:write"
	PermWebhookDelete = "webhooks:delete"

	// Settings permissions
	PermSettingsRead  = "settings:read"
	PermSettingsWrite = "settings:write"

	// Stats permissions
	PermStatsRead = "stats:read"

	// API key permissions
	PermApiKeyRead   = "api_keys:read"
	PermApiKeyWrite  = "api_keys:write"
	PermApiKeyDelete = "api_keys:delete"

	// Super admin permission
	PermAll = "*"
)

// AuditLog represents an audit log entry
type AuditLog struct {
	ID         string    `json:"id" db:"id"`
	UserID     string    `json:"user_id" db:"user_id"`
	TenantID   string    `json:"tenant_id" db:"tenant_id"`
	Action     string    `json:"action" db:"action"`
	Resource   string    `json:"resource" db:"resource"`
	ResourceID string    `json:"resource_id" db:"resource_id"`
	IPAddress  string    `json:"ip_address" db:"ip_address"`
	UserAgent  string    `json:"user_agent" db:"user_agent"`
	Metadata   map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// LoginAttempt represents a login attempt for security monitoring
type LoginAttempt struct {
	ID         string    `json:"id" db:"id"`
	Email      string    `json:"email" db:"email"`
	IPAddress  string    `json:"ip_address" db:"ip_address"`
	UserAgent  string    `json:"user_agent" db:"user_agent"`
	Successful bool      `json:"successful" db:"successful"`
	FailReason string    `json:"fail_reason" db:"fail_reason"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}