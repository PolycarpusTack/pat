package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FortressRole represents fortress security roles
type FortressRole string

const (
	// Fortress Role Hierarchy (from highest to lowest authority)
	RoleCommander   FortressRole = "commander"   // Supreme authority - all permissions
	RoleGuardian    FortressRole = "guardian"    // Administrative authority
	RoleSentinel    FortressRole = "sentinel"    // Monitoring and moderation authority
	RoleObserver    FortressRole = "observer"    // Read-only access
	RoleApiUser     FortressRole = "api_user"    // Programmatic access
	RoleFortressBot FortressRole = "fortress_bot" // System automation
)

// FortressPermission represents fortress permissions
type FortressPermission string

const (
	// Email Fortress Permissions
	PermFortressEmailRead     FortressPermission = "fortress:email:read"
	PermFortressEmailWrite    FortressPermission = "fortress:email:write"
	PermFortressEmailDelete   FortressPermission = "fortress:email:delete"
	PermFortressEmailRelease  FortressPermission = "fortress:email:release"
	PermFortressEmailQuarantine FortressPermission = "fortress:email:quarantine"

	// User Management Fortress Permissions
	PermFortressUserRead      FortressPermission = "fortress:user:read"
	PermFortressUserWrite     FortressPermission = "fortress:user:write"
	PermFortressUserDelete    FortressPermission = "fortress:user:delete"
	PermFortressUserPromote   FortressPermission = "fortress:user:promote"
	PermFortressUserDemote    FortressPermission = "fortress:user:demote"
	PermFortressUserBan       FortressPermission = "fortress:user:ban"

	// Workflow Fortress Permissions
	PermFortressWorkflowRead    FortressPermission = "fortress:workflow:read"
	PermFortressWorkflowWrite   FortressPermission = "fortress:workflow:write"
	PermFortressWorkflowDelete  FortressPermission = "fortress:workflow:delete"
	PermFortressWorkflowExecute FortressPermission = "fortress:workflow:execute"
	PermFortressWorkflowDeploy  FortressPermission = "fortress:workflow:deploy"

	// Plugin Fortress Permissions
	PermFortressPluginRead      FortressPermission = "fortress:plugin:read"
	PermFortressPluginWrite     FortressPermission = "fortress:plugin:write"
	PermFortressPluginInstall   FortressPermission = "fortress:plugin:install"
	PermFortressPluginUninstall FortressPermission = "fortress:plugin:uninstall"
	PermFortressPluginConfigure FortressPermission = "fortress:plugin:configure"

	// Template Fortress Permissions
	PermFortressTemplateRead   FortressPermission = "fortress:template:read"
	PermFortressTemplateWrite  FortressPermission = "fortress:template:write"
	PermFortressTemplateDelete FortressPermission = "fortress:template:delete"
	PermFortressTemplatePublish FortressPermission = "fortress:template:publish"

	// Security Fortress Permissions
	PermFortressSecurityRead    FortressPermission = "fortress:security:read"
	PermFortressSecurityWrite   FortressPermission = "fortress:security:write"
	PermFortressSecurityAudit   FortressPermission = "fortress:security:audit"
	PermFortressSecurityIncident FortressPermission = "fortress:security:incident"

	// System Fortress Permissions
	PermFortressSystemRead     FortressPermission = "fortress:system:read"
	PermFortressSystemWrite    FortressPermission = "fortress:system:write"
	PermFortressSystemMaintain FortressPermission = "fortress:system:maintain"
	PermFortressSystemBackup   FortressPermission = "fortress:system:backup"

	// API Key Fortress Permissions
	PermFortressApiKeyRead     FortressPermission = "fortress:apikey:read"
	PermFortressApiKeyWrite    FortressPermission = "fortress:apikey:write"
	PermFortressApiKeyDelete   FortressPermission = "fortress:apikey:delete"
	PermFortressApiKeyRotate   FortressPermission = "fortress:apikey:rotate"

	// Statistics and Analytics Fortress Permissions
	PermFortressStatsRead      FortressPermission = "fortress:stats:read"
	PermFortressStatsExport    FortressPermission = "fortress:stats:export"

	// Webhook Fortress Permissions
	PermFortressWebhookRead    FortressPermission = "fortress:webhook:read"
	PermFortressWebhookWrite   FortressPermission = "fortress:webhook:write"
	PermFortressWebhookDelete  FortressPermission = "fortress:webhook:delete"
	PermFortressWebhookTrigger FortressPermission = "fortress:webhook:trigger"

	// Supreme Permission
	PermFortressSupreme        FortressPermission = "fortress:supreme"
)

// FortressRoleDefinition represents a fortress role with its permissions
type FortressRoleDefinition struct {
	Role         FortressRole         `json:"role"`
	Name         string               `json:"name"`
	Description  string               `json:"description"`
	Level        int                  `json:"level"` // Higher number = higher authority
	Permissions  []FortressPermission `json:"permissions"`
	CanDelegate  bool                 `json:"can_delegate"`  // Can assign roles to others
	CanEscalate  bool                 `json:"can_escalate"`  // Can escalate permissions
	MaxSessions  int                  `json:"max_sessions"`  // Maximum concurrent sessions
	RequiresMFA  bool                 `json:"requires_mfa"`  // Requires multi-factor authentication
}

// FortressRoleManager manages fortress roles and permissions
type FortressRoleManager struct {
	roleDefinitions map[FortressRole]*FortressRoleDefinition
	auditRepo       AuditRepository
}

// NewFortressRoleManager creates a new fortress role manager
func NewFortressRoleManager(auditRepo AuditRepository) *FortressRoleManager {
	frm := &FortressRoleManager{
		roleDefinitions: make(map[FortressRole]*FortressRoleDefinition),
		auditRepo:       auditRepo,
	}

	// Initialize fortress role definitions
	frm.initializeFortressRoles()

	return frm
}

// initializeFortressRoles initializes the fortress role hierarchy
func (frm *FortressRoleManager) initializeFortressRoles() {
	// Commander - Supreme authority
	frm.roleDefinitions[RoleCommander] = &FortressRoleDefinition{
		Role:        RoleCommander,
		Name:        "Fortress Commander",
		Description: "Supreme fortress authority with all permissions",
		Level:       100,
		Permissions: []FortressPermission{PermFortressSupreme}, // Supreme permission grants all
		CanDelegate: true,
		CanEscalate: true,
		MaxSessions: 10,
		RequiresMFA: true,
	}

	// Guardian - Administrative authority
	frm.roleDefinitions[RoleGuardian] = &FortressRoleDefinition{
		Role:        RoleGuardian,
		Name:        "Fortress Guardian",
		Description: "Administrative authority for fortress operations",
		Level:       80,
		Permissions: []FortressPermission{
			// Email permissions
			PermFortressEmailRead, PermFortressEmailWrite, PermFortressEmailDelete, PermFortressEmailRelease,
			// User management (except ban/promote/demote)
			PermFortressUserRead, PermFortressUserWrite,
			// Workflow permissions
			PermFortressWorkflowRead, PermFortressWorkflowWrite, PermFortressWorkflowDelete, PermFortressWorkflowExecute,
			// Plugin permissions
			PermFortressPluginRead, PermFortressPluginWrite, PermFortressPluginInstall, PermFortressPluginUninstall, PermFortressPluginConfigure,
			// Template permissions
			PermFortressTemplateRead, PermFortressTemplateWrite, PermFortressTemplateDelete, PermFortressTemplatePublish,
			// Security read access
			PermFortressSecurityRead, PermFortressSecurityAudit,
			// System read and write
			PermFortressSystemRead, PermFortressSystemWrite,
			// API key management
			PermFortressApiKeyRead, PermFortressApiKeyWrite, PermFortressApiKeyDelete, PermFortressApiKeyRotate,
			// Stats and analytics
			PermFortressStatsRead, PermFortressStatsExport,
			// Webhooks
			PermFortressWebhookRead, PermFortressWebhookWrite, PermFortressWebhookDelete, PermFortressWebhookTrigger,
		},
		CanDelegate: true,
		CanEscalate: false,
		MaxSessions: 5,
		RequiresMFA: true,
	}

	// Sentinel - Monitoring and moderation authority
	frm.roleDefinitions[RoleSentinel] = &FortressRoleDefinition{
		Role:        RoleSentinel,
		Name:        "Fortress Sentinel",
		Description: "Monitoring and moderation authority",
		Level:       60,
		Permissions: []FortressPermission{
			// Email permissions (read/write, limited delete)
			PermFortressEmailRead, PermFortressEmailWrite, PermFortressEmailQuarantine,
			// User read access
			PermFortressUserRead,
			// Workflow permissions
			PermFortressWorkflowRead, PermFortressWorkflowWrite, PermFortressWorkflowExecute,
			// Template permissions
			PermFortressTemplateRead, PermFortressTemplateWrite,
			// Security read and audit
			PermFortressSecurityRead, PermFortressSecurityAudit,
			// System read
			PermFortressSystemRead,
			// API key read
			PermFortressApiKeyRead,
			// Stats
			PermFortressStatsRead,
			// Webhooks read/write
			PermFortressWebhookRead, PermFortressWebhookWrite, PermFortressWebhookTrigger,
		},
		CanDelegate: false,
		CanEscalate: false,
		MaxSessions: 3,
		RequiresMFA: true,
	}

	// Observer - Read-only access
	frm.roleDefinitions[RoleObserver] = &FortressRoleDefinition{
		Role:        RoleObserver,
		Name:        "Fortress Observer",
		Description: "Read-only access to fortress systems",
		Level:       40,
		Permissions: []FortressPermission{
			// Read-only permissions
			PermFortressEmailRead,
			PermFortressUserRead,
			PermFortressWorkflowRead,
			PermFortressPluginRead,
			PermFortressTemplateRead,
			PermFortressSecurityRead,
			PermFortressSystemRead,
			PermFortressApiKeyRead,
			PermFortressStatsRead,
			PermFortressWebhookRead,
		},
		CanDelegate: false,
		CanEscalate: false,
		MaxSessions: 2,
		RequiresMFA: false,
	}

	// API User - Programmatic access
	frm.roleDefinitions[RoleApiUser] = &FortressRoleDefinition{
		Role:        RoleApiUser,
		Name:        "Fortress API User",
		Description: "Programmatic access for API operations",
		Level:       20,
		Permissions: []FortressPermission{
			// API-specific permissions
			PermFortressEmailRead, PermFortressEmailWrite,
			PermFortressWorkflowRead, PermFortressWorkflowExecute,
			PermFortressTemplateRead,
			PermFortressStatsRead,
			PermFortressWebhookTrigger,
		},
		CanDelegate: false,
		CanEscalate: false,
		MaxSessions: 50, // Higher for API usage
		RequiresMFA: false,
	}

	// Fortress Bot - System automation
	frm.roleDefinitions[RoleFortressBot] = &FortressRoleDefinition{
		Role:        RoleFortressBot,
		Name:        "Fortress Bot",
		Description: "System automation and background tasks",
		Level:       10,
		Permissions: []FortressPermission{
			// Bot-specific permissions
			PermFortressEmailRead,
			PermFortressWorkflowExecute,
			PermFortressSystemMaintain, PermFortressSystemBackup,
			PermFortressStatsRead,
		},
		CanDelegate: false,
		CanEscalate: false,
		MaxSessions: 1,
		RequiresMFA: false,
	}
}

// GuardValidatePermission validates if a user has a specific permission
func (frm *FortressRoleManager) GuardValidatePermission(user *User, permission FortressPermission) bool {
	// Convert legacy roles to fortress roles
	fortressRoles := frm.convertLegacyRoles(user.Roles)

	// Check if user has supreme permission
	if frm.hasSupremePermission(fortressRoles) {
		return true
	}

	// Check specific permission
	return frm.hasPermission(fortressRoles, permission)
}

// SentinelValidateRole validates if a user has a specific role
func (frm *FortressRoleManager) SentinelValidateRole(user *User, role FortressRole) bool {
	fortressRoles := frm.convertLegacyRoles(user.Roles)

	for _, userRole := range fortressRoles {
		if userRole == role {
			return true
		}

		// Check if user has a higher-level role
		userRoleDef, exists := frm.roleDefinitions[userRole]
		if !exists {
			continue
		}

		requiredRoleDef, exists := frm.roleDefinitions[role]
		if !exists {
			continue
		}

		if userRoleDef.Level >= requiredRoleDef.Level {
			return true
		}
	}

	return false
}

// CommanderAssignRole assigns a fortress role to a user
func (frm *FortressRoleManager) CommanderAssignRole(ctx context.Context, assignerID string, targetUserID string, role FortressRole, reason string) error {
	// Validate that assigner can delegate roles
	// This would need to be implemented with user lookup

	// Log role assignment
	frm.logSecurityEvent(ctx, assignerID, "fortress.role.assigned", targetUserID, "", "", map[string]interface{}{
		"target_user": targetUserID,
		"role":        string(role),
		"reason":      reason,
	})

	return nil
}

// GuardRevokeRole revokes a fortress role from a user
func (frm *FortressRoleManager) GuardRevokeRole(ctx context.Context, revokerID string, targetUserID string, role FortressRole, reason string) error {
	// Log role revocation
	frm.logSecurityEvent(ctx, revokerID, "fortress.role.revoked", targetUserID, "", "", map[string]interface{}{
		"target_user": targetUserID,
		"role":        string(role),
		"reason":      reason,
	})

	return nil
}

// GetFortressRoleDefinition returns the definition of a fortress role
func (frm *FortressRoleManager) GetFortressRoleDefinition(role FortressRole) (*FortressRoleDefinition, bool) {
	roleDef, exists := frm.roleDefinitions[role]
	return roleDef, exists
}

// WatchtowerListRoles lists all fortress roles
func (frm *FortressRoleManager) WatchtowerListRoles() []*FortressRoleDefinition {
	roles := make([]*FortressRoleDefinition, 0, len(frm.roleDefinitions))
	for _, roleDef := range frm.roleDefinitions {
		roles = append(roles, roleDef)
	}
	return roles
}

// SentinelValidateEscalation validates if a role escalation is allowed
func (frm *FortressRoleManager) SentinelValidateEscalation(currentRoles []FortressRole, targetRole FortressRole) bool {
	// Get the highest level role of the user
	maxLevel := 0
	canEscalate := false

	for _, role := range currentRoles {
		if roleDef, exists := frm.roleDefinitions[role]; exists {
			if roleDef.Level > maxLevel {
				maxLevel = roleDef.Level
				canEscalate = roleDef.CanEscalate
			}
		}
	}

	// User must have escalation privileges
	if !canEscalate {
		return false
	}

	// Target role must be at or below current level
	if targetRoleDef, exists := frm.roleDefinitions[targetRole]; exists {
		return maxLevel >= targetRoleDef.Level
	}

	return false
}

// convertLegacyRoles converts legacy role strings to fortress roles
func (frm *FortressRoleManager) convertLegacyRoles(legacyRoles []string) []FortressRole {
	var fortressRoles []FortressRole

	for _, legacyRole := range legacyRoles {
		switch strings.ToLower(legacyRole) {
		case "super_admin":
			fortressRoles = append(fortressRoles, RoleCommander)
		case "admin":
			fortressRoles = append(fortressRoles, RoleGuardian)
		case "moderator":
			fortressRoles = append(fortressRoles, RoleSentinel)
		case "user", "readonly":
			fortressRoles = append(fortressRoles, RoleObserver)
		case "api_user":
			fortressRoles = append(fortressRoles, RoleApiUser)
		default:
			// Try to parse as fortress role directly
			if role := FortressRole(legacyRole); frm.isValidFortressRole(role) {
				fortressRoles = append(fortressRoles, role)
			}
		}
	}

	// If no valid roles found, assign Observer as default
	if len(fortressRoles) == 0 {
		fortressRoles = append(fortressRoles, RoleObserver)
	}

	return fortressRoles
}

// hasSupremePermission checks if user has supreme permission
func (frm *FortressRoleManager) hasSupremePermission(roles []FortressRole) bool {
	for _, role := range roles {
		if roleDef, exists := frm.roleDefinitions[role]; exists {
			for _, perm := range roleDef.Permissions {
				if perm == PermFortressSupreme {
					return true
				}
			}
		}
	}
	return false
}

// hasPermission checks if user has a specific permission
func (frm *FortressRoleManager) hasPermission(roles []FortressRole, permission FortressPermission) bool {
	for _, role := range roles {
		if roleDef, exists := frm.roleDefinitions[role]; exists {
			for _, perm := range roleDef.Permissions {
				if perm == permission {
					return true
				}
			}
		}
	}
	return false
}

// isValidFortressRole checks if a string is a valid fortress role
func (frm *FortressRoleManager) isValidFortressRole(role FortressRole) bool {
	_, exists := frm.roleDefinitions[role]
	return exists
}

// logSecurityEvent logs a security event for audit purposes
func (frm *FortressRoleManager) logSecurityEvent(ctx context.Context, userID, action, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
	if frm.auditRepo == nil {
		return
	}

	auditLog := &AuditLog{
		ID:         uuid.New().String(),
		UserID:     userID,
		TenantID:   "", // Will be populated by caller if available
		Action:     action,
		Resource:   "fortress_role",
		ResourceID: resourceID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Metadata:   metadata,
		CreatedAt:  time.Now(),
	}

	// Fire and forget - don't block on audit logging
	go func() {
		if err := frm.auditRepo.Create(context.Background(), auditLog); err != nil {
			// Log error but don't fail the operation
			fmt.Printf("Failed to create audit log: %v\n", err)
		}
	}()
}