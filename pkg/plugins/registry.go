package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// PluginMetadata represents plugin information
type PluginMetadata struct {
	ID           string            `json:"id" db:"id"`
	Name         string            `json:"name" db:"name"`
	Version      string            `json:"version" db:"version"`
	Author       string            `json:"author" db:"author"`
	Description  string            `json:"description" db:"description"`
	Category     string            `json:"category" db:"category"`
	Tags         []string          `json:"tags" db:"tags"`
	Permissions  []string          `json:"permissions" db:"permissions"`
	Dependencies []string          `json:"dependencies" db:"dependencies"`
	Hooks        []string          `json:"hooks" db:"hooks"`
	Config       map[string]string `json:"config" db:"config"`
	MaxMemory    int               `json:"max_memory" db:"max_memory"`
	MaxCPUTime   int               `json:"max_cpu_time" db:"max_cpu_time"`
	CodeHash     string            `json:"code_hash" db:"code_hash"`
	Signature    string            `json:"signature" db:"signature"`
	Status       PluginStatus      `json:"status" db:"status"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at" db:"updated_at"`
}

// PluginCode represents the plugin's executable code
type PluginCode struct {
	PluginID  string    `json:"plugin_id" db:"plugin_id"`
	Version   string    `json:"version" db:"version"`
	Code      string    `json:"code" db:"code"`
	Hash      string    `json:"hash" db:"hash"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// PluginInstallation represents plugin installation per tenant
type PluginInstallation struct {
	ID         string                 `json:"id" db:"id"`
	TenantID   string                 `json:"tenant_id" db:"tenant_id"`
	PluginID   string                 `json:"plugin_id" db:"plugin_id"`
	Version    string                 `json:"version" db:"version"`
	Config     map[string]interface{} `json:"config" db:"config"`
	Enabled    bool                   `json:"enabled" db:"enabled"`
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at" db:"updated_at"`
}

// PluginStatus represents plugin lifecycle status
type PluginStatus string

const (
	PluginStatusDraft     PluginStatus = "draft"
	PluginStatusReview    PluginStatus = "review"
	PluginStatusApproved  PluginStatus = "approved"
	PluginStatusPublished PluginStatus = "published"
	PluginStatusRejected  PluginStatus = "rejected"
	PluginStatusSuspended PluginStatus = "suspended"
	PluginStatusDeprecated PluginStatus = "deprecated"
)

// Registry manages plugin lifecycle and storage
type Registry struct {
	db        Database
	validator *Validator
	security  *SecurityScanner
	logger    Logger
}

// NewRegistry creates a new plugin registry
func NewRegistry(db Database, validator *Validator, security *SecurityScanner, logger Logger) *Registry {
	return &Registry{
		db:        db,
		validator: validator,
		security:  security,
		logger:    logger,
	}
}

// RegisterPlugin registers a new plugin
func (r *Registry) RegisterPlugin(ctx context.Context, metadata *PluginMetadata, code string) error {
	// Generate plugin ID
	metadata.ID = uuid.New().String()
	metadata.CreatedAt = time.Now()
	metadata.UpdatedAt = time.Now()
	metadata.Status = PluginStatusDraft

	// Validate plugin metadata
	if err := r.validator.ValidateMetadata(metadata); err != nil {
		return errors.Wrap(err, "plugin metadata validation failed")
	}

	// Validate plugin code
	if err := r.validator.ValidateCode(code, metadata); err != nil {
		return errors.Wrap(err, "plugin code validation failed")
	}

	// Security scan
	scanResult, err := r.security.ScanPlugin(code, metadata)
	if err != nil {
		return errors.Wrap(err, "plugin security scan failed")
	}

	if scanResult.HasVulnerabilities() {
		return errors.New("plugin contains security vulnerabilities")
	}

	// Generate code hash
	hash := sha256.Sum256([]byte(code))
	metadata.CodeHash = hex.EncodeToString(hash[:])

	// Store plugin metadata
	if err := r.db.CreatePlugin(ctx, metadata); err != nil {
		return errors.Wrap(err, "failed to store plugin metadata")
	}

	// Store plugin code
	pluginCode := &PluginCode{
		PluginID:  metadata.ID,
		Version:   metadata.Version,
		Code:      code,
		Hash:      metadata.CodeHash,
		CreatedAt: time.Now(),
	}

	if err := r.db.CreatePluginCode(ctx, pluginCode); err != nil {
		// Rollback metadata
		r.db.DeletePlugin(ctx, metadata.ID)
		return errors.Wrap(err, "failed to store plugin code")
	}

	r.logger.Info("Plugin registered successfully", map[string]interface{}{
		"plugin_id": metadata.ID,
		"name":      metadata.Name,
		"version":   metadata.Version,
		"author":    metadata.Author,
	})

	return nil
}

// UpdatePlugin updates an existing plugin
func (r *Registry) UpdatePlugin(ctx context.Context, pluginID string, metadata *PluginMetadata, code string) error {
	// Get existing plugin
	existing, err := r.db.GetPlugin(ctx, pluginID)
	if err != nil {
		return errors.Wrap(err, "plugin not found")
	}

	// Check if author matches
	if existing.Author != metadata.Author {
		return errors.New("only plugin author can update")
	}

	// Validate version is newer
	if !r.isVersionNewer(metadata.Version, existing.Version) {
		return errors.New("new version must be greater than current version")
	}

	// Validate plugin metadata
	if err := r.validator.ValidateMetadata(metadata); err != nil {
		return errors.Wrap(err, "plugin metadata validation failed")
	}

	// Validate plugin code
	if err := r.validator.ValidateCode(code, metadata); err != nil {
		return errors.Wrap(err, "plugin code validation failed")
	}

	// Security scan
	scanResult, err := r.security.ScanPlugin(code, metadata)
	if err != nil {
		return errors.Wrap(err, "plugin security scan failed")
	}

	if scanResult.HasVulnerabilities() {
		return errors.New("plugin contains security vulnerabilities")
	}

	// Generate code hash
	hash := sha256.Sum256([]byte(code))
	metadata.CodeHash = hex.EncodeToString(hash[:])
	metadata.ID = pluginID
	metadata.UpdatedAt = time.Now()
	metadata.Status = PluginStatusReview // Reset to review on update

	// Update plugin metadata
	if err := r.db.UpdatePlugin(ctx, metadata); err != nil {
		return errors.Wrap(err, "failed to update plugin metadata")
	}

	// Store new plugin code version
	pluginCode := &PluginCode{
		PluginID:  pluginID,
		Version:   metadata.Version,
		Code:      code,
		Hash:      metadata.CodeHash,
		CreatedAt: time.Now(),
	}

	if err := r.db.CreatePluginCode(ctx, pluginCode); err != nil {
		return errors.Wrap(err, "failed to store plugin code")
	}

	r.logger.Info("Plugin updated successfully", map[string]interface{}{
		"plugin_id": pluginID,
		"version":   metadata.Version,
	})

	return nil
}

// GetPlugin retrieves plugin metadata
func (r *Registry) GetPlugin(ctx context.Context, pluginID string) (*PluginMetadata, error) {
	return r.db.GetPlugin(ctx, pluginID)
}

// GetPluginCode retrieves plugin code for a specific version
func (r *Registry) GetPluginCode(ctx context.Context, pluginID, version string) (*PluginCode, error) {
	return r.db.GetPluginCode(ctx, pluginID, version)
}

// ListPlugins lists plugins with pagination and filtering
func (r *Registry) ListPlugins(ctx context.Context, filter *PluginFilter) ([]*PluginMetadata, error) {
	return r.db.ListPlugins(ctx, filter)
}

// SearchPlugins searches plugins by keyword
func (r *Registry) SearchPlugins(ctx context.Context, query string, limit int) ([]*PluginMetadata, error) {
	return r.db.SearchPlugins(ctx, query, limit)
}

// InstallPlugin installs a plugin for a tenant
func (r *Registry) InstallPlugin(ctx context.Context, tenantID, pluginID, version string, config map[string]interface{}) error {
	// Check if plugin exists and is published
	plugin, err := r.db.GetPlugin(ctx, pluginID)
	if err != nil {
		return errors.Wrap(err, "plugin not found")
	}

	if plugin.Status != PluginStatusPublished {
		return errors.New("plugin is not published")
	}

	// Validate dependencies
	if err := r.validateDependencies(ctx, tenantID, plugin.Dependencies); err != nil {
		return errors.Wrap(err, "dependency validation failed")
	}

	// Check if already installed
	existing, err := r.db.GetPluginInstallation(ctx, tenantID, pluginID)
	if err == nil && existing != nil {
		return errors.New("plugin already installed")
	}

	// Create installation record
	installation := &PluginInstallation{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		PluginID:  pluginID,
		Version:   version,
		Config:    config,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := r.db.CreatePluginInstallation(ctx, installation); err != nil {
		return errors.Wrap(err, "failed to create plugin installation")
	}

	r.logger.Info("Plugin installed successfully", map[string]interface{}{
		"tenant_id": tenantID,
		"plugin_id": pluginID,
		"version":   version,
	})

	return nil
}

// UninstallPlugin removes a plugin installation for a tenant
func (r *Registry) UninstallPlugin(ctx context.Context, tenantID, pluginID string) error {
	if err := r.db.DeletePluginInstallation(ctx, tenantID, pluginID); err != nil {
		return errors.Wrap(err, "failed to uninstall plugin")
	}

	r.logger.Info("Plugin uninstalled successfully", map[string]interface{}{
		"tenant_id": tenantID,
		"plugin_id": pluginID,
	})

	return nil
}

// GetTenantPlugins retrieves all installed plugins for a tenant
func (r *Registry) GetTenantPlugins(ctx context.Context, tenantID string) ([]*PluginInstallation, error) {
	return r.db.GetTenantPlugins(ctx, tenantID)
}

// ApprovePlugin approves a plugin for publication
func (r *Registry) ApprovePlugin(ctx context.Context, pluginID string, reviewerID string) error {
	plugin, err := r.db.GetPlugin(ctx, pluginID)
	if err != nil {
		return errors.Wrap(err, "plugin not found")
	}

	if plugin.Status != PluginStatusReview {
		return errors.New("plugin is not in review status")
	}

	plugin.Status = PluginStatusApproved
	plugin.UpdatedAt = time.Now()

	if err := r.db.UpdatePlugin(ctx, plugin); err != nil {
		return errors.Wrap(err, "failed to approve plugin")
	}

	// Log approval
	r.logger.Info("Plugin approved", map[string]interface{}{
		"plugin_id":   pluginID,
		"reviewer_id": reviewerID,
	})

	return nil
}

// PublishPlugin publishes an approved plugin
func (r *Registry) PublishPlugin(ctx context.Context, pluginID string) error {
	plugin, err := r.db.GetPlugin(ctx, pluginID)
	if err != nil {
		return errors.Wrap(err, "plugin not found")
	}

	if plugin.Status != PluginStatusApproved {
		return errors.New("plugin is not approved for publication")
	}

	plugin.Status = PluginStatusPublished
	plugin.UpdatedAt = time.Now()

	if err := r.db.UpdatePlugin(ctx, plugin); err != nil {
		return errors.Wrap(err, "failed to publish plugin")
	}

	r.logger.Info("Plugin published", map[string]interface{}{
		"plugin_id": pluginID,
	})

	return nil
}

// RejectPlugin rejects a plugin
func (r *Registry) RejectPlugin(ctx context.Context, pluginID string, reason string, reviewerID string) error {
	plugin, err := r.db.GetPlugin(ctx, pluginID)
	if err != nil {
		return errors.Wrap(err, "plugin not found")
	}

	plugin.Status = PluginStatusRejected
	plugin.UpdatedAt = time.Now()

	if err := r.db.UpdatePlugin(ctx, plugin); err != nil {
		return errors.Wrap(err, "failed to reject plugin")
	}

	// Log rejection
	r.logger.Info("Plugin rejected", map[string]interface{}{
		"plugin_id":   pluginID,
		"reason":      reason,
		"reviewer_id": reviewerID,
	})

	return nil
}

// SuspendPlugin suspends a published plugin
func (r *Registry) SuspendPlugin(ctx context.Context, pluginID string, reason string) error {
	plugin, err := r.db.GetPlugin(ctx, pluginID)
	if err != nil {
		return errors.Wrap(err, "plugin not found")
	}

	plugin.Status = PluginStatusSuspended
	plugin.UpdatedAt = time.Now()

	if err := r.db.UpdatePlugin(ctx, plugin); err != nil {
		return errors.Wrap(err, "failed to suspend plugin")
	}

	r.logger.Info("Plugin suspended", map[string]interface{}{
		"plugin_id": pluginID,
		"reason":    reason,
	})

	return nil
}

// validateDependencies checks if all plugin dependencies are installed
func (r *Registry) validateDependencies(ctx context.Context, tenantID string, dependencies []string) error {
	if len(dependencies) == 0 {
		return nil
	}

	tenantPlugins, err := r.db.GetTenantPlugins(ctx, tenantID)
	if err != nil {
		return err
	}

	installedPlugins := make(map[string]bool)
	for _, installation := range tenantPlugins {
		if installation.Enabled {
			installedPlugins[installation.PluginID] = true
		}
	}

	for _, depID := range dependencies {
		if !installedPlugins[depID] {
			return fmt.Errorf("dependency not installed: %s", depID)
		}
	}

	return nil
}

// isVersionNewer compares semantic versions (simplified)
func (r *Registry) isVersionNewer(newVersion, currentVersion string) bool {
	// This is a simplified version comparison
	// In production, use a proper semver library
	return newVersion > currentVersion
}

// PluginFilter represents filtering options for plugin listing
type PluginFilter struct {
	Category string         `json:"category"`
	Author   string         `json:"author"`
	Status   PluginStatus   `json:"status"`
	Tags     []string       `json:"tags"`
	Limit    int            `json:"limit"`
	Offset   int            `json:"offset"`
}

// Database interface for plugin storage
type Database interface {
	CreatePlugin(ctx context.Context, plugin *PluginMetadata) error
	UpdatePlugin(ctx context.Context, plugin *PluginMetadata) error
	GetPlugin(ctx context.Context, pluginID string) (*PluginMetadata, error)
	DeletePlugin(ctx context.Context, pluginID string) error
	ListPlugins(ctx context.Context, filter *PluginFilter) ([]*PluginMetadata, error)
	SearchPlugins(ctx context.Context, query string, limit int) ([]*PluginMetadata, error)
	
	CreatePluginCode(ctx context.Context, code *PluginCode) error
	GetPluginCode(ctx context.Context, pluginID, version string) (*PluginCode, error)
	
	CreatePluginInstallation(ctx context.Context, installation *PluginInstallation) error
	GetPluginInstallation(ctx context.Context, tenantID, pluginID string) (*PluginInstallation, error)
	DeletePluginInstallation(ctx context.Context, tenantID, pluginID string) error
	GetTenantPlugins(ctx context.Context, tenantID string) ([]*PluginInstallation, error)
}

// Logger interface
type Logger interface {
	Info(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Debug(msg string, fields map[string]interface{})
}