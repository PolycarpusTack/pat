// Package security implements fortress-grade security configuration management
// FORTRESS CONFIG SYSTEM - Centralized security configuration and management
package security

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// FortressConfig represents the complete fortress security configuration
type FortressConfig struct {
	// Rate limiting configuration
	RateLimit *RampartLimiterConfig `json:"rate_limit"`
	
	// Input validation configuration
	Validator *FortressValidatorConfig `json:"validator"`
	
	// Request security configuration
	Rampart *RampartSecurityConfig `json:"rampart"`
	
	// Monitoring and alerting configuration
	Watchtower *WatchtowerConfig `json:"watchtower"`
	
	// General fortress settings
	General *GeneralSecurityConfig `json:"general"`
	
	// Environment-specific overrides
	Environment string `json:"environment"`
	
	// Configuration metadata
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GeneralSecurityConfig defines general fortress security settings
type GeneralSecurityConfig struct {
	// Security mode
	SecurityMode         string        `json:"security_mode"` // strict, normal, permissive
	EnableDebugLogging   bool          `json:"enable_debug_logging"`
	EnableMetrics        bool          `json:"enable_metrics"`
	
	// Encryption settings
	EncryptionKey        string        `json:"encryption_key,omitempty"`
	HashAlgorithm        string        `json:"hash_algorithm"`
	
	// Session settings
	SessionTimeout       time.Duration `json:"session_timeout"`
	MaxConcurrentSessions int          `json:"max_concurrent_sessions"`
	
	// Password policy
	PasswordMinLength    int           `json:"password_min_length"`
	PasswordRequireUpper bool          `json:"password_require_upper"`
	PasswordRequireLower bool          `json:"password_require_lower"`
	PasswordRequireDigit bool          `json:"password_require_digit"`
	PasswordRequireSpecial bool        `json:"password_require_special"`
	
	// Audit settings
	EnableAuditLogging   bool          `json:"enable_audit_logging"`
	AuditRetentionDays   int           `json:"audit_retention_days"`
	
	// IP whitelist/blacklist
	IPWhitelist          []string      `json:"ip_whitelist"`
	IPBlacklist          []string      `json:"ip_blacklist"`
	
	// Maintenance mode
	MaintenanceMode      bool          `json:"maintenance_mode"`
	MaintenanceMessage   string        `json:"maintenance_message"`
	
	// Feature flags
	FeatureFlags         map[string]bool `json:"feature_flags"`
}

// DefaultGeneralSecurityConfig returns fortress-grade general configuration
func DefaultGeneralSecurityConfig() *GeneralSecurityConfig {
	return &GeneralSecurityConfig{
		SecurityMode:          "strict",
		EnableDebugLogging:    false,
		EnableMetrics:         true,
		
		HashAlgorithm:         "bcrypt",
		
		SessionTimeout:        30 * time.Minute,
		MaxConcurrentSessions: 5,
		
		PasswordMinLength:     12,
		PasswordRequireUpper:  true,
		PasswordRequireLower:  true,
		PasswordRequireDigit:  true,
		PasswordRequireSpecial: true,
		
		EnableAuditLogging:    true,
		AuditRetentionDays:    90,
		
		IPWhitelist:           []string{},
		IPBlacklist:           []string{},
		
		MaintenanceMode:       false,
		MaintenanceMessage:    "System is under maintenance. Please try again later.",
		
		FeatureFlags: map[string]bool{
			"advanced_threat_detection": true,
			"auto_emergency_mode":       true,
			"geo_blocking":             true,
			"pattern_detection":        true,
			"honeypot_system":          true,
		},
	}
}

// DefaultFortressConfig returns a complete default fortress configuration
func DefaultFortressConfig() *FortressConfig {
	now := time.Now()
	
	return &FortressConfig{
		RateLimit:   DefaultRampartConfig(),
		Validator:   DefaultValidatorConfig(),
		Rampart:     DefaultRampartSecurityConfig(),
		Watchtower:  DefaultWatchtowerConfig(),
		General:     DefaultGeneralSecurityConfig(),
		Environment: "production",
		Version:     "1.0.0",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// SecurityConfigManager manages fortress security configuration
type SecurityConfigManager struct {
	config     *FortressConfig
	configPath string
	logger     *zap.Logger
	watchers   []ConfigWatcher
}

// ConfigWatcher interface for configuration change notifications
type ConfigWatcher interface {
	OnConfigChanged(config *FortressConfig) error
}

// NewSecurityConfigManager creates a new security configuration manager
func NewSecurityConfigManager(configPath string, logger *zap.Logger) (*SecurityConfigManager, error) {
	manager := &SecurityConfigManager{
		configPath: configPath,
		logger:     logger,
		watchers:   make([]ConfigWatcher, 0),
	}
	
	// Load configuration
	if err := manager.LoadConfig(); err != nil {
		// If loading fails, use default configuration
		manager.logger.Warn("Failed to load configuration, using defaults", zap.Error(err))
		manager.config = DefaultFortressConfig()
		
		// Save default configuration
		if err := manager.SaveConfig(); err != nil {
			return nil, fmt.Errorf("failed to save default configuration: %w", err)
		}
	}
	
	return manager, nil
}

// LoadConfig loads fortress configuration from file
func (scm *SecurityConfigManager) LoadConfig() error {
	if scm.configPath == "" {
		scm.config = DefaultFortressConfig()
		return nil
	}
	
	// Check if config file exists
	if _, err := os.Stat(scm.configPath); os.IsNotExist(err) {
		scm.config = DefaultFortressConfig()
		return scm.SaveConfig()
	}
	
	// Read configuration file
	data, err := ioutil.ReadFile(scm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}
	
	// Parse JSON configuration
	var config FortressConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}
	
	// Validate configuration
	if err := scm.validateConfig(&config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Apply environment-specific overrides
	scm.applyEnvironmentOverrides(&config)
	
	scm.config = &config
	scm.logger.Info("Fortress configuration loaded successfully", 
		zap.String("version", config.Version),
		zap.String("environment", config.Environment))
	
	return nil
}

// SaveConfig saves fortress configuration to file
func (scm *SecurityConfigManager) SaveConfig() error {
	if scm.configPath == "" {
		return fmt.Errorf("no config path specified")
	}
	
	// Update timestamp
	scm.config.UpdatedAt = time.Now()
	
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(scm.configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Marshal configuration to JSON
	data, err := json.MarshalIndent(scm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}
	
	// Write configuration to file
	if err := ioutil.WriteFile(scm.configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}
	
	scm.logger.Info("Fortress configuration saved successfully",
		zap.String("path", scm.configPath))
	
	return nil
}

// UpdateConfig updates the fortress configuration
func (scm *SecurityConfigManager) UpdateConfig(newConfig *FortressConfig) error {
	if newConfig == nil {
		return fmt.Errorf("configuration cannot be nil")
	}
	
	// Validate new configuration
	if err := scm.validateConfig(newConfig); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Apply environment overrides
	scm.applyEnvironmentOverrides(newConfig)
	
	// Update configuration
	oldConfig := scm.config
	scm.config = newConfig
	scm.config.UpdatedAt = time.Now()
	
	// Save updated configuration
	if err := scm.SaveConfig(); err != nil {
		// Rollback on save failure
		scm.config = oldConfig
		return fmt.Errorf("failed to save updated configuration: %w", err)
	}
	
	// Notify watchers
	scm.notifyWatchers(newConfig)
	
	scm.logger.Info("Fortress configuration updated successfully")
	
	return nil
}

// GetConfig returns the current fortress configuration
func (scm *SecurityConfigManager) GetConfig() *FortressConfig {
	return scm.config
}

// GetRateLimitConfig returns rate limiting configuration
func (scm *SecurityConfigManager) GetRateLimitConfig() *RampartLimiterConfig {
	return scm.config.RateLimit
}

// GetValidatorConfig returns input validation configuration
func (scm *SecurityConfigManager) GetValidatorConfig() *FortressValidatorConfig {
	return scm.config.Validator
}

// GetRampartConfig returns request security configuration
func (scm *SecurityConfigManager) GetRampartConfig() *RampartSecurityConfig {
	return scm.config.Rampart
}

// GetWatchtowerConfig returns monitoring configuration
func (scm *SecurityConfigManager) GetWatchtowerConfig() *WatchtowerConfig {
	return scm.config.Watchtower
}

// GetGeneralConfig returns general security configuration
func (scm *SecurityConfigManager) GetGeneralConfig() *GeneralSecurityConfig {
	return scm.config.General
}

// AddWatcher adds a configuration change watcher
func (scm *SecurityConfigManager) AddWatcher(watcher ConfigWatcher) {
	scm.watchers = append(scm.watchers, watcher)
}

// validateConfig validates fortress configuration
func (scm *SecurityConfigManager) validateConfig(config *FortressConfig) error {
	if config.RateLimit == nil {
		return fmt.Errorf("rate limit configuration is required")
	}
	
	if config.Validator == nil {
		return fmt.Errorf("validator configuration is required")
	}
	
	if config.Rampart == nil {
		return fmt.Errorf("rampart configuration is required")
	}
	
	if config.Watchtower == nil {
		return fmt.Errorf("watchtower configuration is required")
	}
	
	if config.General == nil {
		return fmt.Errorf("general configuration is required")
	}
	
	// Validate rate limits are positive
	if config.RateLimit.GlobalRequestsPerMinute <= 0 {
		return fmt.Errorf("global requests per minute must be positive")
	}
	
	if config.RateLimit.IPRequestsPerMinute <= 0 {
		return fmt.Errorf("IP requests per minute must be positive")
	}
	
	// Validate security mode
	validModes := []string{"strict", "normal", "permissive"}
	validMode := false
	for _, mode := range validModes {
		if config.General.SecurityMode == mode {
			validMode = true
			break
		}
	}
	
	if !validMode {
		return fmt.Errorf("invalid security mode: %s", config.General.SecurityMode)
	}
	
	// Validate password policy
	if config.General.PasswordMinLength < 8 {
		return fmt.Errorf("minimum password length must be at least 8")
	}
	
	return nil
}

// applyEnvironmentOverrides applies environment-specific configuration overrides
func (scm *SecurityConfigManager) applyEnvironmentOverrides(config *FortressConfig) {
	switch config.Environment {
	case "development":
		// Relax security for development
		config.General.SecurityMode = "permissive"
		config.General.EnableDebugLogging = true
		config.RateLimit.IPRequestsPerMinute = 10000 // Higher limits for dev
		config.Validator.RequireEmailTLS = false
		
	case "staging":
		// Moderate security for staging
		config.General.SecurityMode = "normal"
		config.General.EnableDebugLogging = true
		
	case "production":
		// Strict security for production
		config.General.SecurityMode = "strict"
		config.General.EnableDebugLogging = false
		config.Watchtower.AutoEmergencyMode = true
		
	default:
		scm.logger.Warn("Unknown environment, using production defaults", 
			zap.String("environment", config.Environment))
		config.Environment = "production"
	}
	
	// Apply environment variable overrides
	scm.applyEnvironmentVariableOverrides(config)
}

// applyEnvironmentVariableOverrides applies overrides from environment variables
func (scm *SecurityConfigManager) applyEnvironmentVariableOverrides(config *FortressConfig) {
	// Rate limiting overrides
	if val := os.Getenv("FORTRESS_RATE_LIMIT_GLOBAL"); val != "" {
		if limit, err := parseIntFromEnv(val); err == nil {
			config.RateLimit.GlobalRequestsPerMinute = limit
		}
	}
	
	if val := os.Getenv("FORTRESS_RATE_LIMIT_IP"); val != "" {
		if limit, err := parseIntFromEnv(val); err == nil {
			config.RateLimit.IPRequestsPerMinute = limit
		}
	}
	
	// Security mode override
	if val := os.Getenv("FORTRESS_SECURITY_MODE"); val != "" {
		validModes := []string{"strict", "normal", "permissive"}
		for _, mode := range validModes {
			if val == mode {
				config.General.SecurityMode = val
				break
			}
		}
	}
	
	// Redis URL override
	if val := os.Getenv("FORTRESS_REDIS_URL"); val != "" {
		config.RateLimit.RedisURL = val
	}
	
	// Emergency mode override
	if val := os.Getenv("FORTRESS_EMERGENCY_MODE"); val != "" {
		config.RateLimit.EmergencyMode = parseBoolFromEnv(val)
	}
	
	// Debug logging override
	if val := os.Getenv("FORTRESS_DEBUG"); val != "" {
		config.General.EnableDebugLogging = parseBoolFromEnv(val)
	}
}

// notifyWatchers notifies all configuration watchers of changes
func (scm *SecurityConfigManager) notifyWatchers(config *FortressConfig) {
	for _, watcher := range scm.watchers {
		if err := watcher.OnConfigChanged(config); err != nil {
			scm.logger.Error("Configuration watcher failed", zap.Error(err))
		}
	}
}

// ReloadConfig reloads configuration from file
func (scm *SecurityConfigManager) ReloadConfig() error {
	scm.logger.Info("Reloading fortress configuration")
	
	if err := scm.LoadConfig(); err != nil {
		return fmt.Errorf("failed to reload configuration: %w", err)
	}
	
	// Notify watchers
	scm.notifyWatchers(scm.config)
	
	return nil
}

// SetSecurityMode changes the security mode
func (scm *SecurityConfigManager) SetSecurityMode(mode string) error {
	validModes := []string{"strict", "normal", "permissive"}
	validMode := false
	for _, validMode := range validModes {
		if mode == validMode {
			validMode = true
			break
		}
	}
	
	if !validMode {
		return fmt.Errorf("invalid security mode: %s", mode)
	}
	
	scm.config.General.SecurityMode = mode
	scm.config.UpdatedAt = time.Now()
	
	// Apply mode-specific settings
	switch mode {
	case "strict":
		scm.config.RateLimit.EmergencyMultiplier = 0.1
		scm.config.Rampart.RequireUserAgent = true
		scm.config.Watchtower.AutoEmergencyMode = true
		
	case "normal":
		scm.config.RateLimit.EmergencyMultiplier = 0.3
		scm.config.Rampart.RequireUserAgent = true
		scm.config.Watchtower.AutoEmergencyMode = false
		
	case "permissive":
		scm.config.RateLimit.EmergencyMultiplier = 0.7
		scm.config.Rampart.RequireUserAgent = false
		scm.config.Watchtower.AutoEmergencyMode = false
	}
	
	// Save and notify
	if err := scm.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}
	
	scm.notifyWatchers(scm.config)
	
	scm.logger.Info("Security mode changed", zap.String("mode", mode))
	
	return nil
}

// EnableEmergencyMode enables fortress emergency protocols
func (scm *SecurityConfigManager) EnableEmergencyMode(reason string) error {
	scm.config.RateLimit.EmergencyMode = true
	scm.config.UpdatedAt = time.Now()
	
	// Apply emergency settings
	scm.config.RateLimit.EmergencyMultiplier = 0.05 // Very restrictive
	scm.config.Rampart.EnableHoneypots = true
	scm.config.Rampart.DetectAutomation = true
	
	if err := scm.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save emergency configuration: %w", err)
	}
	
	scm.notifyWatchers(scm.config)
	
	scm.logger.Warn("Fortress emergency mode enabled", 
		zap.String("reason", reason))
	
	return nil
}

// DisableEmergencyMode disables fortress emergency protocols
func (scm *SecurityConfigManager) DisableEmergencyMode() error {
	scm.config.RateLimit.EmergencyMode = false
	scm.config.UpdatedAt = time.Now()
	
	// Restore normal settings based on security mode
	switch scm.config.General.SecurityMode {
	case "strict":
		scm.config.RateLimit.EmergencyMultiplier = 0.1
	case "normal":
		scm.config.RateLimit.EmergencyMultiplier = 0.3
	case "permissive":
		scm.config.RateLimit.EmergencyMultiplier = 0.7
	}
	
	if err := scm.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}
	
	scm.notifyWatchers(scm.config)
	
	scm.logger.Info("Fortress emergency mode disabled")
	
	return nil
}

// ExportConfig exports configuration to a JSON string
func (scm *SecurityConfigManager) ExportConfig() (string, error) {
	data, err := json.MarshalIndent(scm.config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to export configuration: %w", err)
	}
	
	return string(data), nil
}

// ImportConfig imports configuration from a JSON string
func (scm *SecurityConfigManager) ImportConfig(configJSON string) error {
	var config FortressConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("failed to parse configuration JSON: %w", err)
	}
	
	return scm.UpdateConfig(&config)
}

// Helper functions

// parseIntFromEnv safely parses an integer from environment variable
func parseIntFromEnv(val string) (int, error) {
	var result int
	if _, err := fmt.Sscanf(val, "%d", &result); err != nil {
		return 0, err
	}
	return result, nil
}

// parseBoolFromEnv safely parses a boolean from environment variable
func parseBoolFromEnv(val string) bool {
	switch val {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}