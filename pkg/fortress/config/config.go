package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

// Config represents the complete fortress configuration
type Config struct {
	// Server configuration
	Server ServerConfig `json:"server" yaml:"server"`
	
	// SMTP server configuration
	SMTP SMTPConfig `json:"smtp" yaml:"smtp"`
	
	// Database configuration
	Database DatabaseConfig `json:"database" yaml:"database"`
	
	// Security configuration
	Security SecurityConfig `json:"security" yaml:"security"`
	
	// Email processing configuration
	Email EmailConfig `json:"email" yaml:"email"`
	
	// Plugin system configuration
	Plugins PluginConfig `json:"plugins" yaml:"plugins"`
	
	// Monitoring configuration
	Monitoring MonitoringConfig `json:"monitoring" yaml:"monitoring"`
	
	// Event system configuration
	Events EventConfig `json:"events" yaml:"events"`
	
	// API configuration
	API APIConfig `json:"api" yaml:"api"`
	
	// WebSocket configuration
	WebSocket WebSocketConfig `json:"websocket" yaml:"websocket"`
	
	// GraphQL configuration
	GraphQL GraphQLConfig `json:"graphql" yaml:"graphql"`
	
	// Alexandria plugin mode configuration
	Alexandria AlexandriaConfig `json:"alexandria" yaml:"alexandria"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	Host             string     `json:"host" yaml:"host"`
	HTTPPort         int        `json:"httpPort" yaml:"httpPort"`
	TimeoutSeconds   int        `json:"timeoutSeconds" yaml:"timeoutSeconds"`
	MaxBodySizeBytes int        `json:"maxBodySizeBytes" yaml:"maxBodySizeBytes"`
	TLS              TLSConfig  `json:"tls" yaml:"tls"`
	CORS             CORSConfig `json:"cors" yaml:"cors"`
}

// SMTPConfig contains SMTP server settings
type SMTPConfig struct {
	Host                string         `json:"host" yaml:"host"`
	Port                int            `json:"port" yaml:"port"`
	TimeoutSeconds      int            `json:"timeoutSeconds" yaml:"timeoutSeconds"`
	MaxMessageSizeBytes int            `json:"maxMessageSizeBytes" yaml:"maxMessageSizeBytes"`
	MaxRecipients       int            `json:"maxRecipients" yaml:"maxRecipients"`
	TLS                 TLSConfig      `json:"tls" yaml:"tls"`
	Auth                SMTPAuthConfig `json:"auth" yaml:"auth"`
}

// TLSConfig contains TLS/SSL settings
type TLSConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	CertFile   string `json:"certFile" yaml:"certFile"`
	KeyFile    string `json:"keyFile" yaml:"keyFile"`
	MinVersion string `json:"minVersion" yaml:"minVersion"`
}

// CORSConfig contains CORS settings
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowedOrigins" yaml:"allowedOrigins"`
	AllowedMethods   []string `json:"allowedMethods" yaml:"allowedMethods"`
	AllowedHeaders   []string `json:"allowedHeaders" yaml:"allowedHeaders"`
	ExposedHeaders   []string `json:"exposedHeaders" yaml:"exposedHeaders"`
	AllowCredentials bool     `json:"allowCredentials" yaml:"allowCredentials"`
	MaxAge           int      `json:"maxAge" yaml:"maxAge"`
}

// SMTPAuthConfig contains SMTP authentication settings
type SMTPAuthConfig struct {
	Enabled    bool              `json:"enabled" yaml:"enabled"`
	Mechanisms []string          `json:"mechanisms" yaml:"mechanisms"`
	Users      map[string]string `json:"users" yaml:"users"`
}

// DatabaseConfig contains database settings
type DatabaseConfig struct {
	Driver               string            `json:"driver" yaml:"driver"`
	DSN                  string            `json:"dsn" yaml:"dsn"`
	MaxConnections       int               `json:"maxConnections" yaml:"maxConnections"`
	MaxIdleConnections   int               `json:"maxIdleConnections" yaml:"maxIdleConnections"`
	MaxLifetimeMinutes   int               `json:"maxLifetimeMinutes" yaml:"maxLifetimeMinutes"`
	MigrationsPath       string            `json:"migrationsPath" yaml:"migrationsPath"`
	Options              map[string]string `json:"options" yaml:"options"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	JWTSecret                string                 `json:"jwtSecret" yaml:"jwtSecret"`
	TokenExpiryMinutes       int                    `json:"tokenExpiryMinutes" yaml:"tokenExpiryMinutes"`
	RefreshTokenExpiryDays   int                    `json:"refreshTokenExpiryDays" yaml:"refreshTokenExpiryDays"`
	PasswordMinLength        int                    `json:"passwordMinLength" yaml:"passwordMinLength"`
	RequireTwoFactor         bool                   `json:"requireTwoFactor" yaml:"requireTwoFactor"`
	SessionTimeoutMinutes    int                    `json:"sessionTimeoutMinutes" yaml:"sessionTimeoutMinutes"`
	MaxFailedAttempts        int                    `json:"maxFailedAttempts" yaml:"maxFailedAttempts"`
	LockoutDurationMinutes   int                    `json:"lockoutDurationMinutes" yaml:"lockoutDurationMinutes"`
	EnableAPIKeys            bool                   `json:"enableApiKeys" yaml:"enableApiKeys"`
	EnableOAuth              bool                   `json:"enableOauth" yaml:"enableOauth"`
	OAuthProviders           []string               `json:"oauthProviders" yaml:"oauthProviders"`
	PermissionCaching        bool                   `json:"permissionCaching" yaml:"permissionCaching"`
	RateLimiting             RateLimitingConfig     `json:"rateLimiting" yaml:"rateLimiting"`
	Scanning                 ScanningConfig         `json:"scanning" yaml:"scanning"`
	Blacklists               BlacklistsConfig       `json:"blacklists" yaml:"blacklists"`
	ComplianceMode           string                 `json:"complianceMode" yaml:"complianceMode"`
	DataRetentionDays        int                    `json:"dataRetentionDays" yaml:"dataRetentionDays"`
	AuditLogging             bool                   `json:"auditLogging" yaml:"auditLogging"`
	AlertingEnabled          bool                   `json:"alertingEnabled" yaml:"alertingEnabled"`
}

// RateLimitingConfig contains rate limiting settings
type RateLimitingConfig struct {
	Enabled                   bool                       `json:"enabled" yaml:"enabled"`
	DefaultRequestsPerMinute  int                        `json:"defaultRequestsPerMinute" yaml:"defaultRequestsPerMinute"`
	WindowSizeMinutes         int                        `json:"windowSizeMinutes" yaml:"windowSizeMinutes"`
	BurstMultiplier           float64                    `json:"burstMultiplier" yaml:"burstMultiplier"`
	Storage                   string                     `json:"storage" yaml:"storage"`
	CustomLimits              map[string]RateLimitRule   `json:"customLimits" yaml:"customLimits"`
}

// RateLimitRule defines rate limit rule
type RateLimitRule struct {
	RequestsPerMinute int     `json:"requestsPerMinute" yaml:"requestsPerMinute"`
	BurstMultiplier   float64 `json:"burstMultiplier" yaml:"burstMultiplier"`
}

// ScanningConfig contains security scanning settings
type ScanningConfig struct {
	Enabled              bool     `json:"enabled" yaml:"enabled"`
	VirusScanningEnabled bool     `json:"virusScanningEnabled" yaml:"virusScanningEnabled"`
	SpamFilterEnabled    bool     `json:"spamFilterEnabled" yaml:"spamFilterEnabled"`
	PhishingDetection    bool     `json:"phishingDetection" yaml:"phishingDetection"`
	AttachmentScan       bool     `json:"attachmentScan" yaml:"attachmentScan"`
	MaxEmailSizeBytes    int64    `json:"maxEmailSizeBytes" yaml:"maxEmailSizeBytes"`
	QuarantineEnabled    bool     `json:"quarantineEnabled" yaml:"quarantineEnabled"`
	ThreatSources        []string `json:"threatSources" yaml:"threatSources"`
}

// BlacklistsConfig contains blacklist settings
type BlacklistsConfig struct {
	IPAddresses         []string `json:"ipAddresses" yaml:"ipAddresses"`
	EmailAddresses      []string `json:"emailAddresses" yaml:"emailAddresses"`
	Domains             []string `json:"domains" yaml:"domains"`
	Keywords            []string `json:"keywords" yaml:"keywords"`
	AutoUpdate          bool     `json:"autoUpdate" yaml:"autoUpdate"`
	UpdateIntervalHours int      `json:"updateIntervalHours" yaml:"updateIntervalHours"`
}

// EmailConfig contains email processing settings
type EmailConfig struct {
	AsyncProcessing            bool          `json:"asyncProcessing" yaml:"asyncProcessing"`
	MaxConcurrentProcessing    int           `json:"maxConcurrentProcessing" yaml:"maxConcurrentProcessing"`
	ProcessingTimeoutSeconds   int           `json:"processingTimeoutSeconds" yaml:"processingTimeoutSeconds"`
	RetryAttempts              int           `json:"retryAttempts" yaml:"retryAttempts"`
	RetryDelaySeconds          int           `json:"retryDelaySeconds" yaml:"retryDelaySeconds"`
	Storage                    StorageConfig `json:"storage" yaml:"storage"`
	Search                     SearchConfig  `json:"search" yaml:"search"`
	Analytics                  AnalyticsConfig `json:"analytics" yaml:"analytics"`
	Validation                 ValidationConfig `json:"validation" yaml:"validation"`
}

// StorageConfig contains email storage settings
type StorageConfig struct {
	CompressEmails      bool   `json:"compressEmails" yaml:"compressEmails"`
	EncryptEmails       bool   `json:"encryptEmails" yaml:"encryptEmails"`
	MaxEmailSizeBytes   int64  `json:"maxEmailSizeBytes" yaml:"maxEmailSizeBytes"`
	AttachmentStorage   string `json:"attachmentStorage" yaml:"attachmentStorage"`
	IndexEmails         bool   `json:"indexEmails" yaml:"indexEmails"`
	RetentionDays       int    `json:"retentionDays" yaml:"retentionDays"`
}

// SearchConfig contains search settings
type SearchConfig struct {
	Enabled              bool `json:"enabled" yaml:"enabled"`
	IndexingEnabled      bool `json:"indexingEnabled" yaml:"indexingEnabled"`
	FullTextSearch       bool `json:"fullTextSearch" yaml:"fullTextSearch"`
	FuzzySearch          bool `json:"fuzzySearch" yaml:"fuzzySearch"`
	SearchTimeoutSeconds int  `json:"searchTimeoutSeconds" yaml:"searchTimeoutSeconds"`
	MaxResults           int  `json:"maxResults" yaml:"maxResults"`
}

// AnalyticsConfig contains analytics settings
type AnalyticsConfig struct {
	Enabled      bool `json:"enabled" yaml:"enabled"`
	RealTimeStats bool `json:"realTimeStats" yaml:"realTimeStats"`
	HistoricalStats bool `json:"historicalStats" yaml:"historicalStats"`
	RetentionDays int  `json:"retentionDays" yaml:"retentionDays"`
}

// ValidationConfig contains email validation settings
type ValidationConfig struct {
	ValidateHeaders   bool `json:"validateHeaders" yaml:"validateHeaders"`
	ValidateStructure bool `json:"validateStructure" yaml:"validateStructure"`
	ValidateEncoding  bool `json:"validateEncoding" yaml:"validateEncoding"`
	RejectInvalid     bool `json:"rejectInvalid" yaml:"rejectInvalid"`
}

// PluginConfig contains plugin system settings
type PluginConfig struct {
	Directory                string                 `json:"directory" yaml:"directory"`
	MaxConcurrentExecutions  int                    `json:"maxConcurrentExecutions" yaml:"maxConcurrentExecutions"`
	DefaultTimeoutSeconds    int                    `json:"defaultTimeoutSeconds" yaml:"defaultTimeoutSeconds"`
	MaxTimeoutSeconds        int                    `json:"maxTimeoutSeconds" yaml:"maxTimeoutSeconds"`
	EnableSandbox            bool                   `json:"enableSandbox" yaml:"enableSandbox"`
	AllowedTypes             []string               `json:"allowedTypes" yaml:"allowedTypes"`
	SecurityChecks           bool                   `json:"securityChecks" yaml:"securityChecks"`
	AutoReload               bool                   `json:"autoReload" yaml:"autoReload"`
	ReloadIntervalMinutes    int                    `json:"reloadIntervalMinutes" yaml:"reloadIntervalMinutes"`
	EnableCaching            bool                   `json:"enableCaching" yaml:"enableCaching"`
	ExecutionLogging         bool                   `json:"executionLogging" yaml:"executionLogging"`
	PerformanceMonitoring    bool                   `json:"performanceMonitoring" yaml:"performanceMonitoring"`
	ResourceLimits           ResourceLimitsConfig   `json:"resourceLimits" yaml:"resourceLimits"`
}

// ResourceLimitsConfig contains plugin resource limits
type ResourceLimitsConfig struct {
	MaxMemoryMB             int `json:"maxMemoryMb" yaml:"maxMemoryMb"`
	MaxCPUPercent           int `json:"maxCpuPercent" yaml:"maxCpuPercent"`
	MaxExecutionTimeSeconds int `json:"maxExecutionTimeSeconds" yaml:"maxExecutionTimeSeconds"`
}

// MonitoringConfig contains monitoring settings
type MonitoringConfig struct {
	MetricsEnabled             bool     `json:"metricsEnabled" yaml:"metricsEnabled"`
	TracingEnabled             bool     `json:"tracingEnabled" yaml:"tracingEnabled"`
	LogLevel                   string   `json:"logLevel" yaml:"logLevel"`
	MetricsPort                int      `json:"metricsPort" yaml:"metricsPort"`
	AlertingEnabled            bool     `json:"alertingEnabled" yaml:"alertingEnabled"`
	HealthCheckIntervalSeconds int      `json:"healthCheckIntervalSeconds" yaml:"healthCheckIntervalSeconds"`
	RetentionDays              int      `json:"retentionDays" yaml:"retentionDays"`
	ExternalEndpoints          []string `json:"externalEndpoints" yaml:"externalEndpoints"`
}

// EventConfig contains event system settings
type EventConfig struct {
	Driver             string   `json:"driver" yaml:"driver"`
	BufferSize         int      `json:"bufferSize" yaml:"bufferSize"`
	WorkerCount        int      `json:"workerCount" yaml:"workerCount"`
	MaxRetries         int      `json:"maxRetries" yaml:"maxRetries"`
	RetryDelaySeconds  int      `json:"retryDelaySeconds" yaml:"retryDelaySeconds"`
	PersistEvents      bool     `json:"persistEvents" yaml:"persistEvents"`
	RetentionDays      int      `json:"retentionDays" yaml:"retentionDays"`
	ExternalBrokers    []string `json:"externalBrokers" yaml:"externalBrokers"`
}

// APIConfig contains API settings
type APIConfig struct {
	DefaultVersion      string   `json:"defaultVersion" yaml:"defaultVersion"`
	SupportedVersions   []string `json:"supportedVersions" yaml:"supportedVersions"`
	DeprecationNotice   bool     `json:"deprecationNotice" yaml:"deprecationNotice"`
}

// WebSocketConfig contains WebSocket settings
type WebSocketConfig struct {
	Enabled                 bool `json:"enabled" yaml:"enabled"`
	MaxConnections          int  `json:"maxConnections" yaml:"maxConnections"`
	MessageSizeLimitBytes   int  `json:"messageSizeLimitBytes" yaml:"messageSizeLimitBytes"`
	PingIntervalSeconds     int  `json:"pingIntervalSeconds" yaml:"pingIntervalSeconds"`
	PongTimeoutSeconds      int  `json:"pongTimeoutSeconds" yaml:"pongTimeoutSeconds"`
}

// GraphQLConfig contains GraphQL settings
type GraphQLConfig struct {
	Enabled                  bool `json:"enabled" yaml:"enabled"`
	PlaygroundEnabled        bool `json:"playgroundEnabled" yaml:"playgroundEnabled"`
	IntrospectionEnabled     bool `json:"introspectionEnabled" yaml:"introspectionEnabled"`
	MaxComplexity            int  `json:"maxComplexity" yaml:"maxComplexity"`
	MaxDepth                 int  `json:"maxDepth" yaml:"maxDepth"`
}

// AlexandriaConfig contains Alexandria plugin mode settings
type AlexandriaConfig struct {
	Enabled         bool                   `json:"enabled" yaml:"enabled"`
	PluginID        string                 `json:"pluginId" yaml:"pluginId"`
	PluginVersion   string                 `json:"pluginVersion" yaml:"pluginVersion"`
	Integration     AlexandriaIntegration  `json:"integration" yaml:"integration"`
}

// AlexandriaIntegration contains Alexandria integration settings
type AlexandriaIntegration struct {
	UseInternalDB       bool     `json:"useInternalDb" yaml:"useInternalDb"`
	UseInternalAuth     bool     `json:"useInternalAuth" yaml:"useInternalAuth"`
	UseInternalLogging  bool     `json:"useInternalLogging" yaml:"useInternalLogging"`
	ExposeAPIs          []string `json:"exposeApis" yaml:"exposeApis"`
	EventSubscriptions  []string `json:"eventSubscriptions" yaml:"eventSubscriptions"`
	UIContributions     bool     `json:"uiContributions" yaml:"uiContributions"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:             "localhost",
			HTTPPort:         8025,
			TimeoutSeconds:   30,
			MaxBodySizeBytes: 10 * 1024 * 1024, // 10MB
			TLS: TLSConfig{
				Enabled:    false,
				MinVersion: "1.2",
			},
			CORS: CORSConfig{
				AllowedOrigins:   []string{"*"},
				AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"*"},
				AllowCredentials: false,
				MaxAge:           3600,
			},
		},
		SMTP: SMTPConfig{
			Host:                "localhost",
			Port:                1025,
			TimeoutSeconds:      30,
			MaxMessageSizeBytes: 25 * 1024 * 1024, // 25MB
			MaxRecipients:       100,
			TLS: TLSConfig{
				Enabled:    false,
				MinVersion: "1.2",
			},
			Auth: SMTPAuthConfig{
				Enabled: false,
			},
		},
		Database: DatabaseConfig{
			Driver:               "sqlite3",
			DSN:                  "./pat.db",
			MaxConnections:       25,
			MaxIdleConnections:   5,
			MaxLifetimeMinutes:   60,
			MigrationsPath:       "./migrations",
			Options:              make(map[string]string),
		},
		Security: SecurityConfig{
			JWTSecret:              generateSecretKey(),
			TokenExpiryMinutes:     60,
			RefreshTokenExpiryDays: 7,
			PasswordMinLength:      8,
			RequireTwoFactor:       false,
			SessionTimeoutMinutes:  30,
			MaxFailedAttempts:      5,
			LockoutDurationMinutes: 15,
			EnableAPIKeys:          true,
			EnableOAuth:            false,
			PermissionCaching:      true,
			RateLimiting: RateLimitingConfig{
				Enabled:                  true,
				DefaultRequestsPerMinute: 60,
				WindowSizeMinutes:        1,
				BurstMultiplier:          1.5,
				Storage:                  "memory",
				CustomLimits:             make(map[string]RateLimitRule),
			},
			Scanning: ScanningConfig{
				Enabled:              true,
				VirusScanningEnabled: false,
				SpamFilterEnabled:    true,
				PhishingDetection:    true,
				AttachmentScan:       true,
				MaxEmailSizeBytes:    25 * 1024 * 1024,
				QuarantineEnabled:    true,
				ThreatSources:        []string{},
			},
			Blacklists: BlacklistsConfig{
				AutoUpdate:          false,
				UpdateIntervalHours: 24,
			},
			ComplianceMode:    "standard",
			DataRetentionDays: 30,
			AuditLogging:      true,
			AlertingEnabled:   true,
		},
		Email: EmailConfig{
			AsyncProcessing:         true,
			MaxConcurrentProcessing: 10,
			ProcessingTimeoutSeconds: 30,
			RetryAttempts:           3,
			RetryDelaySeconds:       5,
			Storage: StorageConfig{
				CompressEmails:    false,
				EncryptEmails:     false,
				MaxEmailSizeBytes: 25 * 1024 * 1024,
				AttachmentStorage: "database",
				IndexEmails:       true,
				RetentionDays:     30,
			},
			Search: SearchConfig{
				Enabled:              true,
				IndexingEnabled:      true,
				FullTextSearch:       true,
				FuzzySearch:          true,
				SearchTimeoutSeconds: 10,
				MaxResults:           100,
			},
			Analytics: AnalyticsConfig{
				Enabled:         true,
				RealTimeStats:   true,
				HistoricalStats: true,
				RetentionDays:   90,
			},
			Validation: ValidationConfig{
				ValidateHeaders:   true,
				ValidateStructure: true,
				ValidateEncoding:  true,
				RejectInvalid:     false,
			},
		},
		Plugins: PluginConfig{
			Directory:               "./plugins",
			MaxConcurrentExecutions: 5,
			DefaultTimeoutSeconds:   30,
			MaxTimeoutSeconds:       300,
			EnableSandbox:           true,
			AllowedTypes:            []string{"filter", "validator", "transformer", "notifier"},
			SecurityChecks:          true,
			AutoReload:              false,
			ReloadIntervalMinutes:   5,
			EnableCaching:           true,
			ExecutionLogging:        true,
			PerformanceMonitoring:   true,
			ResourceLimits: ResourceLimitsConfig{
				MaxMemoryMB:             128,
				MaxCPUPercent:           50,
				MaxExecutionTimeSeconds: 30,
			},
		},
		Monitoring: MonitoringConfig{
			MetricsEnabled:             true,
			TracingEnabled:             true,
			LogLevel:                   "info",
			MetricsPort:                9090,
			AlertingEnabled:            true,
			HealthCheckIntervalSeconds: 30,
			RetentionDays:              7,
			ExternalEndpoints:          []string{},
		},
		Events: EventConfig{
			Driver:            "memory",
			BufferSize:        1000,
			WorkerCount:       3,
			MaxRetries:        3,
			RetryDelaySeconds: 1,
			PersistEvents:     true,
			RetentionDays:     7,
			ExternalBrokers:   []string{},
		},
		API: APIConfig{
			DefaultVersion:    "v3",
			SupportedVersions: []string{"v1", "v2", "v3"},
			DeprecationNotice: true,
		},
		WebSocket: WebSocketConfig{
			Enabled:               true,
			MaxConnections:        100,
			MessageSizeLimitBytes: 1024 * 1024, // 1MB
			PingIntervalSeconds:   30,
			PongTimeoutSeconds:    10,
		},
		GraphQL: GraphQLConfig{
			Enabled:              true,
			PlaygroundEnabled:    true,
			IntrospectionEnabled: true,
			MaxComplexity:        100,
			MaxDepth:             10,
		},
		Alexandria: AlexandriaConfig{
			Enabled:       false,
			PluginID:      "alexandria-pat",
			PluginVersion: "2.0.0",
			Integration: AlexandriaIntegration{
				UseInternalDB:      false,
				UseInternalAuth:    false,
				UseInternalLogging: false,
				ExposeAPIs:         []string{"email", "admin"},
				EventSubscriptions: []string{"email:received", "system:ready"},
				UIContributions:    true,
			},
		},
	}
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Load from file if provided
	if configPath != "" {
		if err := loadConfigFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config from file: %w", err)
		}
	}

	// Override with environment variables
	loadConfigFromEnv(config)

	// Override with command line flags
	loadConfigFromFlags(config)

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// loadConfigFromFile loads configuration from JSON or YAML file
func loadConfigFromFile(config *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return fmt.Errorf("failed to parse JSON config: %w", err)
		}
	case ".yaml", ".yml":
		// YAML parsing would go here if we add the yaml library
		return fmt.Errorf("YAML config support not implemented yet")
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	return nil
}

// loadConfigFromEnv loads configuration from environment variables
func loadConfigFromEnv(config *Config) {
	// Server config
	if val := os.Getenv("PAT_SERVER_HOST"); val != "" {
		config.Server.Host = val
	}
	if val := os.Getenv("PAT_HTTP_PORT"); val != "" {
		if port := parseInt(val, config.Server.HTTPPort); port > 0 {
			config.Server.HTTPPort = port
		}
	}

	// SMTP config
	if val := os.Getenv("PAT_SMTP_HOST"); val != "" {
		config.SMTP.Host = val
	}
	if val := os.Getenv("PAT_SMTP_PORT"); val != "" {
		if port := parseInt(val, config.SMTP.Port); port > 0 {
			config.SMTP.Port = port
		}
	}

	// Database config
	if val := os.Getenv("PAT_DATABASE_DSN"); val != "" {
		config.Database.DSN = val
	}
	if val := os.Getenv("PAT_DATABASE_DRIVER"); val != "" {
		config.Database.Driver = val
	}

	// Security config
	if val := os.Getenv("PAT_JWT_SECRET"); val != "" {
		config.Security.JWTSecret = val
	}

	// Plugin config
	if val := os.Getenv("PAT_PLUGIN_DIR"); val != "" {
		config.Plugins.Directory = val
	}

	// Alexandria config
	if val := os.Getenv("PAT_ALEXANDRIA_ENABLED"); val != "" {
		config.Alexandria.Enabled = parseBool(val, config.Alexandria.Enabled)
	}

	// Add more environment variable mappings as needed
}

// loadConfigFromFlags loads configuration from command line flags
func loadConfigFromFlags(config *Config) {
	if !pflag.Parsed() {
		return
	}

	// Server flags
	if pflag.Lookup("http-port") != nil && pflag.Changed("http-port") {
		port, _ := pflag.GetInt("http-port")
		config.Server.HTTPPort = port
	}

	if pflag.Lookup("smtp-port") != nil && pflag.Changed("smtp-port") {
		port, _ := pflag.GetInt("smtp-port")
		config.SMTP.Port = port
	}

	if pflag.Lookup("host") != nil && pflag.Changed("host") {
		host, _ := pflag.GetString("host")
		config.Server.Host = host
		config.SMTP.Host = host
	}

	// Database flags
	if pflag.Lookup("db-dsn") != nil && pflag.Changed("db-dsn") {
		dsn, _ := pflag.GetString("db-dsn")
		config.Database.DSN = dsn
	}

	// Add more flag mappings as needed
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate ports
	if config.Server.HTTPPort < 1 || config.Server.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", config.Server.HTTPPort)
	}

	if config.SMTP.Port < 1 || config.SMTP.Port > 65535 {
		return fmt.Errorf("invalid SMTP port: %d", config.SMTP.Port)
	}

	// Validate JWT secret
	if len(config.Security.JWTSecret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	// Validate database DSN
	if config.Database.DSN == "" {
		return fmt.Errorf("database DSN cannot be empty")
	}

	// Add more validations as needed
	return nil
}

// Helper functions

func parseInt(s string, defaultVal int) int {
	if val := parseIntHelper(s); val != 0 {
		return val
	}
	return defaultVal
}

func parseIntHelper(s string) int {
	// Simple integer parsing without external dependencies
	// This is a placeholder - use strconv.Atoi in real implementation
	return 0
}

func parseBool(s string, defaultVal bool) bool {
	switch strings.ToLower(s) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return defaultVal
	}
}

func generateSecretKey() string {
	// Generate a random 64-character secret key
	// This is a placeholder - use crypto/rand in real implementation
	return "fortress-secret-key-change-this-in-production-environments-64chars"
}