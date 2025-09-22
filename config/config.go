package config

import (
	"flag"
	"os"
	"strconv"
	"time"
)

// FortressConfig provides modern configuration for Pat Fortress
type FortressConfig struct {
	// Legacy MailHog compatibility
	AuthFile string
	WebPath  string

	// Fortress enhancements
	SMTPBindAddr     string
	HTTPBindAddr     string
	Hostname         string
	MaxMessageSize   int64
	StorageType      string
	CORSOrigin       string
	EnableTLS        bool
	TLSCertFile      string
	TLSKeyFile       string
	EnableAuth       bool
	EnableRateLimit  bool
	MaxPerIP         int
	TenantID         string
	LogLevel         string
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	EnableSecurity   bool
	RetentionDays    int

	// AI Analysis features
	EnableAIAnalysis bool
	OpenAIAPIKey     string
	OpenAIModel      string
}

// DefaultConfig returns default fortress configuration
func DefaultConfig() *FortressConfig {
    return &FortressConfig{
        AuthFile:         "",
        WebPath:          "web",
        SMTPBindAddr:     "0.0.0.0:1025",
        HTTPBindAddr:     "0.0.0.0:8025",
		Hostname:         "fortress.local",
		MaxMessageSize:   10 * 1024 * 1024, // 10MB
		StorageType:      "memory",
		CORSOrigin:       "",
		EnableTLS:        false,
		TLSCertFile:      "",
		TLSKeyFile:       "",
		EnableAuth:       false,
		EnableRateLimit:  true,
		MaxPerIP:         100,
		TenantID:         "",
		LogLevel:         "info",
		ReadTimeout:      30 * time.Second,
		WriteTimeout:     30 * time.Second,
		EnableSecurity:   true,
		RetentionDays:    7,
		EnableAIAnalysis: false,
		OpenAIAPIKey:     "",
		OpenAIModel:      "gpt-3.5-turbo",
	}
}

var fortressCfg = DefaultConfig()

// Configure applies fortress configuration with environment variable support
func Configure() *FortressConfig {
	// Apply environment variables with fallbacks
	fortressCfg.AuthFile = getEnvString("PAT_AUTH_FILE", fortressCfg.AuthFile)
	fortressCfg.WebPath = getEnvString("PAT_UI_WEB_PATH", fortressCfg.WebPath)
	fortressCfg.SMTPBindAddr = getEnvString("PAT_SMTP_BIND_ADDR", fortressCfg.SMTPBindAddr)
	fortressCfg.HTTPBindAddr = getEnvString("PAT_HTTP_BIND_ADDR", fortressCfg.HTTPBindAddr)
	fortressCfg.Hostname = getEnvString("PAT_HOSTNAME", fortressCfg.Hostname)
	fortressCfg.MaxMessageSize = getEnvInt64("PAT_MAX_MESSAGE_SIZE", fortressCfg.MaxMessageSize)
	fortressCfg.StorageType = getEnvString("PAT_STORAGE", fortressCfg.StorageType)
	fortressCfg.CORSOrigin = getEnvString("PAT_CORS_ORIGIN", fortressCfg.CORSOrigin)
	fortressCfg.EnableTLS = getEnvBool("PAT_ENABLE_TLS", fortressCfg.EnableTLS)
	fortressCfg.TLSCertFile = getEnvString("PAT_TLS_CERT_FILE", fortressCfg.TLSCertFile)
	fortressCfg.TLSKeyFile = getEnvString("PAT_TLS_KEY_FILE", fortressCfg.TLSKeyFile)
	fortressCfg.EnableAuth = getEnvBool("PAT_ENABLE_AUTH", fortressCfg.EnableAuth)
	fortressCfg.EnableRateLimit = getEnvBool("PAT_ENABLE_RATE_LIMIT", fortressCfg.EnableRateLimit)
	fortressCfg.MaxPerIP = getEnvInt("PAT_MAX_PER_IP", fortressCfg.MaxPerIP)
	fortressCfg.TenantID = getEnvString("PAT_TENANT_ID", fortressCfg.TenantID)
	fortressCfg.LogLevel = getEnvString("PAT_LOG_LEVEL", fortressCfg.LogLevel)
	fortressCfg.EnableSecurity = getEnvBool("PAT_ENABLE_SECURITY", fortressCfg.EnableSecurity)
	fortressCfg.RetentionDays = getEnvInt("PAT_RETENTION_DAYS", fortressCfg.RetentionDays)

	// AI Analysis configuration
	fortressCfg.EnableAIAnalysis = getEnvBool("PAT_AI_ENABLED", fortressCfg.EnableAIAnalysis)
	fortressCfg.OpenAIAPIKey = getEnvString("PAT_OPENAI_API_KEY", fortressCfg.OpenAIAPIKey)
	fortressCfg.OpenAIModel = getEnvString("PAT_OPENAI_MODEL", fortressCfg.OpenAIModel)

	// Auto-enable AI if API key is provided
	if fortressCfg.OpenAIAPIKey != "" && !fortressCfg.EnableAIAnalysis {
		fortressCfg.EnableAIAnalysis = true
	}

    // WebPath is treated as a filesystem directory for static assets
    // Do not modify it to avoid breaking relative paths like "web"

	return fortressCfg
}

// RegisterFlags registers fortress command line flags
func RegisterFlags() {
	flag.StringVar(&fortressCfg.AuthFile, "auth-file", fortressCfg.AuthFile, "Authentication file (username:bcryptpw mapping)")
	flag.StringVar(&fortressCfg.WebPath, "ui-web-path", fortressCfg.WebPath, "WebPath under which the UI is served")
	flag.StringVar(&fortressCfg.SMTPBindAddr, "smtp-bind-addr", fortressCfg.SMTPBindAddr, "SMTP server bind address")
	flag.StringVar(&fortressCfg.HTTPBindAddr, "http-bind-addr", fortressCfg.HTTPBindAddr, "HTTP server bind address")
	flag.StringVar(&fortressCfg.Hostname, "hostname", fortressCfg.Hostname, "Server hostname")
	flag.Int64Var(&fortressCfg.MaxMessageSize, "max-message-size", fortressCfg.MaxMessageSize, "Maximum message size in bytes")
	flag.StringVar(&fortressCfg.StorageType, "storage", fortressCfg.StorageType, "Storage type (memory, mongodb, postgresql)")
	flag.StringVar(&fortressCfg.CORSOrigin, "cors-origin", fortressCfg.CORSOrigin, "CORS origin for web UI")
	flag.BoolVar(&fortressCfg.EnableTLS, "enable-tls", fortressCfg.EnableTLS, "Enable TLS support")
	flag.StringVar(&fortressCfg.TLSCertFile, "tls-cert", fortressCfg.TLSCertFile, "TLS certificate file")
	flag.StringVar(&fortressCfg.TLSKeyFile, "tls-key", fortressCfg.TLSKeyFile, "TLS private key file")
	flag.BoolVar(&fortressCfg.EnableAuth, "enable-auth", fortressCfg.EnableAuth, "Enable authentication")
	flag.BoolVar(&fortressCfg.EnableRateLimit, "enable-rate-limit", fortressCfg.EnableRateLimit, "Enable rate limiting")
	flag.IntVar(&fortressCfg.MaxPerIP, "max-per-ip", fortressCfg.MaxPerIP, "Maximum requests per IP")
	flag.StringVar(&fortressCfg.TenantID, "tenant-id", fortressCfg.TenantID, "Fortress tenant ID")
	flag.StringVar(&fortressCfg.LogLevel, "log-level", fortressCfg.LogLevel, "Log level (debug, info, warn, error)")
	flag.BoolVar(&fortressCfg.EnableSecurity, "enable-security", fortressCfg.EnableSecurity, "Enable fortress security features")
	flag.IntVar(&fortressCfg.RetentionDays, "retention-days", fortressCfg.RetentionDays, "Message retention in days")

	// AI Analysis flags
	flag.BoolVar(&fortressCfg.EnableAIAnalysis, "enable-ai", fortressCfg.EnableAIAnalysis, "Enable AI-powered email analysis")
	flag.StringVar(&fortressCfg.OpenAIAPIKey, "openai-api-key", fortressCfg.OpenAIAPIKey, "OpenAI API key for email analysis")
	flag.StringVar(&fortressCfg.OpenAIModel, "openai-model", fortressCfg.OpenAIModel, "OpenAI model to use (default: gpt-3.5-turbo)")
}

// Utility functions for environment variable parsing
func getEnvString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return fallback
}

func getEnvInt64(key string, fallback int64) int64 {
	if value := os.Getenv(key); value != "" {
		if int64Value, err := strconv.ParseInt(value, 10, 64); err == nil {
			return int64Value
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return fallback
}

// Legacy compatibility - maintain original Config struct for backward compatibility
type Config struct {
	AuthFile string
	WebPath  string
}

// GetLegacyConfig returns legacy configuration format for backward compatibility
func GetLegacyConfig() *Config {
	fortress := Configure()
	return &Config{
		AuthFile: fortress.AuthFile,
		WebPath:  fortress.WebPath,
	}
}
