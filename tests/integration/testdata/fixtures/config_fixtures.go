package fixtures

import (
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
)

// ConfigFixtures provides test configuration data
type ConfigFixtures struct{}

// NewConfigFixtures creates a new config fixtures instance
func NewConfigFixtures() *ConfigFixtures {
	return &ConfigFixtures{}
}

// TestDatabaseConfig returns a test database configuration
func (f *ConfigFixtures) TestDatabaseConfig() *interfaces.DatabaseConfig {
	return &interfaces.DatabaseConfig{
		Driver:          "postgres",
		Host:            "localhost",
		Port:            5432,
		Database:        "pat_fortress_test",
		Username:        "pat_test",
		Password:        "test_password",
		SSLMode:         "disable",
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
		MigrationsPath:  "/mnt/c/Projects/Pat/migrations",
		Params: map[string]string{
			"application_name": "pat-fortress-integration-test",
			"search_path":      "public",
		},
	}
}

// TestRedisConfig returns a test Redis configuration  
func (f *ConfigFixtures) TestRedisConfig() *interfaces.RedisConfig {
	return &interfaces.RedisConfig{
		Address:     "localhost:6379",
		Password:    "",
		DB:          1, // Use DB 1 for tests to avoid conflicts
		MaxRetries:  3,
		PoolSize:    10,
		MinIdleConns: 2,
		DialTimeout:  time.Second * 5,
		ReadTimeout:  time.Second * 3,
		WriteTimeout: time.Second * 3,
		IdleTimeout:  time.Minute * 5,
		Prefix:      "fortress:test:",
	}
}

// TestSMTPServerConfig returns a test SMTP server configuration
func (f *ConfigFixtures) TestSMTPServerConfig() *interfaces.SMTPServerConfig {
	return &interfaces.SMTPServerConfig{
		Host:                "127.0.0.1",
		Port:                2525, // Use different port for tests
		MaxMessageSize:      32 * 1024 * 1024, // 32MB
		MaxRecipients:       100,
		ReadTimeout:         time.Minute * 5,
		WriteTimeout:        time.Minute * 5,
		MaxConnections:      100,
		EnableAuth:          false,
		EnableTLS:           false,
		TLSCertFile:         "",
		TLSKeyFile:          "",
		Hostname:            "fortress.test",
		Banner:              "Fortress Test SMTP Server",
		RequireAuth:         false,
		EnablePipelining:    true,
		EnableBinaryMIME:    true,
		EnableDSN:           true,
		MaxLineLength:       1000,
		EnableXCLIENT:       false,
		AuthMechanisms:      []string{"PLAIN", "LOGIN"},
	}
}

// TestHTTPServerConfig returns a test HTTP server configuration
func (f *ConfigFixtures) TestHTTPServerConfig() *interfaces.HTTPServerConfig {
	return &interfaces.HTTPServerConfig{
		Host:               "127.0.0.1",
		Port:               8080, // Use different port for tests
		ReadTimeout:        time.Second * 30,
		WriteTimeout:       time.Second * 30,
		IdleTimeout:        time.Second * 120,
		MaxHeaderBytes:     1 << 20, // 1MB
		EnableCORS:         true,
		EnableGzip:         true,
		EnableMetrics:      true,
		TLSEnabled:         false,
		TLSCertFile:        "",
		TLSKeyFile:         "",
		StaticDir:          "/mnt/c/Projects/Pat/frontend/build",
		APIPrefix:          "/api/v3",
		GraphQLEndpoint:    "/graphql",
		WebSocketEndpoint:  "/ws",
		HealthEndpoint:     "/health",
		MetricsEndpoint:    "/metrics",
		MaxRequestSize:     32 * 1024 * 1024, // 32MB
		RateLimitRPS:       100,
		RateLimitBurst:     200,
		EnablePprof:        true,
		PprofPrefix:        "/debug/pprof",
	}
}

// TestSecurityConfig returns a test security configuration
func (f *ConfigFixtures) TestSecurityConfig() *interfaces.SecurityConfig {
	return &interfaces.SecurityConfig{
		JWTSecret:           "fortress-test-jwt-secret-key-do-not-use-in-production",
		JWTExpiration:       time.Hour * 24,
		RefreshTokenExpiration: time.Hour * 24 * 7, // 7 days
		BCryptCost:          10, // Lower cost for faster tests
		EnableRateLimit:     true,
		EnableIPWhitelist:   false,
		EnableAPIKeyAuth:    true,
		EnableMFA:           false,
		SessionTimeout:      time.Hour * 8,
		MaxLoginAttempts:    5,
		LockoutDuration:     time.Minute * 15,
		PasswordMinLength:   8,
		RequireUppercase:    true,
		RequireLowercase:    true,
		RequireNumbers:      true,
		RequireSpecialChars: false,
		EnableSQLInjectionProtection: true,
		EnableXSSProtection:          true,
		EnableCSRFProtection:         true,
		CSRFTokenLength:             32,
		EnableTLSOnly:               false, // Disable for tests
		HSTSMaxAge:                  0,     // Disable for tests
	}
}

// TestMonitoringConfig returns a test monitoring configuration
func (f *ConfigFixtures) TestMonitoringConfig() *interfaces.MonitoringConfig {
	return &interfaces.MonitoringConfig{
		EnableMetrics:       true,
		EnableTracing:       true,
		EnableProfiling:     true,
		MetricsPort:         9090,
		TracingEndpoint:     "http://localhost:14268/api/traces",
		LogLevel:            "info",
		LogFormat:           "json",
		LogOutput:           "stdout",
		EnableHealthChecks:  true,
		HealthCheckInterval: time.Second * 10,
		MetricsInterval:     time.Second * 15,
		EnableAlerts:        false, // Disable for tests
		AlertWebhookURL:     "",
		PrometheusEnabled:   true,
		PrometheusEndpoint:  "/metrics",
		JaegerEnabled:       false, // Disable for tests
		JaegerEndpoint:      "",
	}
}

// TestPluginConfig returns a test plugin configuration
func (f *ConfigFixtures) TestPluginConfig() *interfaces.PluginConfig {
	return &interfaces.PluginConfig{
		ID:          "test-plugin",
		Name:        "Test Plugin",
		Version:     "1.0.0",
		Description: "Test plugin for integration testing",
		Author:      "Fortress Test Suite",
		Enabled:     true,
		Priority:    10,
		Timeout:     time.Second * 30,
		MaxMemoryMB: 128,
		Settings: map[string]interface{}{
			"test_mode":     true,
			"debug_output":  true,
			"max_emails":    1000,
			"filter_spam":   false,
			"custom_header": "X-Test-Plugin",
		},
		Dependencies: []string{},
		Permissions:  []string{"read_emails", "modify_headers"},
		ScriptPath:   "/mnt/c/Projects/Pat/plugins/test-plugin.js",
		ConfigSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"test_mode": map[string]interface{}{
					"type":    "boolean",
					"default": true,
				},
				"max_emails": map[string]interface{}{
					"type":    "integer",
					"minimum": 1,
					"maximum": 10000,
					"default": 1000,
				},
			},
		},
	}
}

// TestRateLimitConfig returns a test rate limit configuration
func (f *ConfigFixtures) TestRateLimitConfig() *interfaces.RateLimit {
	return &interfaces.RateLimit{
		RequestsPerSecond: 100,
		BurstSize:         200,
		WindowDuration:    time.Minute,
		MaxConnections:    1000,
		ConnectionTimeout: time.Second * 30,
		EnablePerIPLimit:  true,
		EnablePerUserLimit: true,
		IPLimitRPS:        10,
		UserLimitRPS:      50,
		WhitelistIPs:      []string{"127.0.0.1", "::1"},
		BlacklistIPs:      []string{},
		EnableDDOSProtection: true,
		DDOSThreshold:     1000,
		DDOSBanDuration:   time.Minute * 10,
	}
}

// TestBackupConfig returns a test backup configuration
func (f *ConfigFixtures) TestBackupConfig() *interfaces.BackupConfig {
	return &interfaces.BackupConfig{
		Enabled:         true,
		Schedule:        "0 2 * * *", // Daily at 2 AM
		RetentionDays:   7,
		CompressionType: "gzip",
		StorageType:     "local",
		StoragePath:     "/tmp/fortress-test-backups",
		EncryptionKey:   "fortress-test-backup-key",
		MaxBackupSize:   1024 * 1024 * 1024, // 1GB
		IncludeTables:   []string{"emails", "users", "sessions"},
		ExcludeTables:   []string{"logs", "metrics"},
		Metadata: map[string]interface{}{
			"test_mode": true,
			"environment": "integration-test",
		},
	}
}

// TestEventBusConfig returns a test event bus configuration
func (f *ConfigFixtures) TestEventBusConfig() *interfaces.EventBusConfig {
	return &interfaces.EventBusConfig{
		Type:            "memory", // Use memory bus for tests
		BufferSize:      1000,
		MaxWorkers:      10,
		WorkerTimeout:   time.Second * 30,
		RetryAttempts:   3,
		RetryDelay:      time.Second,
		EnablePersistence: false, // Disable for tests
		PersistencePath:   "",
		MaxEventAge:       time.Hour * 24,
		EnableMetrics:     true,
		DeadLetterTopic:   "dlq",
		Topics: []string{
			"email.received",
			"email.processed",
			"email.stored",
			"email.deleted",
			"user.created",
			"user.updated",
			"system.health",
			"security.alert",
		},
	}
}

// TestDockerConfig returns a test Docker configuration for integration tests
func (f *ConfigFixtures) TestDockerConfig() *interfaces.DockerConfig {
	return &interfaces.DockerConfig{
		PostgreSQLImage:    "postgres:15-alpine",
		PostgreSQLPort:     5432,
		PostgreSQLUser:     "pat_test",
		PostgreSQLPassword: "test_password",
		PostgreSQLDatabase: "pat_fortress_test",
		
		RedisImage:    "redis:7-alpine",
		RedisPort:     6379,
		
		MailHogImage: "mailhog/mailhog:latest",
		MailHogSMTPPort: 1025,
		MailHogUIPort:   8025,
		
		NetworkName:    "fortress-test-network",
		ContainerPrefix: "fortress-test",
		
		EnableHealthChecks: true,
		HealthCheckInterval: time.Second * 10,
		StartupTimeout:      time.Minute * 2,
		ShutdownTimeout:     time.Second * 30,
		
		Volumes: map[string]string{
			"fortress-test-pgdata": "/var/lib/postgresql/data",
			"fortress-test-logs":   "/var/log/fortress",
		},
		
		Environment: map[string]string{
			"FORTRESS_ENV":      "test",
			"FORTRESS_LOG_LEVEL": "debug",
			"FORTRESS_DEBUG":     "true",
		},
	}
}

// AllTestConfigs returns a comprehensive set of test configurations
func (f *ConfigFixtures) AllTestConfigs() map[string]interface{} {
	return map[string]interface{}{
		"database":   f.TestDatabaseConfig(),
		"redis":      f.TestRedisConfig(),
		"smtp":       f.TestSMTPServerConfig(),
		"http":       f.TestHTTPServerConfig(),
		"security":   f.TestSecurityConfig(),
		"monitoring": f.TestMonitoringConfig(),
		"plugin":     f.TestPluginConfig(),
		"ratelimit":  f.TestRateLimitConfig(),
		"backup":     f.TestBackupConfig(),
		"eventbus":   f.TestEventBusConfig(),
		"docker":     f.TestDockerConfig(),
	}
}

// MinimalTestConfig returns a minimal configuration for quick tests
func (f *ConfigFixtures) MinimalTestConfig() map[string]interface{} {
	return map[string]interface{}{
		"database": f.TestDatabaseConfig(),
		"smtp":     f.TestSMTPServerConfig(),
		"http":     f.TestHTTPServerConfig(),
		"security": f.TestSecurityConfig(),
	}
}