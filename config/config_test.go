package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.SMTPBindAddr != "0.0.0.0:1025" {
		t.Errorf("Expected SMTP bind addr to be 0.0.0.0:1025, got %s", cfg.SMTPBindAddr)
	}

	if cfg.HTTPBindAddr != "0.0.0.0:8025" {
		t.Errorf("Expected HTTP bind addr to be 0.0.0.0:8025, got %s", cfg.HTTPBindAddr)
	}

	if cfg.StorageType != "memory" {
		t.Errorf("Expected storage type to be memory, got %s", cfg.StorageType)
	}

	if cfg.MaxMessageSize != 10*1024*1024 {
		t.Errorf("Expected max message size to be 10MB, got %d", cfg.MaxMessageSize)
	}

	if cfg.EnableRateLimit != true {
		t.Error("Expected rate limiting to be enabled by default")
	}

	if cfg.MaxPerIP != 100 {
		t.Errorf("Expected max per IP to be 100, got %d", cfg.MaxPerIP)
	}
}

func TestConfigureWithEnvironmentVariables(t *testing.T) {
	// Save original env
	originalSMTPAddr := os.Getenv("PAT_SMTP_BIND_ADDR")
	originalHTTPAddr := os.Getenv("PAT_HTTP_BIND_ADDR")
	originalStorage := os.Getenv("PAT_STORAGE")
	originalLogLevel := os.Getenv("PAT_LOG_LEVEL")
	originalAuth := os.Getenv("PAT_ENABLE_AUTH")

	// Cleanup
	defer func() {
		os.Setenv("PAT_SMTP_BIND_ADDR", originalSMTPAddr)
		os.Setenv("PAT_HTTP_BIND_ADDR", originalHTTPAddr)
		os.Setenv("PAT_STORAGE", originalStorage)
		os.Setenv("PAT_LOG_LEVEL", originalLogLevel)
		os.Setenv("PAT_ENABLE_AUTH", originalAuth)
	}()

	// Set test env vars
	os.Setenv("PAT_SMTP_BIND_ADDR", "127.0.0.1:2025")
	os.Setenv("PAT_HTTP_BIND_ADDR", "127.0.0.1:9025")
	os.Setenv("PAT_STORAGE", "postgresql")
	os.Setenv("PAT_LOG_LEVEL", "debug")
	os.Setenv("PAT_ENABLE_AUTH", "true")

	cfg := Configure()

	if cfg.SMTPBindAddr != "127.0.0.1:2025" {
		t.Errorf("Expected SMTP bind addr to be 127.0.0.1:2025, got %s", cfg.SMTPBindAddr)
	}

	if cfg.HTTPBindAddr != "127.0.0.1:9025" {
		t.Errorf("Expected HTTP bind addr to be 127.0.0.1:9025, got %s", cfg.HTTPBindAddr)
	}

	if cfg.StorageType != "postgresql" {
		t.Errorf("Expected storage type to be postgresql, got %s", cfg.StorageType)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("Expected log level to be debug, got %s", cfg.LogLevel)
	}

	if cfg.EnableAuth != true {
		t.Error("Expected auth to be enabled")
	}
}

func TestGetEnvString(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue string
		expected     string
	}{
		{
			name:         "environment variable set",
			envKey:       "TEST_ENV_VAR",
			envValue:     "test_value",
			defaultValue: "default",
			expected:     "test_value",
		},
		{
			name:         "environment variable not set",
			envKey:       "NON_EXISTENT_VAR",
			envValue:     "",
			defaultValue: "default",
			expected:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original value
			original := os.Getenv(tt.envKey)
			defer os.Setenv(tt.envKey, original)

			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
			} else {
				os.Unsetenv(tt.envKey)
			}

			result := getEnvString(tt.envKey, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue bool
		expected     bool
	}{
		{
			name:         "true value",
			envKey:       "TEST_BOOL_TRUE",
			envValue:     "true",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "false value",
			envKey:       "TEST_BOOL_FALSE",
			envValue:     "false",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "1 value",
			envKey:       "TEST_BOOL_ONE",
			envValue:     "1",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "0 value",
			envKey:       "TEST_BOOL_ZERO",
			envValue:     "0",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "invalid value uses default",
			envKey:       "TEST_BOOL_INVALID",
			envValue:     "invalid",
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "unset uses default",
			envKey:       "TEST_BOOL_UNSET",
			envValue:     "",
			defaultValue: false,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original value
			original := os.Getenv(tt.envKey)
			defer os.Setenv(tt.envKey, original)

			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
			} else {
				os.Unsetenv(tt.envKey)
			}

			result := getEnvBool(tt.envKey, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %t, got %t", tt.expected, result)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue int
		expected     int
	}{
		{
			name:         "valid integer",
			envKey:       "TEST_INT_VALID",
			envValue:     "42",
			defaultValue: 10,
			expected:     42,
		},
		{
			name:         "invalid integer uses default",
			envKey:       "TEST_INT_INVALID",
			envValue:     "not_a_number",
			defaultValue: 10,
			expected:     10,
		},
		{
			name:         "unset uses default",
			envKey:       "TEST_INT_UNSET",
			envValue:     "",
			defaultValue: 15,
			expected:     15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original value
			original := os.Getenv(tt.envKey)
			defer os.Setenv(tt.envKey, original)

			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
			} else {
				os.Unsetenv(tt.envKey)
			}

			result := getEnvInt(tt.envKey, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestAIConfiguration(t *testing.T) {
	// Save original env
	originalAPIKey := os.Getenv("PAT_OPENAI_API_KEY")
	originalModel := os.Getenv("PAT_OPENAI_MODEL")
	originalEnabled := os.Getenv("PAT_AI_ENABLED")

	// Cleanup
	defer func() {
		os.Setenv("PAT_OPENAI_API_KEY", originalAPIKey)
		os.Setenv("PAT_OPENAI_MODEL", originalModel)
		os.Setenv("PAT_AI_ENABLED", originalEnabled)
	}()

	t.Run("AI auto-enabled with API key", func(t *testing.T) {
		os.Setenv("PAT_OPENAI_API_KEY", "sk-test-key")
		os.Unsetenv("PAT_AI_ENABLED")

		cfg := Configure()

		if !cfg.EnableAIAnalysis {
			t.Error("Expected AI analysis to be auto-enabled when API key is provided")
		}

		if cfg.OpenAIAPIKey != "sk-test-key" {
			t.Errorf("Expected API key to be sk-test-key, got %s", cfg.OpenAIAPIKey)
		}

		if cfg.OpenAIModel != "gpt-3.5-turbo" {
			t.Errorf("Expected default model to be gpt-3.5-turbo, got %s", cfg.OpenAIModel)
		}
	})

	t.Run("Custom AI model", func(t *testing.T) {
		os.Setenv("PAT_OPENAI_API_KEY", "sk-test-key")
		os.Setenv("PAT_OPENAI_MODEL", "gpt-4")

		cfg := Configure()

		if cfg.OpenAIModel != "gpt-4" {
			t.Errorf("Expected model to be gpt-4, got %s", cfg.OpenAIModel)
		}
	})
}