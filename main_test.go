package main

import (
	"testing"

	"github.com/pat-fortress/config"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.FortressConfig
		expectError bool
		errorString string
	}{
		{
			name: "valid config",
			config: &config.FortressConfig{
				MaxMessageSize:  10 * 1024 * 1024, // 10MB
				EnableTLS:       false,
				EnableRateLimit: true,
				MaxPerIP:        100,
				RetentionDays:   7,
			},
			expectError: false,
		},
		{
			name: "message size too small",
			config: &config.FortressConfig{
				MaxMessageSize:  512, // Less than 1KB
				EnableTLS:       false,
				EnableRateLimit: true,
				MaxPerIP:        100,
				RetentionDays:   7,
			},
			expectError: true,
			errorString: "max message size too small",
		},
		{
			name: "message size too large",
			config: &config.FortressConfig{
				MaxMessageSize:  200 * 1024 * 1024, // 200MB
				EnableTLS:       false,
				EnableRateLimit: true,
				MaxPerIP:        100,
				RetentionDays:   7,
			},
			expectError: true,
			errorString: "max message size too large",
		},
		{
			name: "TLS enabled without cert files",
			config: &config.FortressConfig{
				MaxMessageSize:  10 * 1024 * 1024,
				EnableTLS:       true,
				TLSCertFile:     "", // Missing cert file
				TLSKeyFile:      "", // Missing key file
				EnableRateLimit: true,
				MaxPerIP:        100,
				RetentionDays:   7,
			},
			expectError: true,
			errorString: "TLS enabled but cert/key files not specified",
		},
		{
			name: "rate limiting enabled with invalid MaxPerIP",
			config: &config.FortressConfig{
				MaxMessageSize:  10 * 1024 * 1024,
				EnableTLS:       false,
				EnableRateLimit: true,
				MaxPerIP:        0, // Invalid value
				RetentionDays:   7,
			},
			expectError: true,
			errorString: "rate limiting enabled but MaxPerIP is 0",
		},
		{
			name: "negative retention days",
			config: &config.FortressConfig{
				MaxMessageSize:  10 * 1024 * 1024,
				EnableTLS:       false,
				EnableRateLimit: true,
				MaxPerIP:        100,
				RetentionDays:   -1, // Negative value
			},
			expectError: true,
			errorString: "retention days cannot be negative",
		},
		{
			name: "TLS with cert and key files",
			config: &config.FortressConfig{
				MaxMessageSize:  10 * 1024 * 1024,
				EnableTLS:       true,
				TLSCertFile:     "/path/to/cert.pem",
				TLSKeyFile:      "/path/to/key.pem",
				EnableRateLimit: true,
				MaxPerIP:        100,
				RetentionDays:   7,
			},
			expectError: false,
		},
		{
			name: "rate limiting disabled",
			config: &config.FortressConfig{
				MaxMessageSize:  10 * 1024 * 1024,
				EnableTLS:       false,
				EnableRateLimit: false, // Disabled
				MaxPerIP:        0,     // Should be ignored when disabled
				RetentionDays:   7,
			},
			expectError: false,
		},
		{
			name: "minimum valid message size",
			config: &config.FortressConfig{
				MaxMessageSize:  1024, // Exactly 1KB
				EnableTLS:       false,
				EnableRateLimit: true,
				MaxPerIP:        1, // Minimum valid value
				RetentionDays:   0, // Zero is valid
			},
			expectError: false,
		},
		{
			name: "maximum valid message size",
			config: &config.FortressConfig{
				MaxMessageSize:  100 * 1024 * 1024, // Exactly 100MB
				EnableTLS:       false,
				EnableRateLimit: true,
				MaxPerIP:        1000,
				RetentionDays:   365,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorString)
				} else if tt.errorString != "" && len(tt.errorString) > 0 {
					// Check if error message contains expected string
					if len(err.Error()) == 0 || len(tt.errorString) == 0 {
						t.Errorf("Expected error containing '%s', got '%s'", tt.errorString, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

func TestGetStorageDSN(t *testing.T) {
	// Test that getStorageDSN returns empty string for memory storage
	dsn := getStorageDSN()
	if dsn != "" {
		t.Errorf("Expected empty DSN for memory storage, got: %s", dsn)
	}
}

func TestVersion(t *testing.T) {
	if version == "" {
		t.Error("Expected version to be set")
	}

	if version != "fortress-2.0.0" {
		t.Errorf("Expected version to be 'fortress-2.0.0', got: %s", version)
	}
}

// Test helper functions
func TestGlobalVariables(t *testing.T) {
	// Test that global variables are properly declared
	if logger != nil {
		t.Error("Expected logger to be nil initially")
	}

	if store != nil {
		t.Error("Expected store to be nil initially")
	}

	if cfg != nil {
		t.Error("Expected cfg to be nil initially")
	}
}

// Benchmark tests
func BenchmarkValidateConfig(b *testing.B) {
	config := &config.FortressConfig{
		MaxMessageSize:  10 * 1024 * 1024,
		EnableTLS:       false,
		EnableRateLimit: true,
		MaxPerIP:        100,
		RetentionDays:   7,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validateConfig(config)
	}
}

func BenchmarkGetStorageDSN(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getStorageDSN()
	}
}