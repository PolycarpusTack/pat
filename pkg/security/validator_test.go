// Package security implements fortress security tests
// FORTRESS TESTING - Comprehensive input validation tests
package security

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestFortressValidator_ValidateEmail(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewFortressValidator(nil, logger)
	require.NoError(t, err)
	
	tests := []struct {
		name     string
		email    string
		valid    bool
		severity string
	}{
		{"Valid email", "user@example.com", true, "INFO"},
		{"Valid email with subdomain", "user@mail.example.com", true, "INFO"},
		{"Valid email with plus", "user+tag@example.com", true, "INFO"},
		{"Empty email", "", false, "ERROR"},
		{"Invalid format", "invalid-email", false, "ERROR"},
		{"Missing @", "user.example.com", false, "ERROR"},
		{"Missing domain", "user@", false, "ERROR"},
		{"Missing user", "@example.com", false, "ERROR"},
		{"Too long", strings.Repeat("a", 300) + "@example.com", false, "ERROR"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateEmail(tt.email)
			assert.Equal(t, tt.valid, result.Valid, "Email validation result")
			assert.Equal(t, tt.severity, result.Severity, "Severity level")
			
			if tt.valid {
				assert.NotEmpty(t, result.Sanitized, "Should have sanitized email")
				assert.Empty(t, result.Errors, "Should have no errors")
			} else {
				assert.NotEmpty(t, result.Errors, "Should have errors")
			}
		})
	}
}

func TestFortressValidator_ValidateEmailDomains(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultValidatorConfig()
	config.BlockedEmailDomains = []string{"blocked.com", "spam.net"}
	config.AllowedEmailDomains = []string{"allowed.com", "trusted.org"}
	
	validator, err := NewFortressValidator(config, logger)
	require.NoError(t, err)
	
	// Test blocked domains
	result := validator.ValidateEmail("user@blocked.com")
	assert.False(t, result.Valid)
	assert.Equal(t, "HIGH", result.ThreatLevel)
	assert.Contains(t, result.Errors[0], "blocked")
	
	// Test allowed domains
	result = validator.ValidateEmail("user@allowed.com")
	assert.True(t, result.Valid)
	
	// Test non-allowed domain (should be blocked when allowlist is used)
	result = validator.ValidateEmail("user@other.com")
	assert.False(t, result.Valid)
	assert.Contains(t, result.Errors[0], "not in allowed list")
}

func TestFortressValidator_ValidateString(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewFortressValidator(nil, logger)
	require.NoError(t, err)
	
	tests := []struct {
		name        string
		input       string
		fieldName   string
		maxLength   int
		valid       bool
		threatLevel string
	}{
		{"Valid string", "Hello World", "message", 100, true, "SAFE"},
		{"Empty string", "", "message", 100, true, "SAFE"},
		{"Too long", strings.Repeat("a", 1001), "message", 100, false, "MEDIUM"},
		{"SQL injection", "'; DROP TABLE users; --", "input", 100, false, "CRITICAL"},
		{"XSS script", "<script>alert('xss')</script>", "content", 100, false, "CRITICAL"},
		{"Path traversal", "../../../etc/passwd", "filename", 100, false, "HIGH"},
		{"Invalid UTF-8", string([]byte{0xff, 0xfe, 0xfd}), "text", 100, false, "HIGH"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateString(tt.input, tt.fieldName, tt.maxLength)
			assert.Equal(t, tt.valid, result.Valid, "String validation result")
			assert.Equal(t, tt.threatLevel, result.ThreatLevel, "Threat level")
			
			if !tt.valid {
				assert.NotEmpty(t, result.Errors, "Should have errors")
			}
		})
	}
}

func TestFortressValidator_ValidateJSON(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultValidatorConfig()
	config.MaxJSONDepth = 3
	config.MaxJSONSize = 1000
	
	validator, err := NewFortressValidator(config, logger)
	require.NoError(t, err)
	
	tests := []struct {
		name    string
		json    string
		valid   bool
		reason  string
	}{
		{
			"Valid JSON",
			`{"name": "test", "value": 123}`,
			true,
			"",
		},
		{
			"Invalid JSON",
			`{"name": "test", "value": }`,
			false,
			"Invalid JSON format",
		},
		{
			"Too large",
			`{"data": "` + strings.Repeat("a", 2000) + `"}`,
			false,
			"exceeds maximum size",
		},
		{
			"Too deep",
			`{"a": {"b": {"c": {"d": "too deep"}}}}`,
			false,
			"nesting depth",
		},
		{
			"XSS in JSON",
			`{"content": "<script>alert('xss')</script>"}`,
			false,
			"invalid string values",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateJSON([]byte(tt.json))
			assert.Equal(t, tt.valid, result.Valid, "JSON validation result")
			
			if !tt.valid {
				assert.NotEmpty(t, result.Errors, "Should have errors")
				if tt.reason != "" {
					found := false
					for _, err := range result.Errors {
						if strings.Contains(err, tt.reason) {
							found = true
							break
						}
					}
					assert.True(t, found, "Should contain expected error reason: %s", tt.reason)
				}
			}
		})
	}
}

func TestFortressValidator_ValidateURL(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewFortressValidator(nil, logger)
	require.NoError(t, err)
	
	tests := []struct {
		name        string
		url         string
		valid       bool
		threatLevel string
	}{
		{"Valid HTTP URL", "http://example.com", true, "SAFE"},
		{"Valid HTTPS URL", "https://example.com/path", true, "SAFE"},
		{"Valid FTP URL", "ftp://files.example.com", true, "SAFE"},
		{"Empty URL", "", false, "LOW"},
		{"Invalid scheme", "javascript:alert('xss')", false, "HIGH"},
		{"Path traversal in URL", "http://example.com/../../../etc/passwd", false, "HIGH"},
		{"Malformed URL", "http://", false, "MEDIUM"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateURL(tt.url)
			assert.Equal(t, tt.valid, result.Valid, "URL validation result")
			assert.Equal(t, tt.threatLevel, result.ThreatLevel, "Threat level")
			
			if tt.valid {
				assert.NotEmpty(t, result.Sanitized, "Should have sanitized URL")
			}
		})
	}
}

func TestFortressValidator_ValidateFileUpload(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultValidatorConfig()
	config.MaxFileSize = 1024 // 1KB for testing
	config.AllowedMimeTypes = []string{"text/plain", "image/jpeg"}
	config.BlockedMimeTypes = []string{"application/x-executable"}
	
	validator, err := NewFortressValidator(config, logger)
	require.NoError(t, err)
	
	tests := []struct {
		name        string
		filename    string
		contentType string
		size        int64
		valid       bool
		threatLevel string
	}{
		{"Valid text file", "document.txt", "text/plain", 500, true, "SAFE"},
		{"Valid image", "photo.jpg", "image/jpeg", 800, true, "SAFE"},
		{"File too large", "large.txt", "text/plain", 2048, false, "MEDIUM"},
		{"Blocked MIME type", "virus.exe", "application/x-executable", 100, false, "HIGH"},
		{"Not allowed MIME type", "script.js", "text/javascript", 100, false, "HIGH"},
		{"Invalid filename", "../../etc/passwd", "text/plain", 100, false, "MEDIUM"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateFileUpload(tt.filename, tt.contentType, tt.size, nil)
			assert.Equal(t, tt.valid, result.Valid, "File upload validation result")
			assert.Equal(t, tt.threatLevel, result.ThreatLevel, "Threat level")
		})
	}
}

func TestFortressValidator_ValidateGraphQLQuery(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultValidatorConfig()
	config.MaxQueryDepth = 5
	config.MaxQueryComplexity = 50
	config.MaxQuerySize = 1000
	
	validator, err := NewFortressValidator(config, logger)
	require.NoError(t, err)
	
	tests := []struct {
		name    string
		query   string
		valid   bool
		reason  string
	}{
		{
			"Valid query",
			`query { user(id: "123") { name email } }`,
			true,
			"",
		},
		{
			"Query too large",
			`query { ` + strings.Repeat("field ", 200) + `}`,
			false,
			"exceeds maximum size",
		},
		{
			"Query too deep",
			`query { a { b { c { d { e { f { g } } } } } } }`,
			false,
			"depth",
		},
		{
			"XSS in query",
			`query { user(id: "<script>alert('xss')</script>") { name } }`,
			false,
			"Invalid GraphQL query",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateGraphQLQuery(tt.query)
			assert.Equal(t, tt.valid, result.Valid, "GraphQL query validation result")
			
			if !tt.valid && tt.reason != "" {
				found := false
				for _, err := range result.Errors {
					if strings.Contains(err, tt.reason) {
						found = true
						break
					}
				}
				assert.True(t, found, "Should contain expected error reason: %s", tt.reason)
			}
		})
	}
}

func TestFortressValidator_SanitizeHTML(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewFortressValidator(nil, logger)
	require.NoError(t, err)
	
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"Remove script tags",
			`<p>Safe content</p><script>alert('xss')</script>`,
			`<p>Safe content</p>`,
		},
		{
			"Remove iframe",
			`<div>Content</div><iframe src="evil.com"></iframe>`,
			`<div>Content</div>`,
		},
		{
			"Remove event handlers",
			`<img onerror="alert('xss')" src="image.jpg">`,
			`<img  src="image.jpg">`,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.SanitizeHTML(tt.input)
			assert.Equal(t, tt.expected, result, "HTML sanitization result")
		})
	}
}

func TestFortressValidator_UpdateConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewFortressValidator(nil, logger)
	require.NoError(t, err)
	
	// Test config update
	newConfig := DefaultValidatorConfig()
	newConfig.MaxStringLength = 500
	
	err = validator.UpdateConfig(newConfig)
	assert.NoError(t, err)
	
	// Test with nil config
	err = validator.UpdateConfig(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

func TestFortressValidator_JSONDepthCalculation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewFortressValidator(nil, logger)
	require.NoError(t, err)
	
	tests := []struct {
		name     string
		data     interface{}
		expected int
	}{
		{"Simple value", "string", 1},
		{"Simple object", map[string]interface{}{"key": "value"}, 2},
		{"Nested object", map[string]interface{}{"a": map[string]interface{}{"b": "value"}}, 3},
		{"Array", []interface{}{"a", "b", "c"}, 2},
		{"Mixed nesting", map[string]interface{}{"arr": []interface{}{map[string]interface{}{"nested": "value"}}}, 4},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			depth := validator.calculateJSONDepth(tt.data)
			assert.Equal(t, tt.expected, depth, "JSON depth calculation")
		})
	}
}

func TestFortressValidator_SecurityPatterns(t *testing.T) {
	logger := zaptest.NewLogger(t)
	validator, err := NewFortressValidator(nil, logger)
	require.NoError(t, err)
	
	// Test that security patterns are properly compiled
	assert.NotEmpty(t, validator.sqlPatterns, "Should have SQL injection patterns")
	assert.NotEmpty(t, validator.xssPatterns, "Should have XSS patterns")
	assert.NotEmpty(t, validator.traversalPatterns, "Should have path traversal patterns")
	
	// Test pattern matching
	sqlTests := []string{
		"'; DROP TABLE users; --",
		"UNION SELECT * FROM passwords",
		"OR 1=1",
		"/* malicious comment */",
	}
	
	for _, test := range sqlTests {
		result := validator.ValidateString(test, "input", 1000)
		assert.False(t, result.Valid, "Should detect SQL injection: %s", test)
		assert.Equal(t, "CRITICAL", result.ThreatLevel)
	}
	
	xssTests := []string{
		"<script>alert('xss')</script>",
		"<iframe src='javascript:alert(1)'></iframe>",
		"<img onerror='alert(1)' src='x'>",
		"javascript:alert('xss')",
	}
	
	for _, test := range xssTests {
		result := validator.ValidateString(test, "input", 1000)
		assert.False(t, result.Valid, "Should detect XSS: %s", test)
		assert.Equal(t, "CRITICAL", result.ThreatLevel)
	}
}

func BenchmarkFortressValidator_ValidateEmail(b *testing.B) {
	logger := zaptest.NewLogger(b)
	validator, _ := NewFortressValidator(nil, logger)
	
	email := "user@example.com"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateEmail(email)
	}
}

func BenchmarkFortressValidator_ValidateString(b *testing.B) {
	logger := zaptest.NewLogger(b)
	validator, _ := NewFortressValidator(nil, logger)
	
	input := "This is a test string with some content"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateString(input, "test", 1000)
	}
}

func BenchmarkFortressValidator_ValidateJSON(b *testing.B) {
	logger := zaptest.NewLogger(b)
	validator, _ := NewFortressValidator(nil, logger)
	
	data := map[string]interface{}{
		"name":  "test",
		"value": 123,
		"nested": map[string]interface{}{
			"field": "data",
		},
	}
	jsonData, _ := json.Marshal(data)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateJSON(jsonData)
	}
}