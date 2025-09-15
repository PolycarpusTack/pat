// Package security implements fortress-grade input validation
// FORTRESS GUARD SYSTEM - Comprehensive input validation and sanitization
package security

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"go.uber.org/zap"
)

// FortressValidatorConfig defines comprehensive validation rules
type FortressValidatorConfig struct {
	// Email validation settings
	MaxEmailLength        int      `json:"max_email_length"`
	AllowedEmailDomains   []string `json:"allowed_email_domains"`
	BlockedEmailDomains   []string `json:"blocked_email_domains"`
	RequireEmailTLS       bool     `json:"require_email_tls"`
	
	// String validation settings
	MaxStringLength       int      `json:"max_string_length"`
	MaxTextLength         int      `json:"max_text_length"`
	AllowedCharsets       []string `json:"allowed_charsets"`
	
	// JSON/XML validation settings
	MaxJSONDepth          int      `json:"max_json_depth"`
	MaxJSONSize           int      `json:"max_json_size"`
	MaxXMLDepth           int      `json:"max_xml_depth"`
	MaxXMLSize            int      `json:"max_xml_size"`
	
	// File upload validation
	MaxFileSize           int64    `json:"max_file_size"`
	AllowedMimeTypes      []string `json:"allowed_mime_types"`
	BlockedMimeTypes      []string `json:"blocked_mime_types"`
	RequireVirusScan      bool     `json:"require_virus_scan"`
	
	// GraphQL validation
	MaxQueryDepth         int      `json:"max_query_depth"`
	MaxQueryComplexity    int      `json:"max_query_complexity"`
	MaxQuerySize          int      `json:"max_query_size"`
	
	// SQL injection patterns
	SQLInjectionPatterns  []string `json:"sql_injection_patterns"`
	
	// XSS prevention patterns
	XSSPatterns           []string `json:"xss_patterns"`
	
	// Path traversal patterns
	PathTraversalPatterns []string `json:"path_traversal_patterns"`
}

// DefaultValidatorConfig returns fortress-grade validation settings
func DefaultValidatorConfig() *FortressValidatorConfig {
	return &FortressValidatorConfig{
		MaxEmailLength:      320,   // RFC 5321 limit
		AllowedEmailDomains: []string{}, // Empty = all allowed
		BlockedEmailDomains: []string{"example.com", "test.com", "invalid.com"},
		RequireEmailTLS:     true,
		
		MaxStringLength:     1000,
		MaxTextLength:       100000,
		AllowedCharsets:     []string{"UTF-8"},
		
		MaxJSONDepth:        10,
		MaxJSONSize:         1048576, // 1MB
		MaxXMLDepth:         10,
		MaxXMLSize:          1048576, // 1MB
		
		MaxFileSize:         52428800, // 50MB
		AllowedMimeTypes:    []string{
			"text/plain", "text/html", "text/css", "text/javascript",
			"application/json", "application/xml", "application/pdf",
			"image/jpeg", "image/png", "image/gif", "image/webp",
			"application/zip", "application/octet-stream",
		},
		BlockedMimeTypes:    []string{
			"application/x-executable", "application/x-msdownload",
			"application/x-dosexec", "application/x-winexe",
		},
		RequireVirusScan:    true,
		
		MaxQueryDepth:       10,
		MaxQueryComplexity:  1000,
		MaxQuerySize:        100000,
		
		SQLInjectionPatterns: []string{
			`(?i)\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b`,
			`(?i)\b(or|and)\s+\d+\s*=\s*\d+`,
			`(?i)\b(or|and)\s+['"]\w+['"]\s*=\s*['"]\w+['"]`,
			`(?i)[\s'"]*;\s*(drop|delete|update|insert|create|alter)\b`,
			`(?i)\b(information_schema|mysql|pg_|sys\.)\b`,
			`(?i)[\s'"]*--[\s\S]*$`,
			`(?i)/\*[\s\S]*?\*/`,
		},
		
		XSSPatterns: []string{
			`(?i)<script[\s\S]*?>[\s\S]*?</script>`,
			`(?i)<iframe[\s\S]*?>[\s\S]*?</iframe>`,
			`(?i)<object[\s\S]*?>[\s\S]*?</object>`,
			`(?i)<embed[\s\S]*?>`,
			`(?i)<applet[\s\S]*?>[\s\S]*?</applet>`,
			`(?i)javascript:[\s\S]*`,
			`(?i)vbscript:[\s\S]*`,
			`(?i)on\w+\s*=[\s\S]*`,
			`(?i)<img[\s\S]*?onerror[\s\S]*?>`,
			`(?i)<svg[\s\S]*?onload[\s\S]*?>`,
		},
		
		PathTraversalPatterns: []string{
			`\.\.\/`,
			`\.\.\\`,
			`\.\.[/\\]`,
			`[/\\]\.\.`,
			`%2e%2e%2f`,
			`%2e%2e%5c`,
			`%252e%252e%252f`,
			`%c0%ae%c0%ae%c0%af`,
		},
	}
}

// ValidationResult represents fortress validation outcome
type ValidationResult struct {
	Valid       bool     `json:"valid"`
	Errors      []string `json:"errors,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Severity    string   `json:"severity"`
	ThreatLevel string   `json:"threat_level"`
	Sanitized   string   `json:"sanitized,omitempty"`
}

// FortressValidator implements comprehensive security validation
type FortressValidator struct {
	config           *FortressValidatorConfig
	logger           *zap.Logger
	emailRegex       *regexp.Regexp
	sqlPatterns      []*regexp.Regexp
	xssPatterns      []*regexp.Regexp
	traversalPatterns []*regexp.Regexp
}

// NewFortressValidator creates a new fortress input validator
func NewFortressValidator(config *FortressValidatorConfig, logger *zap.Logger) (*FortressValidator, error) {
	if config == nil {
		config = DefaultValidatorConfig()
	}
	
	// Compile email regex (RFC 5322 compliant)
	emailRegex, err := regexp.Compile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile email regex: %w", err)
	}
	
	validator := &FortressValidator{
		config:     config,
		logger:     logger,
		emailRegex: emailRegex,
	}
	
	// Compile security patterns
	if err := validator.compileSecurityPatterns(); err != nil {
		return nil, fmt.Errorf("failed to compile security patterns: %w", err)
	}
	
	return validator, nil
}

// compileSecurityPatterns compiles all security validation patterns
func (fv *FortressValidator) compileSecurityPatterns() error {
	// Compile SQL injection patterns
	for _, pattern := range fv.config.SQLInjectionPatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile SQL pattern '%s': %w", pattern, err)
		}
		fv.sqlPatterns = append(fv.sqlPatterns, regex)
	}
	
	// Compile XSS patterns
	for _, pattern := range fv.config.XSSPatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile XSS pattern '%s': %w", pattern, err)
		}
		fv.xssPatterns = append(fv.xssPatterns, regex)
	}
	
	// Compile path traversal patterns
	for _, pattern := range fv.config.PathTraversalPatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile traversal pattern '%s': %w", pattern, err)
		}
		fv.traversalPatterns = append(fv.traversalPatterns, regex)
	}
	
	return nil
}

// ValidateEmail performs fortress-grade email validation
func (fv *FortressValidator) ValidateEmail(email string) *ValidationResult {
	result := &ValidationResult{
		Valid:       true,
		Severity:    "INFO",
		ThreatLevel: "SAFE",
	}
	
	// Basic length validation
	if len(email) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "Email cannot be empty")
		result.Severity = "ERROR"
		result.ThreatLevel = "LOW"
		return result
	}
	
	if len(email) > fv.config.MaxEmailLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Email exceeds maximum length of %d characters", fv.config.MaxEmailLength))
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// RFC 5322 validation using Go's mail package
	addr, err := mail.ParseAddress(email)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, "Invalid email format: "+err.Error())
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// Extract domain for domain-based validation
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		result.Valid = false
		result.Errors = append(result.Errors, "Invalid email format")
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	domain := strings.ToLower(parts[1])
	
	// Check against blocked domains
	for _, blocked := range fv.config.BlockedEmailDomains {
		if strings.ToLower(blocked) == domain {
			result.Valid = false
			result.Errors = append(result.Errors, "Email domain is blocked")
			result.Severity = "ERROR"
			result.ThreatLevel = "HIGH"
			return result
		}
	}
	
	// Check against allowed domains (if specified)
	if len(fv.config.AllowedEmailDomains) > 0 {
		allowed := false
		for _, allowedDomain := range fv.config.AllowedEmailDomains {
			if strings.ToLower(allowedDomain) == domain {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Valid = false
			result.Errors = append(result.Errors, "Email domain is not in allowed list")
			result.Severity = "ERROR"
			result.ThreatLevel = "HIGH"
			return result
		}
	}
	
	result.Sanitized = addr.Address
	return result
}

// ValidateString performs comprehensive string validation
func (fv *FortressValidator) ValidateString(input, fieldName string, maxLength int) *ValidationResult {
	result := &ValidationResult{
		Valid:       true,
		Severity:    "INFO",
		ThreatLevel: "SAFE",
	}
	
	if maxLength == 0 {
		maxLength = fv.config.MaxStringLength
	}
	
	// Length validation
	if len(input) > maxLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("%s exceeds maximum length of %d characters", fieldName, maxLength))
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// UTF-8 validation
	if !utf8.ValidString(input) {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("%s contains invalid UTF-8 characters", fieldName))
		result.Severity = "ERROR"
		result.ThreatLevel = "HIGH"
		return result
	}
	
	// SQL injection detection
	for _, pattern := range fv.sqlPatterns {
		if pattern.MatchString(input) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("%s contains potential SQL injection pattern", fieldName))
			result.Severity = "CRITICAL"
			result.ThreatLevel = "CRITICAL"
			return result
		}
	}
	
	// XSS detection
	for _, pattern := range fv.xssPatterns {
		if pattern.MatchString(input) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("%s contains potential XSS pattern", fieldName))
			result.Severity = "CRITICAL"
			result.ThreatLevel = "CRITICAL"
			return result
		}
	}
	
	// Path traversal detection
	for _, pattern := range fv.traversalPatterns {
		if pattern.MatchString(input) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("%s contains potential path traversal pattern", fieldName))
			result.Severity = "HIGH"
			result.ThreatLevel = "HIGH"
			return result
		}
	}
	
	result.Sanitized = input
	return result
}

// ValidateJSON performs fortress-grade JSON validation
func (fv *FortressValidator) ValidateJSON(jsonData []byte) *ValidationResult {
	result := &ValidationResult{
		Valid:       true,
		Severity:    "INFO",
		ThreatLevel: "SAFE",
	}
	
	// Size validation
	if len(jsonData) > fv.config.MaxJSONSize {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("JSON exceeds maximum size of %d bytes", fv.config.MaxJSONSize))
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// Parse and validate JSON structure
	var parsed interface{}
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, "Invalid JSON format: "+err.Error())
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// Check nesting depth
	depth := fv.calculateJSONDepth(parsed)
	if depth > fv.config.MaxJSONDepth {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("JSON nesting depth %d exceeds maximum of %d", depth, fv.config.MaxJSONDepth))
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// Validate string values within JSON
	if err := fv.validateJSONStrings(parsed, result); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, "JSON contains invalid string values: "+err.Error())
		result.Severity = "HIGH"
		result.ThreatLevel = "HIGH"
		return result
	}
	
	return result
}

// calculateJSONDepth recursively calculates JSON nesting depth
func (fv *FortressValidator) calculateJSONDepth(data interface{}) int {
	switch v := data.(type) {
	case map[string]interface{}:
		maxDepth := 0
		for _, value := range v {
			if depth := fv.calculateJSONDepth(value); depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	case []interface{}:
		maxDepth := 0
		for _, value := range v {
			if depth := fv.calculateJSONDepth(value); depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	default:
		return 1
	}
}

// validateJSONStrings recursively validates string values in JSON
func (fv *FortressValidator) validateJSONStrings(data interface{}, result *ValidationResult) error {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			// Validate key
			keyResult := fv.ValidateString(key, "JSON key", 100)
			if !keyResult.Valid {
				return fmt.Errorf("invalid key '%s': %s", key, strings.Join(keyResult.Errors, ", "))
			}
			
			// Recursively validate value
			if err := fv.validateJSONStrings(value, result); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, value := range v {
			if err := fv.validateJSONStrings(value, result); err != nil {
				return err
			}
		}
	case string:
		stringResult := fv.ValidateString(v, "JSON string", fv.config.MaxStringLength)
		if !stringResult.Valid {
			return fmt.Errorf("invalid string value: %s", strings.Join(stringResult.Errors, ", "))
		}
		
		// Add warnings for detected patterns
		if len(stringResult.Warnings) > 0 {
			result.Warnings = append(result.Warnings, stringResult.Warnings...)
		}
	}
	
	return nil
}

// ValidateURL performs fortress-grade URL validation
func (fv *FortressValidator) ValidateURL(urlStr string) *ValidationResult {
	result := &ValidationResult{
		Valid:       true,
		Severity:    "INFO",
		ThreatLevel: "SAFE",
	}
	
	// Basic validation
	if len(urlStr) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "URL cannot be empty")
		result.Severity = "ERROR"
		result.ThreatLevel = "LOW"
		return result
	}
	
	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, "Invalid URL format: "+err.Error())
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// Validate scheme
	allowedSchemes := []string{"http", "https", "ftp", "ftps"}
	schemeValid := false
	for _, allowed := range allowedSchemes {
		if parsedURL.Scheme == allowed {
			schemeValid = true
			break
		}
	}
	
	if !schemeValid {
		result.Valid = false
		result.Errors = append(result.Errors, "URL scheme not allowed: "+parsedURL.Scheme)
		result.Severity = "HIGH"
		result.ThreatLevel = "HIGH"
		return result
	}
	
	// Check for path traversal in URL
	for _, pattern := range fv.traversalPatterns {
		if pattern.MatchString(parsedURL.Path) {
			result.Valid = false
			result.Errors = append(result.Errors, "URL contains path traversal pattern")
			result.Severity = "HIGH"
			result.ThreatLevel = "HIGH"
			return result
		}
	}
	
	result.Sanitized = parsedURL.String()
	return result
}

// ValidateFileUpload performs comprehensive file upload validation
func (fv *FortressValidator) ValidateFileUpload(filename string, contentType string, size int64, content []byte) *ValidationResult {
	result := &ValidationResult{
		Valid:       true,
		Severity:    "INFO",
		ThreatLevel: "SAFE",
	}
	
	// Size validation
	if size > fv.config.MaxFileSize {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("File size %d exceeds maximum of %d bytes", size, fv.config.MaxFileSize))
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// Filename validation
	filenameResult := fv.ValidateString(filename, "filename", 255)
	if !filenameResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, "Invalid filename: "+strings.Join(filenameResult.Errors, ", "))
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// MIME type validation
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, "Invalid content type: "+err.Error())
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// Check against blocked MIME types
	for _, blocked := range fv.config.BlockedMimeTypes {
		if strings.EqualFold(mediaType, blocked) {
			result.Valid = false
			result.Errors = append(result.Errors, "File type is blocked: "+mediaType)
			result.Severity = "HIGH"
			result.ThreatLevel = "HIGH"
			return result
		}
	}
	
	// Check against allowed MIME types (if specified)
	if len(fv.config.AllowedMimeTypes) > 0 {
		allowed := false
		for _, allowedType := range fv.config.AllowedMimeTypes {
			if strings.EqualFold(mediaType, allowedType) {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Valid = false
			result.Errors = append(result.Errors, "File type not allowed: "+mediaType)
			result.Severity = "HIGH"
			result.ThreatLevel = "HIGH"
			return result
		}
	}
	
	// Basic content validation
	if fv.config.RequireVirusScan {
		result.Warnings = append(result.Warnings, "Virus scan required for uploaded file")
	}
	
	return result
}

// ValidateGraphQLQuery performs fortress-grade GraphQL query validation
func (fv *FortressValidator) ValidateGraphQLQuery(query string) *ValidationResult {
	result := &ValidationResult{
		Valid:       true,
		Severity:    "INFO",
		ThreatLevel: "SAFE",
	}
	
	// Size validation
	if len(query) > fv.config.MaxQuerySize {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("GraphQL query exceeds maximum size of %d characters", fv.config.MaxQuerySize))
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	// Basic string validation
	stringResult := fv.ValidateString(query, "GraphQL query", fv.config.MaxQuerySize)
	if !stringResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, "Invalid GraphQL query: "+strings.Join(stringResult.Errors, ", "))
		result.Severity = stringResult.Severity
		result.ThreatLevel = stringResult.ThreatLevel
		return result
	}
	
	// Estimate query depth and complexity
	depth := fv.estimateGraphQLDepth(query)
	if depth > fv.config.MaxQueryDepth {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("GraphQL query depth %d exceeds maximum of %d", depth, fv.config.MaxQueryDepth))
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	complexity := fv.estimateGraphQLComplexity(query)
	if complexity > fv.config.MaxQueryComplexity {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("GraphQL query complexity %d exceeds maximum of %d", complexity, fv.config.MaxQueryComplexity))
		result.Severity = "ERROR"
		result.ThreatLevel = "MEDIUM"
		return result
	}
	
	return result
}

// estimateGraphQLDepth estimates the nesting depth of a GraphQL query
func (fv *FortressValidator) estimateGraphQLDepth(query string) int {
	depth := 0
	currentDepth := 0
	
	for _, char := range query {
		switch char {
		case '{':
			currentDepth++
			if currentDepth > depth {
				depth = currentDepth
			}
		case '}':
			currentDepth--
		}
	}
	
	return depth
}

// estimateGraphQLComplexity estimates the complexity of a GraphQL query
func (fv *FortressValidator) estimateGraphQLComplexity(query string) int {
	// Simple complexity estimation based on field count and nesting
	fieldCount := strings.Count(query, "\n") + strings.Count(query, ",")
	nestingBonus := fv.estimateGraphQLDepth(query) * 10
	
	return fieldCount + nestingBonus
}

// SanitizeHTML sanitizes HTML input to prevent XSS attacks
func (fv *FortressValidator) SanitizeHTML(input string) string {
	// Basic HTML sanitization - remove script tags and dangerous attributes
	sanitized := input
	
	for _, pattern := range fv.xssPatterns {
		sanitized = pattern.ReplaceAllString(sanitized, "")
	}
	
	return sanitized
}

// GetConfig returns the current validator configuration
func (fv *FortressValidator) GetConfig() *FortressValidatorConfig {
	return fv.config
}

// UpdateConfig updates the validator configuration
func (fv *FortressValidator) UpdateConfig(config *FortressValidatorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	fv.config = config
	
	// Recompile security patterns with new configuration
	if err := fv.compileSecurityPatterns(); err != nil {
		return fmt.Errorf("failed to recompile security patterns: %w", err)
	}
	
	fv.logger.Info("Fortress validator configuration updated")
	
	return nil
}