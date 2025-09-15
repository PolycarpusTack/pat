package plugins

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/robertkrimen/otto"
)

// Validator validates plugin metadata and code
type Validator struct {
	allowedPermissions map[string]bool
	allowedHooks       map[string]bool
	maxCodeSize        int
	maxMemoryLimit     int
	maxCPUTimeLimit    int
}

// NewValidator creates a new plugin validator
func NewValidator() *Validator {
	return &Validator{
		allowedPermissions: map[string]bool{
			"email:read":     true,
			"email:write":    true,
			"storage:read":   true,
			"storage:write":  true,
			"http:request":   true,
			"webhook:send":   true,
			"analytics:read": true,
		},
		allowedHooks: map[string]bool{
			"email.received":  true,
			"email.processed": true,
			"email.sent":      true,
			"workflow.start":  true,
			"workflow.end":    true,
			"user.login":      true,
			"user.logout":     true,
		},
		maxCodeSize:     1024 * 1024, // 1MB
		maxMemoryLimit:  512,         // 512MB
		maxCPUTimeLimit: 5000,        // 5 seconds
	}
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ValidationResult contains validation results
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors"`
}

// ValidateMetadata validates plugin metadata
func (v *Validator) ValidateMetadata(metadata *PluginMetadata) error {
	var errors []ValidationError

	// Validate required fields
	if metadata.Name == "" {
		errors = append(errors, ValidationError{
			Field:   "name",
			Message: "Plugin name is required",
			Code:    "REQUIRED_FIELD",
		})
	}

	if metadata.Version == "" {
		errors = append(errors, ValidationError{
			Field:   "version",
			Message: "Plugin version is required",
			Code:    "REQUIRED_FIELD",
		})
	}

	if metadata.Author == "" {
		errors = append(errors, ValidationError{
			Field:   "author",
			Message: "Plugin author is required",
			Code:    "REQUIRED_FIELD",
		})
	}

	if metadata.Description == "" {
		errors = append(errors, ValidationError{
			Field:   "description",
			Message: "Plugin description is required",
			Code:    "REQUIRED_FIELD",
		})
	}

	// Validate name format
	if !v.isValidName(metadata.Name) {
		errors = append(errors, ValidationError{
			Field:   "name",
			Message: "Plugin name must contain only alphanumeric characters, hyphens, and underscores",
			Code:    "INVALID_FORMAT",
		})
	}

	// Validate version format (semantic versioning)
	if !v.isValidVersion(metadata.Version) {
		errors = append(errors, ValidationError{
			Field:   "version",
			Message: "Plugin version must follow semantic versioning (e.g., 1.0.0)",
			Code:    "INVALID_FORMAT",
		})
	}

	// Validate permissions
	for _, permission := range metadata.Permissions {
		if !v.allowedPermissions[permission] {
			errors = append(errors, ValidationError{
				Field:   "permissions",
				Message: fmt.Sprintf("Permission '%s' is not allowed", permission),
				Code:    "INVALID_PERMISSION",
			})
		}
	}

	// Validate hooks
	for _, hook := range metadata.Hooks {
		if !v.allowedHooks[hook] {
			errors = append(errors, ValidationError{
				Field:   "hooks",
				Message: fmt.Sprintf("Hook '%s' is not allowed", hook),
				Code:    "INVALID_HOOK",
			})
		}
	}

	// Validate resource limits
	if metadata.MaxMemory <= 0 || metadata.MaxMemory > v.maxMemoryLimit {
		errors = append(errors, ValidationError{
			Field:   "max_memory",
			Message: fmt.Sprintf("Memory limit must be between 1 and %d MB", v.maxMemoryLimit),
			Code:    "INVALID_LIMIT",
		})
	}

	if metadata.MaxCPUTime <= 0 || metadata.MaxCPUTime > v.maxCPUTimeLimit {
		errors = append(errors, ValidationError{
			Field:   "max_cpu_time",
			Message: fmt.Sprintf("CPU time limit must be between 1 and %d ms", v.maxCPUTimeLimit),
			Code:    "INVALID_LIMIT",
		})
	}

	// Validate description length
	if len(metadata.Description) > 1000 {
		errors = append(errors, ValidationError{
			Field:   "description",
			Message: "Description must be less than 1000 characters",
			Code:    "LENGTH_EXCEEDED",
		})
	}

	// Validate category
	if metadata.Category != "" && !v.isValidCategory(metadata.Category) {
		errors = append(errors, ValidationError{
			Field:   "category",
			Message: "Invalid category",
			Code:    "INVALID_CATEGORY",
		})
	}

	// Validate tags
	for _, tag := range metadata.Tags {
		if !v.isValidTag(tag) {
			errors = append(errors, ValidationError{
				Field:   "tags",
				Message: fmt.Sprintf("Invalid tag: %s", tag),
				Code:    "INVALID_TAG",
			})
		}
	}

	if len(errors) > 0 {
		return v.createValidationError(errors)
	}

	return nil
}

// ValidateCode validates plugin JavaScript code
func (v *Validator) ValidateCode(code string, metadata *PluginMetadata) error {
	var errors []ValidationError

	// Check code size
	if len(code) > v.maxCodeSize {
		errors = append(errors, ValidationError{
			Field:   "code",
			Message: fmt.Sprintf("Code size exceeds maximum of %d bytes", v.maxCodeSize),
			Code:    "SIZE_EXCEEDED",
		})
	}

	// Check for required main function
	if !strings.Contains(code, "function main") && !strings.Contains(code, "const main") && !strings.Contains(code, "let main") {
		errors = append(errors, ValidationError{
			Field:   "code",
			Message: "Plugin must export a main function",
			Code:    "MISSING_MAIN_FUNCTION",
		})
	}

	// Syntax validation using Otto
	vm := otto.New()
	_, err := vm.Compile("", code)
	if err != nil {
		errors = append(errors, ValidationError{
			Field:   "code",
			Message: fmt.Sprintf("JavaScript syntax error: %s", err.Error()),
			Code:    "SYNTAX_ERROR",
		})
	}

	// Security checks
	securityErrors := v.performSecurityChecks(code)
	errors = append(errors, securityErrors...)

	// API usage validation
	apiErrors := v.validateAPIUsage(code, metadata.Permissions)
	errors = append(errors, apiErrors...)

	if len(errors) > 0 {
		return v.createValidationError(errors)
	}

	return nil
}

// performSecurityChecks checks for potentially dangerous code patterns
func (v *Validator) performSecurityChecks(code string) []ValidationError {
	var errors []ValidationError

	// Dangerous patterns to check for
	dangerousPatterns := map[string]string{
		`eval\s*\(`:                    "Use of eval() is not allowed",
		`Function\s*\(`:                "Use of Function constructor is not allowed",
		`require\s*\(`:                 "Use of require() is not allowed",
		`import\s+.*\s+from`:           "ES6 imports are not allowed",
		`process\.`:                    "Access to process object is not allowed",
		`global\.`:                     "Access to global object is not allowed",
		`__dirname`:                    "Access to __dirname is not allowed",
		`__filename`:                   "Access to __filename is not allowed",
		`setTimeout\s*\(`:              "Use of setTimeout is not allowed",
		`setInterval\s*\(`:             "Use of setInterval is not allowed",
		`setImmediate\s*\(`:            "Use of setImmediate is not allowed",
		`XMLHttpRequest`:               "Use of XMLHttpRequest is not allowed, use Http API instead",
		`fetch\s*\(`:                   "Use of fetch is not allowed, use Http API instead",
		`document\.`:                   "Access to DOM is not allowed",
		`window\.`:                     "Access to window object is not allowed",
		`localStorage`:                 "Access to localStorage is not allowed, use Storage API instead",
		`sessionStorage`:               "Access to sessionStorage is not allowed, use Storage API instead",
		`IndexedDB`:                    "Access to IndexedDB is not allowed",
		`WebSocket`:                    "Direct WebSocket usage is not allowed",
		`Worker\s*\(`:                  "Web Workers are not allowed",
		`SharedArrayBuffer`:            "SharedArrayBuffer is not allowed",
		`Atomics\.`:                    "Atomics operations are not allowed",
		`while\s*\(\s*true\s*\)`:       "Infinite loops are not allowed",
		`for\s*\(\s*;\s*;\s*\)`:        "Infinite loops are not allowed",
		`crypto\.subtle`:               "Direct crypto API usage is not allowed, use Utils.hash instead",
		`btoa\s*\(`:                    "Use Utils.base64Encode instead",
		`atob\s*\(`:                    "Use Utils.base64Decode instead",
	}

	for pattern, message := range dangerousPatterns {
		matched, _ := regexp.MatchString(pattern, code)
		if matched {
			errors = append(errors, ValidationError{
				Field:   "code",
				Message: message,
				Code:    "SECURITY_VIOLATION",
			})
		}
	}

	// Check for suspicious string patterns
	suspiciousStrings := []string{
		"javascript:",
		"data:text/html",
		"<script",
		"</script>",
		"onclick=",
		"onerror=",
		"onload=",
	}

	for _, suspicious := range suspiciousStrings {
		if strings.Contains(strings.ToLower(code), strings.ToLower(suspicious)) {
			errors = append(errors, ValidationError{
				Field:   "code",
				Message: fmt.Sprintf("Suspicious string pattern detected: %s", suspicious),
				Code:    "SECURITY_VIOLATION",
			})
		}
	}

	return errors
}

// validateAPIUsage checks if the code uses APIs it has permission for
func (v *Validator) validateAPIUsage(code string, permissions []string) []ValidationError {
	var errors []ValidationError

	permissionSet := make(map[string]bool)
	for _, perm := range permissions {
		permissionSet[perm] = true
	}

	// Check Email API usage
	if strings.Contains(code, "Email.") && !permissionSet["email:read"] && !permissionSet["email:write"] {
		errors = append(errors, ValidationError{
			Field:   "code",
			Message: "Code uses Email API but lacks email permissions",
			Code:    "MISSING_PERMISSION",
		})
	}

	// Check Http API usage
	if (strings.Contains(code, "Http.get") || strings.Contains(code, "Http.post")) && !permissionSet["http:request"] {
		errors = append(errors, ValidationError{
			Field:   "code",
			Message: "Code uses Http API but lacks http:request permission",
			Code:    "MISSING_PERMISSION",
		})
	}

	// Check Storage API usage
	if strings.Contains(code, "Storage.") && !permissionSet["storage:read"] && !permissionSet["storage:write"] {
		errors = append(errors, ValidationError{
			Field:   "code",
			Message: "Code uses Storage API but lacks storage permissions",
			Code:    "MISSING_PERMISSION",
		})
	}

	return errors
}

// isValidName checks if plugin name follows naming conventions
func (v *Validator) isValidName(name string) bool {
	// Plugin name should be 3-50 characters, alphanumeric, hyphens, underscores
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]{3,50}$`, name)
	return matched
}

// isValidVersion checks if version follows semantic versioning
func (v *Validator) isValidVersion(version string) bool {
	// Basic semver pattern: major.minor.patch
	matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$`, version)
	return matched
}

// isValidCategory checks if category is valid
func (v *Validator) isValidCategory(category string) bool {
	validCategories := map[string]bool{
		"utility":      true,
		"security":     true,
		"analytics":    true,
		"automation":   true,
		"integration":  true,
		"workflow":     true,
		"notification": true,
		"export":       true,
		"import":       true,
		"filter":       true,
		"transform":    true,
	}
	return validCategories[category]
}

// isValidTag checks if tag is valid
func (v *Validator) isValidTag(tag string) bool {
	// Tags should be 2-30 characters, alphanumeric and hyphens
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9-]{2,30}$`, tag)
	return matched
}

// createValidationError creates a structured validation error
func (v *Validator) createValidationError(validationErrors []ValidationError) error {
	result := ValidationResult{
		Valid:  false,
		Errors: validationErrors,
	}

	jsonBytes, _ := json.Marshal(result)
	return errors.New(string(jsonBytes))
}