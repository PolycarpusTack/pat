package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PasswordConfig holds configuration for password hashing
type PasswordConfig struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultPasswordConfig returns a secure default configuration
func DefaultPasswordConfig() *PasswordConfig {
	return &PasswordConfig{
		Memory:      64 * 1024, // 64 MB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// PasswordHasher handles password hashing and verification
type PasswordHasher struct {
	config *PasswordConfig
}

// NewPasswordHasher creates a new password hasher
func NewPasswordHasher(config *PasswordConfig) *PasswordHasher {
	if config == nil {
		config = DefaultPasswordConfig()
	}
	return &PasswordHasher{config: config}
}

// HashPassword creates a hash of the password using Argon2id
func (ph *PasswordHasher) HashPassword(password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, ph.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash the password
	hash := argon2.IDKey([]byte(password), salt, ph.config.Iterations, ph.config.Memory, ph.config.Parallelism, ph.config.KeyLength)

	// Encode the hash using base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		ph.config.Memory, ph.config.Iterations, ph.config.Parallelism, b64Salt, b64Hash), nil
}

// VerifyPassword verifies a password against a hash
func (ph *PasswordHasher) VerifyPassword(password, hash string) (bool, error) {
	// Parse the hash
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, fmt.Errorf("invalid hash format")
	}

	// Parse parameters
	var memory, iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, fmt.Errorf("failed to parse hash parameters: %w", err)
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Hash the provided password with the same parameters
	actualHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))

	// Compare hashes using constant-time comparison
	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1, nil
}

// PasswordValidator validates password strength
type PasswordValidator struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSymbols   bool
	ForbiddenWords   []string
}

// DefaultPasswordValidator returns a validator with secure defaults
func DefaultPasswordValidator() *PasswordValidator {
	return &PasswordValidator{
		MinLength:        12,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSymbols:   true,
		ForbiddenWords:   []string{"password", "123456", "qwerty", "admin", "test", "email"},
	}
}

// PasswordValidationError represents password validation errors
type PasswordValidationError struct {
	Errors []string
}

func (e *PasswordValidationError) Error() string {
	return strings.Join(e.Errors, "; ")
}

// ValidatePassword validates a password against the configured rules
func (pv *PasswordValidator) ValidatePassword(password string) error {
	var errors []string

	// Length check
	if len(password) < pv.MinLength {
		errors = append(errors, fmt.Sprintf("password must be at least %d characters long", pv.MinLength))
	}
	if len(password) > pv.MaxLength {
		errors = append(errors, fmt.Sprintf("password must be no more than %d characters long", pv.MaxLength))
	}

	// Character requirements
	if pv.RequireUppercase {
		if matched, _ := regexp.MatchString(`[A-Z]`, password); !matched {
			errors = append(errors, "password must contain at least one uppercase letter")
		}
	}

	if pv.RequireLowercase {
		if matched, _ := regexp.MatchString(`[a-z]`, password); !matched {
			errors = append(errors, "password must contain at least one lowercase letter")
		}
	}

	if pv.RequireNumbers {
		if matched, _ := regexp.MatchString(`[0-9]`, password); !matched {
			errors = append(errors, "password must contain at least one number")
		}
	}

	if pv.RequireSymbols {
		if matched, _ := regexp.MatchString(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]`, password); !matched {
			errors = append(errors, "password must contain at least one symbol")
		}
	}

	// Forbidden words check
	passwordLower := strings.ToLower(password)
	for _, word := range pv.ForbiddenWords {
		if strings.Contains(passwordLower, strings.ToLower(word)) {
			errors = append(errors, fmt.Sprintf("password must not contain common word: %s", word))
		}
	}

	// Check for repeated characters
	if hasRepeatedCharacters(password, 3) {
		errors = append(errors, "password must not contain more than 3 consecutive identical characters")
	}

	// Check for keyboard patterns
	if hasKeyboardPattern(password) {
		errors = append(errors, "password must not contain keyboard patterns")
	}

	if len(errors) > 0 {
		return &PasswordValidationError{Errors: errors}
	}

	return nil
}

// hasRepeatedCharacters checks if password has too many repeated characters
func hasRepeatedCharacters(password string, maxRepeats int) bool {
	if len(password) < maxRepeats {
		return false
	}

	for i := 0; i <= len(password)-maxRepeats; i++ {
		char := password[i]
		count := 1
		for j := i + 1; j < len(password) && password[j] == char; j++ {
			count++
			if count > maxRepeats {
				return true
			}
		}
	}
	return false
}

// hasKeyboardPattern checks for common keyboard patterns
func hasKeyboardPattern(password string) bool {
	patterns := []string{
		"qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
		"1234567890", "0987654321", "abcdefg", "zyxwvu",
	}

	passwordLower := strings.ToLower(password)
	for _, pattern := range patterns {
		if strings.Contains(passwordLower, pattern) || strings.Contains(passwordLower, reverse(pattern)) {
			return true
		}
	}
	return false
}

// reverse reverses a string
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// GenerateSecurePassword generates a cryptographically secure random password
func GenerateSecurePassword(length int) (string, error) {
	if length < 8 {
		length = 12 // Minimum secure length
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	
	password := make([]byte, length)
	for i := range password {
		randomByte := make([]byte, 1)
		if _, err := rand.Read(randomByte); err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}
		password[i] = charset[int(randomByte[0])%len(charset)]
	}

	return string(password), nil
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}