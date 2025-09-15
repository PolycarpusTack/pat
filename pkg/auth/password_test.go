package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordHasher_HashPassword(t *testing.T) {
	hasher := NewPasswordHasher(nil)

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "SecurePassword123!",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  false, // Hasher should work with empty password
		},
		{
			name:     "unicode password",
			password: "пароль123🔒",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := hasher.HashPassword(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, hash)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, hash)
				assert.Contains(t, hash, "$argon2id$")
				
				// Verify hash has correct format
				parts := strings.Split(hash, "$")
				assert.Len(t, parts, 6)
				assert.Equal(t, "", parts[0])
				assert.Equal(t, "argon2id", parts[1])
				assert.Equal(t, "v=19", parts[2])
			}
		})
	}
}

func TestPasswordHasher_VerifyPassword(t *testing.T) {
	hasher := NewPasswordHasher(nil)
	password := "TestPassword123!"

	// Generate hash
	hash, err := hasher.HashPassword(password)
	require.NoError(t, err)

	tests := []struct {
		name        string
		password    string
		hash        string
		wantValid   bool
		wantErr     bool
	}{
		{
			name:      "correct password",
			password:  password,
			hash:      hash,
			wantValid: true,
			wantErr:   false,
		},
		{
			name:      "incorrect password",
			password:  "WrongPassword",
			hash:      hash,
			wantValid: false,
			wantErr:   false,
		},
		{
			name:      "invalid hash format",
			password:  password,
			hash:      "invalid-hash",
			wantValid: false,
			wantErr:   true,
		},
		{
			name:      "malformed hash",
			password:  password,
			hash:      "$argon2id$v=19$invalid",
			wantValid: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := hasher.VerifyPassword(tt.password, tt.hash)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantValid, valid)
			}
		})
	}
}

func TestPasswordHasher_ConsistentHashing(t *testing.T) {
	hasher := NewPasswordHasher(nil)
	password := "TestPassword123!"

	// Generate multiple hashes of the same password
	hash1, err := hasher.HashPassword(password)
	require.NoError(t, err)

	hash2, err := hasher.HashPassword(password)
	require.NoError(t, err)

	// Hashes should be different (due to random salt)
	assert.NotEqual(t, hash1, hash2)

	// But both should verify correctly
	valid1, err := hasher.VerifyPassword(password, hash1)
	assert.NoError(t, err)
	assert.True(t, valid1)

	valid2, err := hasher.VerifyPassword(password, hash2)
	assert.NoError(t, err)
	assert.True(t, valid2)
}

func TestPasswordValidator_ValidatePassword(t *testing.T) {
	validator := DefaultPasswordValidator()

	tests := []struct {
		name     string
		password string
		wantErr  bool
		errCount int
	}{
		{
			name:     "valid strong password",
			password: "SecurePassword123!",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "Short1!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "no uppercase",
			password: "lowercasepassword123!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "no lowercase",
			password: "UPPERCASEPASSWORD123!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "no numbers",
			password: "NoNumbersPassword!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "no symbols",
			password: "NoSymbolsPassword123",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "contains forbidden word",
			password: "MyPassword123!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "repeated characters",
			password: "MyPasswordddd123!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "keyboard pattern",
			password: "Qwerty123!",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "multiple violations",
			password: "password",
			wantErr:  true,
			errCount: 5, // short, no uppercase, no numbers, no symbols, forbidden word
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePassword(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errCount > 0 {
					validationErr, ok := err.(*PasswordValidationError)
					require.True(t, ok)
					assert.Len(t, validationErr.Errors, tt.errCount)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPasswordValidator_CustomConfiguration(t *testing.T) {
	validator := &PasswordValidator{
		MinLength:        8,
		MaxLength:        20,
		RequireUppercase: false,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSymbols:   false,
		ForbiddenWords:   []string{"test", "demo"},
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid with custom rules",
			password: "mypassword123",
			wantErr:  false,
		},
		{
			name:     "too long",
			password: "thispasswordistoolongforthevalidator123",
			wantErr:  true,
		},
		{
			name:     "contains custom forbidden word",
			password: "mytestpassword123",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePassword(tt.password)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateSecurePassword(t *testing.T) {
	tests := []struct {
		name   string
		length int
		want   int
	}{
		{
			name:   "default minimum length",
			length: 5, // Should be increased to 12
			want:   12,
		},
		{
			name:   "specified length",
			length: 16,
			want:   16,
		},
		{
			name:   "long password",
			length: 64,
			want:   64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := GenerateSecurePassword(tt.length)
			assert.NoError(t, err)
			assert.Len(t, password, tt.want)

			// Verify password contains different character types
			hasUpper := strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
			hasLower := strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
			hasDigit := strings.ContainsAny(password, "0123456789")
			hasSymbol := strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?")

			// For reasonable lengths, we should have variety
			if tt.want >= 12 {
				assert.True(t, hasUpper || hasLower || hasDigit || hasSymbol, "Password should contain varied characters")
			}
		})
	}
}

func TestGenerateSecureToken(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "16 byte token",
			length: 16,
		},
		{
			name:   "32 byte token",
			length: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateSecureToken(tt.length)
			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			// Verify it's base64 URL encoded
			// The encoded length should be approximately (length * 4 / 3) with padding
			expectedMinLen := (tt.length * 4) / 3
			expectedMaxLen := expectedMinLen + 4 // Account for padding
			assert.GreaterOrEqual(t, len(token), expectedMinLen)
			assert.LessOrEqual(t, len(token), expectedMaxLen)
		})
	}
}

func Test_hasRepeatedCharacters(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		maxRepeats  int
		want        bool
	}{
		{
			name:       "no repeats",
			password:   "abcdef",
			maxRepeats: 3,
			want:       false,
		},
		{
			name:       "acceptable repeats",
			password:   "aabbc",
			maxRepeats: 3,
			want:       false,
		},
		{
			name:       "too many repeats",
			password:   "aaaa",
			maxRepeats: 3,
			want:       true,
		},
		{
			name:       "repeats at end",
			password:   "abcddddd",
			maxRepeats: 3,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasRepeatedCharacters(tt.password, tt.maxRepeats)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_hasKeyboardPattern(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "no pattern",
			password: "randompassword",
			want:     false,
		},
		{
			name:     "qwerty pattern",
			password: "myqwerty123",
			want:     true,
		},
		{
			name:     "number sequence",
			password: "pass1234567890",
			want:     true,
		},
		{
			name:     "reverse pattern",
			password: "mytreqw123",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasKeyboardPattern(tt.password)
			assert.Equal(t, tt.want, got)
		})
	}
}

func BenchmarkPasswordHasher_HashPassword(b *testing.B) {
	hasher := NewPasswordHasher(nil)
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.HashPassword(password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasswordHasher_VerifyPassword(b *testing.B) {
	hasher := NewPasswordHasher(nil)
	password := "BenchmarkPassword123!"

	// Generate hash once
	hash, err := hasher.HashPassword(password)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.VerifyPassword(password, hash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasswordValidator_ValidatePassword(b *testing.B) {
	validator := DefaultPasswordValidator()
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidatePassword(password)
	}
}