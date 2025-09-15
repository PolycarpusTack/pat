package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/nacl/secretbox"
)

// SecretsManager provides secure secrets management for Pat Fortress
type SecretsManager struct {
	logger       *zap.Logger
	encryptionKey [32]byte
	secrets      map[string]*EncryptedSecret
	mutex        sync.RWMutex
}

// EncryptedSecret represents an encrypted secret with metadata
type EncryptedSecret struct {
	EncryptedData []byte
	Nonce         [24]byte
	CreatedAt     time.Time
	LastAccessed  time.Time
	AccessCount   int64
}

// SecretConfig defines secret configuration options
type SecretConfig struct {
	TTL           time.Duration
	MaxAccess     int64
	RequireAudit  bool
	Environment   string
}

// NewSecretsManager creates a new secure secrets manager
func NewSecretsManager(logger *zap.Logger) (*SecretsManager, error) {
	sm := &SecretsManager{
		logger:  logger,
		secrets: make(map[string]*EncryptedSecret),
	}

	// Generate or load master encryption key
	if err := sm.initEncryptionKey(); err != nil {
		return nil, fmt.Errorf("failed to initialize encryption key: %w", err)
	}

	logger.Info("SecretsManager initialized with secure encryption")
	return sm, nil
}

// initEncryptionKey initializes the master encryption key
func (sm *SecretsManager) initEncryptionKey() error {
	keyHex := os.Getenv("PAT_MASTER_KEY")
	if keyHex == "" {
		// Generate new key for development
		if _, err := rand.Read(sm.encryptionKey[:]); err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}
		sm.logger.Warn("Generated new master key - store PAT_MASTER_KEY environment variable for production")
		return nil
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid master key format: %w", err)
	}

	if len(keyBytes) != 32 {
		return fmt.Errorf("master key must be 32 bytes, got %d", len(keyBytes))
	}

	copy(sm.encryptionKey[:], keyBytes)
	sm.logger.Info("Master key loaded from environment")
	return nil
}

// StoreSecret encrypts and stores a secret securely
func (sm *SecretsManager) StoreSecret(ctx context.Context, key, value string, config *SecretConfig) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Generate random nonce
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the secret
	encryptedData := secretbox.Seal(nil, []byte(value), &nonce, &sm.encryptionKey)

	// Store encrypted secret
	secret := &EncryptedSecret{
		EncryptedData: encryptedData,
		Nonce:         nonce,
		CreatedAt:     time.Now(),
		LastAccessed:  time.Now(),
		AccessCount:   0,
	}

	sm.secrets[key] = secret

	sm.logger.Info("Secret stored securely", 
		zap.String("key", key),
		zap.String("environment", getEnv(config)),
		zap.Bool("audit_required", getAuditRequired(config)),
	)

	return nil
}

// GetSecret retrieves and decrypts a secret
func (sm *SecretsManager) GetSecret(ctx context.Context, key string) (string, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	secret, exists := sm.secrets[key]
	if !exists {
		// Try to load from environment as fallback
		if envValue := os.Getenv(strings.ToUpper(key)); envValue != "" {
			sm.logger.Warn("Secret loaded from environment - consider using secure storage",
				zap.String("key", key),
			)
			return envValue, nil
		}
		return "", fmt.Errorf("secret not found: %s", key)
	}

	// Decrypt the secret
	decryptedData, ok := secretbox.Open(nil, secret.EncryptedData, &secret.Nonce, &sm.encryptionKey)
	if !ok {
		sm.logger.Error("Failed to decrypt secret", zap.String("key", key))
		return "", fmt.Errorf("failed to decrypt secret: %s", key)
	}

	// Update access metrics
	secret.LastAccessed = time.Now()
	secret.AccessCount++

	sm.logger.Debug("Secret accessed",
		zap.String("key", key),
		zap.Int64("access_count", secret.AccessCount),
	)

	return string(decryptedData), nil
}

// RotateSecret rotates a secret with a new value
func (sm *SecretsManager) RotateSecret(ctx context.Context, key, newValue string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Store the new secret
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	encryptedData := secretbox.Seal(nil, []byte(newValue), &nonce, &sm.encryptionKey)

	secret := &EncryptedSecret{
		EncryptedData: encryptedData,
		Nonce:         nonce,
		CreatedAt:     time.Now(),
		LastAccessed:  time.Now(),
		AccessCount:   0,
	}

	sm.secrets[key] = secret

	sm.logger.Info("Secret rotated successfully", 
		zap.String("key", key),
		zap.Time("rotated_at", time.Now()),
	)

	return nil
}

// DeleteSecret securely removes a secret
func (sm *SecretsManager) DeleteSecret(ctx context.Context, key string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if _, exists := sm.secrets[key]; !exists {
		return fmt.Errorf("secret not found: %s", key)
	}

	// Securely clear the secret data
	secret := sm.secrets[key]
	for i := range secret.EncryptedData {
		secret.EncryptedData[i] = 0
	}
	for i := range secret.Nonce {
		secret.Nonce[i] = 0
	}

	delete(sm.secrets, key)

	sm.logger.Info("Secret deleted securely", zap.String("key", key))
	return nil
}

// ListSecrets returns metadata about stored secrets (not the values)
func (sm *SecretsManager) ListSecrets() []string {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	keys := make([]string, 0, len(sm.secrets))
	for key := range sm.secrets {
		keys = append(keys, key)
	}
	return keys
}

// GetSecretMetadata returns metadata about a secret without decrypting it
func (sm *SecretsManager) GetSecretMetadata(key string) (*SecretMetadata, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	secret, exists := sm.secrets[key]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	return &SecretMetadata{
		Key:          key,
		CreatedAt:    secret.CreatedAt,
		LastAccessed: secret.LastAccessed,
		AccessCount:  secret.AccessCount,
	}, nil
}

// SecretMetadata contains non-sensitive metadata about secrets
type SecretMetadata struct {
	Key          string    `json:"key"`
	CreatedAt    time.Time `json:"created_at"`
	LastAccessed time.Time `json:"last_accessed"`
	AccessCount  int64     `json:"access_count"`
}

// Helper functions
func getEnv(config *SecretConfig) string {
	if config != nil && config.Environment != "" {
		return config.Environment
	}
	return "production"
}

func getAuditRequired(config *SecretConfig) bool {
	if config != nil {
		return config.RequireAudit
	}
	return true
}

// GenerateMasterKey generates a new master key for the secrets manager
func GenerateMasterKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate master key: %w", err)
	}
	return hex.EncodeToString(key), nil
}