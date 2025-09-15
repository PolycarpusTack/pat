package foundation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"go.uber.org/zap"
)

// FoundationService implements the Foundation interface - fortress database and storage systems
type FoundationService struct {
	config *interfaces.DatabaseConfig
	logger *zap.Logger

	// Database components
	database     *DatabaseManager
	cache        *CacheManager
	fileStorage  *FileStorageManager
	backupMgr    *BackupManager

	// Connection state
	mu        sync.RWMutex
	connected bool
	started   bool

	// Transaction management
	activeTransactions map[string]*TransactionImpl
	txMu              sync.RWMutex
}

// NewFoundationService creates a new Foundation service instance
func NewFoundationService(ctx context.Context, config *interfaces.DatabaseConfig, logger *zap.Logger) (*FoundationService, error) {
	if config == nil {
		return nil, fmt.Errorf("database config cannot be nil")
	}

	service := &FoundationService{
		config:             config,
		logger:             logger.Named("foundation"),
		activeTransactions: make(map[string]*TransactionImpl),
	}

	// Initialize components
	if err := service.initializeComponents(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	logger.Info("Foundation service created successfully")
	return service, nil
}

// Connect establishes connection to the database
func (f *FoundationService) Connect(ctx context.Context, config *interfaces.DatabaseConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.connected {
		return fmt.Errorf("foundation already connected")
	}

	if config != nil {
		f.config = config
	}

	f.logger.Info("Connecting to database", 
		zap.String("driver", f.config.Driver),
		zap.String("dsn", maskSensitiveInfo(f.config.DSN)))

	// Connect to database
	if err := f.database.Connect(ctx, f.config); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Initialize cache
	if err := f.cache.Connect(ctx); err != nil {
		f.logger.Warn("Failed to connect to cache", zap.Error(err))
		// Cache connection failure is not fatal
	}

	// Initialize file storage
	if err := f.fileStorage.Initialize(ctx); err != nil {
		f.logger.Warn("Failed to initialize file storage", zap.Error(err))
		// File storage failure is not fatal
	}

	f.connected = true
	f.logger.Info("Foundation connected successfully")

	return nil
}

// Disconnect closes the database connection
func (f *FoundationService) Disconnect(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.connected {
		return nil
	}

	f.logger.Info("Disconnecting from database")

	// Close active transactions
	f.txMu.Lock()
	for txID, tx := range f.activeTransactions {
		if err := tx.Rollback(); err != nil {
			f.logger.Warn("Failed to rollback active transaction", 
				zap.String("tx_id", txID), 
				zap.Error(err))
		}
	}
	f.activeTransactions = make(map[string]*TransactionImpl)
	f.txMu.Unlock()

	// Disconnect components
	if f.database != nil {
		if err := f.database.Disconnect(ctx); err != nil {
			f.logger.Error("Failed to disconnect database", zap.Error(err))
		}
	}

	if f.cache != nil {
		if err := f.cache.Disconnect(ctx); err != nil {
			f.logger.Error("Failed to disconnect cache", zap.Error(err))
		}
	}

	if f.fileStorage != nil {
		if err := f.fileStorage.Close(ctx); err != nil {
			f.logger.Error("Failed to close file storage", zap.Error(err))
		}
	}

	f.connected = false
	f.logger.Info("Foundation disconnected")

	return nil
}

// Migrate runs database migrations
func (f *FoundationService) Migrate(ctx context.Context, version string) error {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.connected {
		return fmt.Errorf("foundation not connected")
	}

	f.logger.Info("Running database migration", zap.String("version", version))

	if err := f.database.Migrate(ctx, version, f.config.MigrationsPath); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	f.logger.Info("Database migration completed successfully", zap.String("version", version))
	return nil
}

// Query executes a query and returns results
func (f *FoundationService) Query(ctx context.Context, query string, args ...interface{}) (*interfaces.QueryResult, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.connected {
		return nil, fmt.Errorf("foundation not connected")
	}

	f.logger.Debug("Executing query", 
		zap.String("query", query),
		zap.Int("args_count", len(args)))

	startTime := time.Now()

	result, err := f.database.Query(ctx, query, args...)
	if err != nil {
		f.logger.Error("Query failed", 
			zap.String("query", query),
			zap.Error(err))
		return nil, fmt.Errorf("query execution failed: %w", err)
	}

	duration := time.Since(startTime)
	result.Duration = duration

	f.logger.Debug("Query completed", 
		zap.Duration("duration", duration),
		zap.Int64("rows", result.Count))

	return result, nil
}

// QueryOne executes a query and returns a single result
func (f *FoundationService) QueryOne(ctx context.Context, query string, args ...interface{}) (map[string]interface{}, error) {
	result, err := f.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	if len(result.Rows) == 0 {
		return nil, nil
	}

	return result.Rows[0], nil
}

// Exec executes a statement without returning results
func (f *FoundationService) Exec(ctx context.Context, query string, args ...interface{}) error {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.connected {
		return fmt.Errorf("foundation not connected")
	}

	f.logger.Debug("Executing statement", 
		zap.String("query", query),
		zap.Int("args_count", len(args)))

	startTime := time.Now()

	err := f.database.Exec(ctx, query, args...)
	if err != nil {
		f.logger.Error("Statement execution failed", 
			zap.String("query", query),
			zap.Error(err))
		return fmt.Errorf("statement execution failed: %w", err)
	}

	duration := time.Since(startTime)
	f.logger.Debug("Statement completed", zap.Duration("duration", duration))

	return nil
}

// BeginTransaction starts a new transaction
func (f *FoundationService) BeginTransaction(ctx context.Context) (interfaces.Transaction, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.connected {
		return nil, fmt.Errorf("foundation not connected")
	}

	f.logger.Debug("Beginning transaction")

	// Create database transaction
	dbTx, err := f.database.BeginTransaction(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin database transaction: %w", err)
	}

	// Create transaction wrapper
	tx := &TransactionImpl{
		ID:         f.generateTransactionID(),
		dbTx:       dbTx,
		foundation: f,
		logger:     f.logger.Named("tx"),
		startTime:  time.Now(),
	}

	// Register transaction
	f.txMu.Lock()
	f.activeTransactions[tx.ID] = tx
	f.txMu.Unlock()

	f.logger.Debug("Transaction started", zap.String("tx_id", tx.ID))

	return tx, nil
}

// Transaction executes a function within a transaction
func (f *FoundationService) Transaction(ctx context.Context, fn func(tx interfaces.Transaction) error) error {
	tx, err := f.BeginTransaction(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			f.logger.Error("Failed to rollback transaction", zap.Error(rbErr))
		}
		return err
	}

	return tx.Commit()
}

// Cache operations

// CacheGet retrieves a value from cache
func (f *FoundationService) CacheGet(ctx context.Context, key string) (interface{}, error) {
	if f.cache == nil {
		return nil, fmt.Errorf("cache not available")
	}

	return f.cache.Get(ctx, key)
}

// CacheSet stores a value in cache
func (f *FoundationService) CacheSet(ctx context.Context, key string, value interface{}, ttl *time.Duration) error {
	if f.cache == nil {
		return fmt.Errorf("cache not available")
	}

	return f.cache.Set(ctx, key, value, ttl)
}

// CacheDelete removes a value from cache
func (f *FoundationService) CacheDelete(ctx context.Context, key string) error {
	if f.cache == nil {
		return fmt.Errorf("cache not available")
	}

	return f.cache.Delete(ctx, key)
}

// CacheClear removes values matching pattern from cache
func (f *FoundationService) CacheClear(ctx context.Context, pattern string) error {
	if f.cache == nil {
		return fmt.Errorf("cache not available")
	}

	return f.cache.Clear(ctx, pattern)
}

// File storage operations

// StoreFile stores a file
func (f *FoundationService) StoreFile(ctx context.Context, path string, data []byte) error {
	if f.fileStorage == nil {
		return fmt.Errorf("file storage not available")
	}

	return f.fileStorage.StoreFile(ctx, path, data)
}

// RetrieveFile retrieves a file
func (f *FoundationService) RetrieveFile(ctx context.Context, path string) ([]byte, error) {
	if f.fileStorage == nil {
		return nil, fmt.Errorf("file storage not available")
	}

	return f.fileStorage.RetrieveFile(ctx, path)
}

// DeleteFile deletes a file
func (f *FoundationService) DeleteFile(ctx context.Context, path string) error {
	if f.fileStorage == nil {
		return fmt.Errorf("file storage not available")
	}

	return f.fileStorage.DeleteFile(ctx, path)
}

// ListFiles lists files matching pattern
func (f *FoundationService) ListFiles(ctx context.Context, pattern string) ([]string, error) {
	if f.fileStorage == nil {
		return nil, fmt.Errorf("file storage not available")
	}

	return f.fileStorage.ListFiles(ctx, pattern)
}

// Backup and recovery operations

// CreateBackup creates a database backup
func (f *FoundationService) CreateBackup(ctx context.Context, config *interfaces.BackupConfig) error {
	if f.backupMgr == nil {
		return fmt.Errorf("backup manager not available")
	}

	f.logger.Info("Creating backup", 
		zap.String("type", config.Type),
		zap.String("destination", config.Destination))

	return f.backupMgr.CreateBackup(ctx, config)
}

// RestoreBackup restores from a backup
func (f *FoundationService) RestoreBackup(ctx context.Context, backupID string) error {
	if f.backupMgr == nil {
		return fmt.Errorf("backup manager not available")
	}

	f.logger.Info("Restoring backup", zap.String("backup_id", backupID))

	return f.backupMgr.RestoreBackup(ctx, backupID)
}

// ListBackups lists available backups
func (f *FoundationService) ListBackups(ctx context.Context) ([]*interfaces.BackupInfo, error) {
	if f.backupMgr == nil {
		return nil, fmt.Errorf("backup manager not available")
	}

	return f.backupMgr.ListBackups(ctx)
}

// Service lifecycle methods

// Start starts the Foundation service
func (f *FoundationService) Start(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.started {
		return fmt.Errorf("foundation service already started")
	}

	f.logger.Info("Starting Foundation service")

	// Auto-connect if not connected
	if !f.connected {
		if err := f.Connect(ctx, f.config); err != nil {
			return fmt.Errorf("failed to connect during startup: %w", err)
		}
	}

	// Run initial migration if configured
	if f.config.MigrationsPath != "" {
		if err := f.Migrate(ctx, "latest"); err != nil {
			f.logger.Warn("Migration failed during startup", zap.Error(err))
			// Migration failure is not fatal for startup
		}
	}

	f.started = true
	f.logger.Info("Foundation service started successfully")

	return nil
}

// Stop stops the Foundation service
func (f *FoundationService) Stop(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.started {
		return nil
	}

	f.logger.Info("Stopping Foundation service")

	// Disconnect from database
	if err := f.Disconnect(ctx); err != nil {
		f.logger.Error("Error during disconnect", zap.Error(err))
	}

	f.started = false
	f.logger.Info("Foundation service stopped")

	return nil
}

// Health returns the health status of the Foundation service
func (f *FoundationService) Health(ctx context.Context) *interfaces.HealthStatus {
	f.mu.RLock()
	defer f.mu.RUnlock()

	status := &interfaces.HealthStatus{
		Service:   "foundation",
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	if !f.connected {
		status.Status = interfaces.HealthStatusUnhealthy
		status.Message = "Not connected to database"
		return status
	}

	// Test database connectivity
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := f.QueryOne(testCtx, "SELECT 1 as test")
	if err != nil {
		status.Status = interfaces.HealthStatusUnhealthy
		status.Message = fmt.Sprintf("Database connectivity test failed: %v", err)
		return status
	}

	// Check component health
	components := make(map[string]string)
	components["database"] = "healthy"

	if f.cache != nil {
		if f.cache.Health(ctx) {
			components["cache"] = "healthy"
		} else {
			components["cache"] = "degraded"
			status.Status = interfaces.HealthStatusDegraded
		}
	}

	if f.fileStorage != nil {
		if f.fileStorage.Health(ctx) {
			components["file_storage"] = "healthy"
		} else {
			components["file_storage"] = "degraded"
			status.Status = interfaces.HealthStatusDegraded
		}
	}

	// Add statistics
	f.txMu.RLock()
	activeTxCount := len(f.activeTransactions)
	f.txMu.RUnlock()

	status.Details["components"] = components
	status.Details["active_transactions"] = activeTxCount
	status.Details["driver"] = f.config.Driver

	if status.Status == "" {
		status.Status = interfaces.HealthStatusHealthy
		status.Message = "All foundation systems operational"
	}

	return status
}

// Private helper methods

func (f *FoundationService) initializeComponents(ctx context.Context) error {
	var err error

	// Initialize database manager
	f.database, err = NewDatabaseManager(f.logger)
	if err != nil {
		return fmt.Errorf("failed to create database manager: %w", err)
	}

	// Initialize cache manager
	f.cache, err = NewCacheManager(f.logger)
	if err != nil {
		return fmt.Errorf("failed to create cache manager: %w", err)
	}

	// Initialize file storage manager
	f.fileStorage, err = NewFileStorageManager(f.logger)
	if err != nil {
		return fmt.Errorf("failed to create file storage manager: %w", err)
	}

	// Initialize backup manager
	f.backupMgr, err = NewBackupManager(f.database, f.logger)
	if err != nil {
		return fmt.Errorf("failed to create backup manager: %w", err)
	}

	return nil
}

func (f *FoundationService) generateTransactionID() string {
	return fmt.Sprintf("tx_%d_%d", time.Now().Unix(), time.Now().Nanosecond())
}

func (f *FoundationService) unregisterTransaction(txID string) {
	f.txMu.Lock()
	defer f.txMu.Unlock()
	delete(f.activeTransactions, txID)
}

// Helper functions

func maskSensitiveInfo(dsn string) string {
	// Simple masking - in production would use proper DSN parsing
	if len(dsn) > 20 {
		return dsn[:10] + "***" + dsn[len(dsn)-7:]
	}
	return "***"
}

// TransactionImpl implements the Transaction interface
type TransactionImpl struct {
	ID         string
	dbTx       DatabaseTransaction
	foundation *FoundationService
	logger     *zap.Logger
	startTime  time.Time
	completed  bool
}

// Commit commits the transaction
func (t *TransactionImpl) Commit() error {
	if t.completed {
		return fmt.Errorf("transaction already completed")
	}

	t.logger.Debug("Committing transaction", zap.String("tx_id", t.ID))

	err := t.dbTx.Commit()
	t.completed = true

	// Unregister transaction
	t.foundation.unregisterTransaction(t.ID)

	duration := time.Since(t.startTime)
	
	if err != nil {
		t.logger.Error("Transaction commit failed", 
			zap.String("tx_id", t.ID),
			zap.Error(err))
		return fmt.Errorf("commit failed: %w", err)
	}

	t.logger.Debug("Transaction committed", 
		zap.String("tx_id", t.ID),
		zap.Duration("duration", duration))

	return nil
}

// Rollback rolls back the transaction
func (t *TransactionImpl) Rollback() error {
	if t.completed {
		return fmt.Errorf("transaction already completed")
	}

	t.logger.Debug("Rolling back transaction", zap.String("tx_id", t.ID))

	err := t.dbTx.Rollback()
	t.completed = true

	// Unregister transaction
	t.foundation.unregisterTransaction(t.ID)

	duration := time.Since(t.startTime)

	if err != nil {
		t.logger.Error("Transaction rollback failed", 
			zap.String("tx_id", t.ID),
			zap.Error(err))
		return fmt.Errorf("rollback failed: %w", err)
	}

	t.logger.Debug("Transaction rolled back", 
		zap.String("tx_id", t.ID),
		zap.Duration("duration", duration))

	return nil
}

// Query executes a query within the transaction
func (t *TransactionImpl) Query(query string, args ...interface{}) (*interfaces.QueryResult, error) {
	if t.completed {
		return nil, fmt.Errorf("transaction completed")
	}

	return t.dbTx.Query(query, args...)
}

// Exec executes a statement within the transaction
func (t *TransactionImpl) Exec(query string, args ...interface{}) error {
	if t.completed {
		return fmt.Errorf("transaction completed")
	}

	return t.dbTx.Exec(query, args...)
}