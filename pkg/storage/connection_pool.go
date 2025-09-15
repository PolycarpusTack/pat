package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	_ "github.com/lib/pq" // PostgreSQL driver
	"go.uber.org/zap"
)

// ConnectionPool provides high-performance database connection pooling
type ConnectionPool struct {
	logger       *zap.Logger
	config       *PoolConfig
	masterDB     *sqlx.DB
	replicaDBs   []*sqlx.DB
	metrics      *PoolMetrics
	healthCheck  *HealthChecker
	shutdown     chan struct{}
	mutex        sync.RWMutex
}

// PoolConfig defines database connection pool configuration
type PoolConfig struct {
	// Master database connection
	MasterDSN string
	
	// Read replica connections
	ReplicaDSNs []string
	
	// Connection pool settings
	MaxOpenConns        int
	MaxIdleConns        int
	ConnMaxLifetime     time.Duration
	ConnMaxIdleTime     time.Duration
	
	// Health check settings
	EnableHealthCheck   bool
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
	
	// Performance settings
	EnableMetrics       bool
	MetricsInterval     time.Duration
	
	// Failover settings
	EnableFailover      bool
	FailoverTimeout     time.Duration
	MaxRetries          int
}

// PoolMetrics tracks connection pool performance
type PoolMetrics struct {
	mutex                  sync.RWMutex
	TotalConnections       int64
	ActiveConnections      int64
	IdleConnections        int64
	ConnectionsCreated     int64
	ConnectionsDestroyed   int64
	QueriesExecuted        int64
	QueryErrors            int64
	AverageQueryTime       time.Duration
	MasterQueries          int64
	ReplicaQueries         int64
	FailoverCount          int64
	LastHealthCheck        time.Time
	HealthyReplicas        int
	TotalReplicas          int
}

// HealthChecker monitors database connection health
type HealthChecker struct {
	pool     *ConnectionPool
	interval time.Duration
	timeout  time.Duration
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// ConnectionType specifies the type of database connection needed
type ConnectionType int

const (
	ConnectionRead ConnectionType = iota
	ConnectionWrite
	ConnectionReadPreferred
)

// NewConnectionPool creates a new high-performance database connection pool
func NewConnectionPool(logger *zap.Logger, config *PoolConfig) (*ConnectionPool, error) {
	if config == nil {
		config = DefaultPoolConfig()
	}
	
	pool := &ConnectionPool{
		logger:      logger,
		config:      config,
		metrics:     &PoolMetrics{},
		shutdown:    make(chan struct{}),
		replicaDBs:  make([]*sqlx.DB, 0, len(config.ReplicaDSNs)),
	}
	
	// Initialize master connection
	if err := pool.initMasterConnection(); err != nil {
		return nil, fmt.Errorf("failed to initialize master connection: %w", err)
	}
	
	// Initialize replica connections
	if err := pool.initReplicaConnections(); err != nil {
		logger.Warn("Failed to initialize some replica connections", zap.Error(err))
	}
	
	// Start health checker if enabled
	if config.EnableHealthCheck {
		pool.healthCheck = &HealthChecker{
			pool:     pool,
			interval: config.HealthCheckInterval,
			timeout:  config.HealthCheckTimeout,
			shutdown: make(chan struct{}),
		}
		go pool.healthCheck.start()
	}
	
	// Start metrics collection if enabled
	if config.EnableMetrics {
		go pool.metricsCollector()
	}
	
	logger.Info("Database connection pool initialized",
		zap.String("master_dsn", maskDSN(config.MasterDSN)),
		zap.Int("replica_count", len(pool.replicaDBs)),
		zap.Int("max_open_conns", config.MaxOpenConns),
		zap.Int("max_idle_conns", config.MaxIdleConns),
	)
	
	return pool, nil
}

// DefaultPoolConfig returns sensible default configuration
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxOpenConns:        25,  // Conservative default for high concurrency
		MaxIdleConns:        10,  // Keep some connections warm
		ConnMaxLifetime:     1 * time.Hour,
		ConnMaxIdleTime:     10 * time.Minute,
		EnableHealthCheck:   true,
		HealthCheckInterval: 30 * time.Second,
		HealthCheckTimeout:  5 * time.Second,
		EnableMetrics:       true,
		MetricsInterval:     60 * time.Second,
		EnableFailover:      true,
		FailoverTimeout:     5 * time.Second,
		MaxRetries:          3,
	}
}

// GetConnection returns a database connection based on the specified type
func (cp *ConnectionPool) GetConnection(ctx context.Context, connType ConnectionType) (*sqlx.DB, error) {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	
	switch connType {
	case ConnectionWrite:
		return cp.getMasterConnection(ctx)
	case ConnectionRead:
		return cp.getReplicaConnection(ctx)
	case ConnectionReadPreferred:
		if db := cp.getHealthyReplicaConnection(ctx); db != nil {
			return db, nil
		}
		// Fallback to master if no healthy replicas
		return cp.getMasterConnection(ctx)
	default:
		return cp.getMasterConnection(ctx)
	}
}

// getMasterConnection returns the master database connection
func (cp *ConnectionPool) getMasterConnection(ctx context.Context) (*sqlx.DB, error) {
	if cp.masterDB == nil {
		return nil, ErrMasterConnectionNotAvailable
	}
	
	// Verify connection is healthy
	if err := cp.masterDB.PingContext(ctx); err != nil {
		cp.logger.Error("Master database connection unhealthy", zap.Error(err))
		
		// Attempt to reconnect if failover is enabled
		if cp.config.EnableFailover {
			if err := cp.reconnectMaster(); err != nil {
				return nil, fmt.Errorf("failed to reconnect to master: %w", err)
			}
		} else {
			return nil, err
		}
	}
	
	cp.updateConnectionMetrics(true, false)
	return cp.masterDB, nil
}

// getReplicaConnection returns a healthy replica connection
func (cp *ConnectionPool) getReplicaConnection(ctx context.Context) (*sqlx.DB, error) {
	if len(cp.replicaDBs) == 0 {
		// No replicas available, fallback to master
		cp.logger.Debug("No replicas available, using master for read")
		return cp.getMasterConnection(ctx)
	}
	
	// Round-robin selection of healthy replicas
	healthyReplicas := cp.getHealthyReplicas(ctx)
	if len(healthyReplicas) == 0 {
		cp.logger.Warn("No healthy replicas available, falling back to master")
		return cp.getMasterConnection(ctx)
	}
	
	// Simple round-robin (could be enhanced with more sophisticated load balancing)
	replica := healthyReplicas[int(cp.metrics.ReplicaQueries)%len(healthyReplicas)]
	
	cp.updateConnectionMetrics(false, true)
	return replica, nil
}

// getHealthyReplicaConnection returns a healthy replica or nil
func (cp *ConnectionPool) getHealthyReplicaConnection(ctx context.Context) *sqlx.DB {
	if db, err := cp.getReplicaConnection(ctx); err == nil {
		return db
	}
	return nil
}

// getHealthyReplicas returns a list of healthy replica connections
func (cp *ConnectionPool) getHealthyReplicas(ctx context.Context) []*sqlx.DB {
	healthy := make([]*sqlx.DB, 0, len(cp.replicaDBs))
	
	for _, replica := range cp.replicaDBs {
		if replica != nil {
			if err := replica.PingContext(ctx); err == nil {
				healthy = append(healthy, replica)
			}
		}
	}
	
	return healthy
}

// initMasterConnection initializes the master database connection
func (cp *ConnectionPool) initMasterConnection() error {
	db, err := sqlx.Connect("postgres", cp.config.MasterDSN)
	if err != nil {
		return fmt.Errorf("failed to connect to master database: %w", err)
	}
	
	// Configure connection pool
	db.SetMaxOpenConns(cp.config.MaxOpenConns)
	db.SetMaxIdleConns(cp.config.MaxIdleConns)
	db.SetConnMaxLifetime(cp.config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cp.config.ConnMaxIdleTime)
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping master database: %w", err)
	}
	
	cp.masterDB = db
	cp.logger.Info("Master database connection established")
	
	return nil
}

// initReplicaConnections initializes replica database connections
func (cp *ConnectionPool) initReplicaConnections() error {
	var lastErr error
	
	for i, dsn := range cp.config.ReplicaDSNs {
		db, err := sqlx.Connect("postgres", dsn)
		if err != nil {
			cp.logger.Warn("Failed to connect to replica",
				zap.Int("replica_index", i),
				zap.String("dsn", maskDSN(dsn)),
				zap.Error(err),
			)
			lastErr = err
			continue
		}
		
		// Configure connection pool
		db.SetMaxOpenConns(cp.config.MaxOpenConns / 2) // Replicas get half the connections
		db.SetMaxIdleConns(cp.config.MaxIdleConns / 2)
		db.SetConnMaxLifetime(cp.config.ConnMaxLifetime)
		db.SetConnMaxIdleTime(cp.config.ConnMaxIdleTime)
		
		// Test connection
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := db.PingContext(ctx); err != nil {
			cp.logger.Warn("Failed to ping replica",
				zap.Int("replica_index", i),
				zap.Error(err),
			)
			db.Close()
			cancel()
			lastErr = err
			continue
		}
		cancel()
		
		cp.replicaDBs = append(cp.replicaDBs, db)
		cp.logger.Info("Replica database connection established",
			zap.Int("replica_index", i),
		)
	}
	
	return lastErr
}

// reconnectMaster attempts to reconnect to the master database
func (cp *ConnectionPool) reconnectMaster() error {
	cp.logger.Info("Attempting to reconnect to master database")
	
	if cp.masterDB != nil {
		cp.masterDB.Close()
	}
	
	if err := cp.initMasterConnection(); err != nil {
		cp.metrics.mutex.Lock()
		cp.metrics.FailoverCount++
		cp.metrics.mutex.Unlock()
		return err
	}
	
	cp.logger.Info("Successfully reconnected to master database")
	return nil
}

// Close gracefully closes all database connections
func (cp *ConnectionPool) Close() error {
	close(cp.shutdown)
	
	if cp.healthCheck != nil {
		close(cp.healthCheck.shutdown)
		cp.healthCheck.wg.Wait()
	}
	
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	
	// Close master connection
	if cp.masterDB != nil {
		if err := cp.masterDB.Close(); err != nil {
			cp.logger.Error("Error closing master connection", zap.Error(err))
		}
	}
	
	// Close replica connections
	for i, replica := range cp.replicaDBs {
		if replica != nil {
			if err := replica.Close(); err != nil {
				cp.logger.Error("Error closing replica connection",
					zap.Int("replica_index", i),
					zap.Error(err),
				)
			}
		}
	}
	
	cp.logger.Info("Database connection pool closed")
	return nil
}

// GetMetrics returns current pool metrics
func (cp *ConnectionPool) GetMetrics() PoolMetrics {
	cp.metrics.mutex.RLock()
	defer cp.metrics.mutex.RUnlock()
	
	metrics := *cp.metrics
	
	// Update live connection stats
	if cp.masterDB != nil {
		stats := cp.masterDB.Stats()
		metrics.ActiveConnections = int64(stats.InUse)
		metrics.IdleConnections = int64(stats.Idle)
		metrics.TotalConnections = int64(stats.OpenConnections)
	}
	
	metrics.TotalReplicas = len(cp.replicaDBs)
	
	return metrics
}

// updateConnectionMetrics updates connection usage metrics
func (cp *ConnectionPool) updateConnectionMetrics(masterUsed, replicaUsed bool) {
	cp.metrics.mutex.Lock()
	defer cp.metrics.mutex.Unlock()
	
	if masterUsed {
		cp.metrics.MasterQueries++
	}
	if replicaUsed {
		cp.metrics.ReplicaQueries++
	}
	cp.metrics.QueriesExecuted++
}

// metricsCollector runs periodic metrics collection
func (cp *ConnectionPool) metricsCollector() {
	ticker := time.NewTicker(cp.config.MetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			metrics := cp.GetMetrics()
			cp.logger.Info("Database connection pool metrics",
				zap.Int64("total_connections", metrics.TotalConnections),
				zap.Int64("active_connections", metrics.ActiveConnections),
				zap.Int64("idle_connections", metrics.IdleConnections),
				zap.Int64("queries_executed", metrics.QueriesExecuted),
				zap.Int64("master_queries", metrics.MasterQueries),
				zap.Int64("replica_queries", metrics.ReplicaQueries),
				zap.Int64("failover_count", metrics.FailoverCount),
				zap.Int("healthy_replicas", metrics.HealthyReplicas),
				zap.Int("total_replicas", metrics.TotalReplicas),
			)
		case <-cp.shutdown:
			return
		}
	}
}

// start begins health checking routine
func (hc *HealthChecker) start() {
	hc.wg.Add(1)
	defer hc.wg.Done()
	
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			hc.performHealthCheck()
		case <-hc.shutdown:
			return
		}
	}
}

// performHealthCheck checks the health of all database connections
func (hc *HealthChecker) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), hc.timeout)
	defer cancel()
	
	hc.pool.logger.Debug("Performing database health check")
	
	// Check master health
	masterHealthy := true
	if hc.pool.masterDB != nil {
		if err := hc.pool.masterDB.PingContext(ctx); err != nil {
			hc.pool.logger.Warn("Master database health check failed", zap.Error(err))
			masterHealthy = false
		}
	}
	
	// Check replica health
	healthyReplicas := 0
	for i, replica := range hc.pool.replicaDBs {
		if replica != nil {
			if err := replica.PingContext(ctx); err != nil {
				hc.pool.logger.Debug("Replica health check failed",
					zap.Int("replica_index", i),
					zap.Error(err),
				)
			} else {
				healthyReplicas++
			}
		}
	}
	
	// Update metrics
	hc.pool.metrics.mutex.Lock()
	hc.pool.metrics.LastHealthCheck = time.Now()
	hc.pool.metrics.HealthyReplicas = healthyReplicas
	hc.pool.metrics.mutex.Unlock()
	
	if !masterHealthy || healthyReplicas == 0 {
		hc.pool.logger.Warn("Database health check completed with issues",
			zap.Bool("master_healthy", masterHealthy),
			zap.Int("healthy_replicas", healthyReplicas),
			zap.Int("total_replicas", len(hc.pool.replicaDBs)),
		)
	}
}

// maskDSN masks sensitive information in database DSN for logging
func maskDSN(dsn string) string {
	// Simple masking - in production, use a more sophisticated approach
	if len(dsn) > 20 {
		return dsn[:10] + "***" + dsn[len(dsn)-7:]
	}
	return "***"
}

// Common errors
var (
	ErrMasterConnectionNotAvailable = fmt.Errorf("master database connection not available")
	ErrNoHealthyConnections         = fmt.Errorf("no healthy database connections available")
)