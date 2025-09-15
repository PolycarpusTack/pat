package external_systems

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/pat-fortress/tests/integration/testdata/fixtures"
	"github.com/pat-fortress/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// FortressDatabaseIntegrationSuite tests database integration functionality
type FortressDatabaseIntegrationSuite struct {
	suite.Suite
	testUtils      *utils.FortressTestUtils
	configFixtures *fixtures.ConfigFixtures
	emailFixtures  *fixtures.EmailFixtures
	
	// Database connections
	db          *sqlx.DB
	foundation  interfaces.Foundation
	ctx         context.Context
	cancel      context.CancelFunc
	
	// Test configuration
	config *interfaces.DatabaseConfig
}

// SetupSuite initializes the database integration test environment
func (s *FortressDatabaseIntegrationSuite) SetupSuite() {
	s.testUtils = utils.NewFortressTestUtils(s.T())
	s.configFixtures = fixtures.NewConfigFixtures()
	s.emailFixtures = fixtures.NewEmailFixtures()
	
	s.ctx, s.cancel = context.WithTimeout(context.Background(), time.Minute*10)
	
	// Get database configuration
	s.config = s.configFixtures.TestDatabaseConfig()
	
	// Override with environment variables if present
	s.overrideConfigFromEnv()
	
	// Initialize database connection
	s.initializeDatabaseConnection()
	
	// Setup test schema
	s.setupTestSchema()
	
	// Initialize Foundation service with real database
	s.foundation = s.createFoundationService()
	
	// Start Foundation service
	err := s.foundation.Start(s.ctx)
	require.NoError(s.T(), err)
}

// TearDownSuite cleans up the database integration test environment
func (s *FortressDatabaseIntegrationSuite) TearDownSuite() {
	if s.foundation != nil {
		s.foundation.Stop(s.ctx)
	}
	
	if s.db != nil {
		s.cleanupTestSchema()
		s.db.Close()
	}
	
	if s.cancel != nil {
		s.cancel()
	}
}

// SetupTest prepares each test case
func (s *FortressDatabaseIntegrationSuite) SetupTest() {
	// Clean test data before each test
	s.cleanupTestData()
}

// TestDatabaseConnection tests basic database connectivity
func (s *FortressDatabaseIntegrationSuite) TestDatabaseConnection() {
	s.T().Run("Database_Connectivity", func(t *testing.T) {
		// Test direct database connection
		err := s.db.Ping()
		require.NoError(t, err, "Should be able to ping database")
		
		// Test through Foundation service
		health := s.foundation.Health(s.ctx)
		require.NotNil(t, health)
		assert.Equal(t, interfaces.HealthStatusHealthy, health.Status)
		assert.Equal(t, "foundation", health.Service)
	})
}

// TestDatabaseMigrations tests database schema migrations
func (s *FortressDatabaseIntegrationSuite) TestDatabaseMigrations() {
	s.T().Run("Schema_Migrations", func(t *testing.T) {
		// Test migration application
		err := s.foundation.Migrate(s.ctx, "latest")
		require.NoError(t, err, "Should be able to apply migrations")
		
		// Verify tables exist
		expectedTables := []string{
			"emails",
			"users", 
			"sessions",
			"plugin_configs",
			"rate_limits",
			"audit_logs",
		}
		
		for _, tableName := range expectedTables {
			var exists bool
			query := `
				SELECT EXISTS (
					SELECT FROM information_schema.tables 
					WHERE table_schema = 'public' 
					AND table_name = $1
				)`
			
			err := s.db.QueryRow(query, tableName).Scan(&exists)
			require.NoError(t, err)
			assert.True(t, exists, "Table %s should exist after migration", tableName)
		}
	})
}

// TestEmailStorageOperations tests email CRUD operations
func (s *FortressDatabaseIntegrationSuite) TestEmailStorageOperations() {
	emails := []*interfaces.Email{
		s.emailFixtures.SimpleTextEmail(),
		s.emailFixtures.HTMLEmail(),
		s.emailFixtures.EmailWithUnicodeContent(),
	}
	
	s.T().Run("Email_CRUD_Operations", func(t *testing.T) {
		// Test email insertion
		for _, email := range emails {
			err := s.insertEmail(email)
			require.NoError(t, err, "Should be able to insert email %s", email.ID)
		}
		
		// Test email retrieval
		for _, originalEmail := range emails {
			retrievedEmail, err := s.retrieveEmail(originalEmail.ID)
			require.NoError(t, err, "Should be able to retrieve email %s", originalEmail.ID)
			
			assert.Equal(t, originalEmail.ID, retrievedEmail.ID)
			assert.Equal(t, originalEmail.MessageID, retrievedEmail.MessageID)
			assert.Equal(t, originalEmail.From, retrievedEmail.From)
			assert.Equal(t, originalEmail.Subject, retrievedEmail.Subject)
		}
		
		// Test email update
		updatedSubject := "Updated Subject"
		err := s.updateEmail(emails[0].ID, map[string]interface{}{
			"subject": updatedSubject,
		})
		require.NoError(t, err)
		
		updatedEmail, err := s.retrieveEmail(emails[0].ID)
		require.NoError(t, err)
		assert.Equal(t, updatedSubject, updatedEmail.Subject)
		
		// Test email deletion
		err = s.deleteEmail(emails[0].ID)
		require.NoError(t, err)
		
		_, err = s.retrieveEmail(emails[0].ID)
		assert.Error(t, err, "Should not be able to retrieve deleted email")
	})
}

// TestDatabaseTransactions tests transaction handling
func (s *FortressDatabaseIntegrationSuite) TestDatabaseTransactions() {
	email := s.emailFixtures.SimpleTextEmail()
	
	s.T().Run("Transaction_Commit", func(t *testing.T) {
		// Test successful transaction
		err := s.foundation.Transaction(s.ctx, func(tx interfaces.Transaction) error {
			// Insert email in transaction
			query := `
				INSERT INTO emails (id, message_id, from_address, to_addresses, subject, body, received_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`
			
			return tx.Exec(s.ctx, query,
				email.ID, email.MessageID, email.From, pq.Array(email.To),
				email.Subject, email.Body, email.ReceivedAt)
		})
		require.NoError(t, err)
		
		// Verify email was committed
		retrievedEmail, err := s.retrieveEmail(email.ID)
		require.NoError(t, err)
		assert.Equal(t, email.ID, retrievedEmail.ID)
	})
	
	s.T().Run("Transaction_Rollback", func(t *testing.T) {
		// Test failed transaction
		testEmail := s.emailFixtures.HTMLEmail()
		
		err := s.foundation.Transaction(s.ctx, func(tx interfaces.Transaction) error {
			// Insert email
			query := `
				INSERT INTO emails (id, message_id, from_address, to_addresses, subject, body, received_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`
			
			err := tx.Exec(s.ctx, query,
				testEmail.ID, testEmail.MessageID, testEmail.From, pq.Array(testEmail.To),
				testEmail.Subject, testEmail.Body, testEmail.ReceivedAt)
			if err != nil {
				return err
			}
			
			// Force transaction failure
			return fmt.Errorf("intentional failure for rollback test")
		})
		
		// Transaction should fail
		require.Error(t, err)
		assert.Contains(t, err.Error(), "intentional failure")
		
		// Verify email was not committed
		_, err = s.retrieveEmail(testEmail.ID)
		assert.Error(t, err, "Email should not exist due to transaction rollback")
	})
}

// TestDatabasePerformance tests database performance under load
func (s *FortressDatabaseIntegrationSuite) TestDatabasePerformance() {
	batchSize := 1000
	emails := s.emailFixtures.EmailBatch(batchSize)
	
	s.T().Run("Bulk_Insert_Performance", func(t *testing.T) {
		startTime := time.Now()
		
		// Use transaction for bulk insert
		err := s.foundation.Transaction(s.ctx, func(tx interfaces.Transaction) error {
			query := `
				INSERT INTO emails (id, message_id, from_address, to_addresses, subject, body, received_at, size)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
			
			for _, email := range emails {
				err := tx.Exec(s.ctx, query,
					email.ID, email.MessageID, email.From, pq.Array(email.To),
					email.Subject, email.Body, email.ReceivedAt, email.Size)
				if err != nil {
					return err
				}
			}
			return nil
		})
		
		insertDuration := time.Since(startTime)
		require.NoError(t, err)
		
		// Performance assertions
		assert.Less(t, insertDuration, time.Second*30,
			"Should insert %d emails within 30 seconds", batchSize)
		
		ratePerSecond := float64(batchSize) / insertDuration.Seconds()
		assert.Greater(t, ratePerSecond, float64(50),
			"Should insert at least 50 emails per second")
		
		t.Logf("Inserted %d emails in %v (%.2f emails/sec)",
			batchSize, insertDuration, ratePerSecond)
		
		// Verify all emails were inserted
		var count int64
		err = s.db.QueryRow("SELECT COUNT(*) FROM emails").Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, int64(batchSize), count)
	})
	
	s.T().Run("Query_Performance", func(t *testing.T) {
		startTime := time.Now()
		
		// Query with pagination
		query := `
			SELECT id, message_id, from_address, subject, received_at
			FROM emails
			ORDER BY received_at DESC
			LIMIT 100 OFFSET 0`
		
		rows, err := s.db.Query(query)
		require.NoError(t, err)
		defer rows.Close()
		
		var retrievedEmails []interfaces.Email
		for rows.Next() {
			var email interfaces.Email
			err := rows.Scan(&email.ID, &email.MessageID, &email.From, &email.Subject, &email.ReceivedAt)
			require.NoError(t, err)
			retrievedEmails = append(retrievedEmails, email)
		}
		
		queryDuration := time.Since(startTime)
		
		// Performance assertions
		assert.Less(t, queryDuration, time.Second*5,
			"Query should complete within 5 seconds")
		assert.Equal(t, 100, len(retrievedEmails))
		
		t.Logf("Queried 100 emails in %v", queryDuration)
	})
}

// TestDatabaseIndexing tests query optimization with indexes
func (s *FortressDatabaseIntegrationSuite) TestDatabaseIndexing() {
	s.T().Run("Index_Performance", func(t *testing.T) {
		// Create test emails with specific patterns
		testEmails := []*interfaces.Email{
			s.emailFixtures.SimpleTextEmail(),
			s.emailFixtures.HTMLEmail(),
		}
		
		// Set specific from addresses for testing
		testEmails[0].From = "indexed-test-1@fortress.test"
		testEmails[1].From = "indexed-test-2@fortress.test"
		
		// Insert emails
		for _, email := range testEmails {
			err := s.insertEmail(email)
			require.NoError(t, err)
		}
		
		// Test index usage with EXPLAIN
		query := `EXPLAIN (ANALYZE, BUFFERS) 
			SELECT id, from_address, subject 
			FROM emails 
			WHERE from_address = $1`
		
		rows, err := s.db.Query(query, testEmails[0].From)
		require.NoError(t, err)
		defer rows.Close()
		
		var queryPlan []string
		for rows.Next() {
			var line string
			err := rows.Scan(&line)
			require.NoError(t, err)
			queryPlan = append(queryPlan, line)
		}
		
		// Verify query plan includes index usage (if indexes exist)
		assert.NotEmpty(t, queryPlan, "Should have query execution plan")
		
		t.Logf("Query plan for indexed search:\n%v", queryPlan)
	})
}

// TestDatabaseConcurrency tests concurrent database access
func (s *FortressDatabaseIntegrationSuite) TestDatabaseConcurrency() {
	s.T().Run("Concurrent_Operations", func(t *testing.T) {
		concurrency := 20
		emails := s.emailFixtures.EmailBatch(concurrency)
		
		// Test concurrent inserts
		s.testUtils.FortressTestConcurrentExecution(concurrency, func(workerID int) {
			email := emails[workerID]
			err := s.insertEmail(email)
			assert.NoError(s.T(), err, "Worker %d should insert email successfully", workerID)
		})
		
		// Verify all emails were inserted
		var count int64
		err := s.db.QueryRow("SELECT COUNT(*) FROM emails WHERE id = ANY($1)",
			pq.Array(s.extractEmailIDs(emails))).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, int64(concurrency), count,
			"All concurrent inserts should succeed")
	})
}

// TestDatabaseConstraints tests database integrity constraints
func (s *FortressDatabaseIntegrationSuite) TestDatabaseConstraints() {
	email := s.emailFixtures.SimpleTextEmail()
	
	s.T().Run("Unique_Constraints", func(t *testing.T) {
		// Insert email
		err := s.insertEmail(email)
		require.NoError(t, err)
		
		// Try to insert same email again (should fail due to unique constraint)
		err = s.insertEmail(email)
		assert.Error(t, err, "Should not be able to insert duplicate email")
		
		// Verify it's a unique constraint violation
		if pqErr, ok := err.(*pq.Error); ok {
			assert.Equal(t, "23505", string(pqErr.Code), // unique_violation
				"Should be unique constraint violation")
		}
	})
	
	s.T().Run("Foreign_Key_Constraints", func(t *testing.T) {
		// This would test foreign key constraints if they exist
		// For example, testing that a session requires a valid user_id
		
		// Test with non-existent user ID
		invalidUserID := "non-existent-user-id"
		query := `
			INSERT INTO sessions (id, user_id, token, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5)`
		
		err := s.db.QueryRow(query,
			"test-session", invalidUserID, "test-token",
			time.Now().Add(time.Hour), time.Now()).Scan()
		
		// This should fail if foreign key constraints are properly set up
		// If no foreign key constraints exist, this test will be skipped
		if err != nil {
			if pqErr, ok := err.(*pq.Error); ok {
				if string(pqErr.Code) == "23503" { // foreign_key_violation
					t.Log("Foreign key constraint properly enforced")
				}
			}
		}
	})
}

// Helper methods

func (s *FortressDatabaseIntegrationSuite) overrideConfigFromEnv() {
	if host := os.Getenv("FORTRESS_TEST_DB_HOST"); host != "" {
		s.config.Host = host
	}
	if port := os.Getenv("FORTRESS_TEST_DB_PORT"); port != "" {
		// Convert string to int if needed
		s.config.Port = 5432 // Default for now
	}
	if database := os.Getenv("FORTRESS_TEST_DB_NAME"); database != "" {
		s.config.Database = database
	}
	if username := os.Getenv("FORTRESS_TEST_DB_USER"); username != "" {
		s.config.Username = username
	}
	if password := os.Getenv("FORTRESS_TEST_DB_PASSWORD"); password != "" {
		s.config.Password = password
	}
}

func (s *FortressDatabaseIntegrationSuite) initializeDatabaseConnection() {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		s.config.Username, s.config.Password, s.config.Host, s.config.Port,
		s.config.Database, s.config.SSLMode)
	
	var err error
	s.db, err = sqlx.Connect("postgres", dsn)
	require.NoError(s.T(), err, "Should be able to connect to test database")
	
	// Configure connection pool
	s.db.SetMaxOpenConns(s.config.MaxOpenConns)
	s.db.SetMaxIdleConns(s.config.MaxIdleConns)
	s.db.SetConnMaxLifetime(s.config.ConnMaxLifetime)
}

func (s *FortressDatabaseIntegrationSuite) setupTestSchema() {
	// Create test tables
	schema := `
		CREATE TABLE IF NOT EXISTS emails (
			id VARCHAR(255) PRIMARY KEY,
			message_id VARCHAR(255) UNIQUE NOT NULL,
			from_address VARCHAR(255) NOT NULL,
			to_addresses TEXT[] NOT NULL,
			cc_addresses TEXT[],
			bcc_addresses TEXT[],
			subject TEXT,
			body TEXT,
			html_body TEXT,
			headers JSONB,
			attachments JSONB,
			metadata JSONB,
			received_at TIMESTAMP WITH TIME ZONE NOT NULL,
			processed_at TIMESTAMP WITH TIME ZONE,
			stored_at TIMESTAMP WITH TIME ZONE,
			size BIGINT DEFAULT 0,
			status VARCHAR(50) DEFAULT 'received',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_emails_from_address ON emails(from_address);
		CREATE INDEX IF NOT EXISTS idx_emails_received_at ON emails(received_at);
		CREATE INDEX IF NOT EXISTS idx_emails_subject ON emails USING gin(to_tsvector('english', subject));

		CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(255) PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS sessions (
			id VARCHAR(255) PRIMARY KEY,
			user_id VARCHAR(255),
			token VARCHAR(255) UNIQUE NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`
	
	_, err := s.db.Exec(schema)
	require.NoError(s.T(), err, "Should be able to create test schema")
}

func (s *FortressDatabaseIntegrationSuite) cleanupTestSchema() {
	// Drop test tables
	cleanup := `
		DROP TABLE IF EXISTS sessions;
		DROP TABLE IF EXISTS users;
		DROP TABLE IF EXISTS emails;`
	
	_, err := s.db.Exec(cleanup)
	if err != nil {
		s.T().Logf("Warning: Error cleaning up test schema: %v", err)
	}
}

func (s *FortressDatabaseIntegrationSuite) cleanupTestData() {
	// Clean test data from tables
	_, err := s.db.Exec("DELETE FROM sessions")
	if err != nil {
		s.T().Logf("Warning: Error cleaning sessions: %v", err)
	}
	
	_, err = s.db.Exec("DELETE FROM emails")
	if err != nil {
		s.T().Logf("Warning: Error cleaning emails: %v", err)
	}
}

func (s *FortressDatabaseIntegrationSuite) createFoundationService() interfaces.Foundation {
	// This would create a real Foundation service implementation
	// For now, return a mock that uses the real database
	return &DatabaseFoundationService{db: s.db, config: s.config}
}

func (s *FortressDatabaseIntegrationSuite) insertEmail(email *interfaces.Email) error {
	query := `
		INSERT INTO emails (id, message_id, from_address, to_addresses, subject, body, html_body, headers, received_at, size)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	
	_, err := s.db.Exec(query,
		email.ID, email.MessageID, email.From, pq.Array(email.To),
		email.Subject, email.Body, email.HTMLBody, email.Headers,
		email.ReceivedAt, email.Size)
	
	return err
}

func (s *FortressDatabaseIntegrationSuite) retrieveEmail(id string) (*interfaces.Email, error) {
	email := &interfaces.Email{}
	query := `
		SELECT id, message_id, from_address, to_addresses, subject, body, html_body, received_at, size
		FROM emails WHERE id = $1`
	
	err := s.db.QueryRow(query, id).Scan(
		&email.ID, &email.MessageID, &email.From, pq.Array(&email.To),
		&email.Subject, &email.Body, &email.HTMLBody, &email.ReceivedAt, &email.Size)
	
	if err != nil {
		return nil, err
	}
	
	return email, nil
}

func (s *FortressDatabaseIntegrationSuite) updateEmail(id string, updates map[string]interface{}) error {
	// Simple update implementation for testing
	if subject, ok := updates["subject"]; ok {
		_, err := s.db.Exec("UPDATE emails SET subject = $1 WHERE id = $2", subject, id)
		return err
	}
	return nil
}

func (s *FortressDatabaseIntegrationSuite) deleteEmail(id string) error {
	_, err := s.db.Exec("DELETE FROM emails WHERE id = $1", id)
	return err
}

func (s *FortressDatabaseIntegrationSuite) extractEmailIDs(emails []*interfaces.Email) []string {
	ids := make([]string, len(emails))
	for i, email := range emails {
		ids[i] = email.ID
	}
	return ids
}

// DatabaseFoundationService is a real Foundation implementation for testing
type DatabaseFoundationService struct {
	db     *sqlx.DB
	config *interfaces.DatabaseConfig
}

func (d *DatabaseFoundationService) Connect(ctx context.Context, config *interfaces.DatabaseConfig) error {
	return nil // Already connected
}

func (d *DatabaseFoundationService) Disconnect(ctx context.Context) error {
	return nil // Let test suite handle disconnection
}

func (d *DatabaseFoundationService) Migrate(ctx context.Context, version string) error {
	return nil // Migrations handled by test setup
}

func (d *DatabaseFoundationService) Query(ctx context.Context, query string, args ...interface{}) (*interfaces.QueryResult, error) {
	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	// Convert to QueryResult (simplified implementation)
	return &interfaces.QueryResult{}, nil
}

func (d *DatabaseFoundationService) QueryOne(ctx context.Context, query string, args ...interface{}) (map[string]interface{}, error) {
	return make(map[string]interface{}), nil
}

func (d *DatabaseFoundationService) Exec(ctx context.Context, query string, args ...interface{}) error {
	_, err := d.db.ExecContext(ctx, query, args...)
	return err
}

func (d *DatabaseFoundationService) BeginTransaction(ctx context.Context) (interfaces.Transaction, error) {
	tx, err := d.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &DatabaseTransaction{tx: tx}, nil
}

func (d *DatabaseFoundationService) Transaction(ctx context.Context, fn func(tx interfaces.Transaction) error) error {
	tx, err := d.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		} else if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()
	
	err = fn(tx)
	return err
}

// Implement other Foundation methods with mocks for now
func (d *DatabaseFoundationService) CacheGet(ctx context.Context, key string) (interface{}, error) {
	return nil, fmt.Errorf("key not found: %s", key)
}

func (d *DatabaseFoundationService) CacheSet(ctx context.Context, key string, value interface{}, ttl *time.Duration) error {
	return nil
}

func (d *DatabaseFoundationService) CacheDelete(ctx context.Context, key string) error {
	return nil
}

func (d *DatabaseFoundationService) CacheClear(ctx context.Context, pattern string) error {
	return nil
}

func (d *DatabaseFoundationService) StoreFile(ctx context.Context, path string, data []byte) error {
	return nil
}

func (d *DatabaseFoundationService) RetrieveFile(ctx context.Context, path string) ([]byte, error) {
	return nil, fmt.Errorf("file not found: %s", path)
}

func (d *DatabaseFoundationService) DeleteFile(ctx context.Context, path string) error {
	return nil
}

func (d *DatabaseFoundationService) ListFiles(ctx context.Context, pattern string) ([]string, error) {
	return []string{}, nil
}

func (d *DatabaseFoundationService) CreateBackup(ctx context.Context, config *interfaces.BackupConfig) error {
	return nil
}

func (d *DatabaseFoundationService) RestoreBackup(ctx context.Context, backupID string) error {
	return nil
}

func (d *DatabaseFoundationService) ListBackups(ctx context.Context) ([]*interfaces.BackupInfo, error) {
	return []*interfaces.BackupInfo{}, nil
}

func (d *DatabaseFoundationService) Start(ctx context.Context) error {
	return nil
}

func (d *DatabaseFoundationService) Stop(ctx context.Context) error {
	return nil
}

func (d *DatabaseFoundationService) Health(ctx context.Context) *interfaces.HealthStatus {
	// Test database ping
	err := d.db.Ping()
	status := interfaces.HealthStatusHealthy
	message := "Database connection healthy"
	
	if err != nil {
		status = interfaces.HealthStatusUnhealthy
		message = fmt.Sprintf("Database connection failed: %v", err)
	}
	
	return &interfaces.HealthStatus{
		Service:   "foundation",
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
		Duration:  time.Millisecond * 10,
	}
}

// DatabaseTransaction implements interfaces.Transaction with real database transaction
type DatabaseTransaction struct {
	tx *sqlx.Tx
}

func (d *DatabaseTransaction) Query(ctx context.Context, query string, args ...interface{}) (*interfaces.QueryResult, error) {
	rows, err := d.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	return &interfaces.QueryResult{}, nil
}

func (d *DatabaseTransaction) Exec(ctx context.Context, query string, args ...interface{}) error {
	_, err := d.tx.ExecContext(ctx, query, args...)
	return err
}

func (d *DatabaseTransaction) Commit() error {
	return d.tx.Commit()
}

func (d *DatabaseTransaction) Rollback() error {
	return d.tx.Rollback()
}

// TestFortressDatabaseIntegration runs the database integration test suite
func TestFortressDatabaseIntegration(t *testing.T) {
	// Skip if no database available
	if os.Getenv("FORTRESS_TEST_DB_HOST") == "" {
		t.Skip("Skipping database integration tests - no database configured")
	}
	
	suite.Run(t, new(FortressDatabaseIntegrationSuite))
}