package keep_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/pat-fortress/pkg/keep"
	"github.com/pat-fortress/tests/mocks"
	"github.com/pat-fortress/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

// FortressKeepServiceTestSuite provides comprehensive testing for The Keep service
type FortressKeepServiceTestSuite struct {
	suite.Suite
	service     *keep.KeepService
	foundation  *mocks.MockFoundation
	eventBus    *mocks.MockEventBus
	watchtower  *mocks.MockWatchtower
	rampart     *mocks.MockRampart
	testUtils   *utils.FortressTestUtils
	ctx         context.Context
	cancelFunc  context.CancelFunc
}

// SetupSuite initializes the test suite
func (suite *FortressKeepServiceTestSuite) SetupSuite() {
	suite.testUtils = utils.NewFortressTestUtils(suite.T())
	
	// Create mock dependencies
	suite.foundation = mocks.NewMockFoundation()
	suite.eventBus = mocks.NewMockEventBus()
	suite.watchtower = mocks.NewMockWatchtower()
	suite.rampart = mocks.NewMockRampart()
	
	// Setup context
	suite.ctx, suite.cancelFunc = context.WithTimeout(context.Background(), 30*time.Second)
}

// SetupTest runs before each test
func (suite *FortressKeepServiceTestSuite) SetupTest() {
	// Reset mocks
	suite.foundation.ExpectedCalls = nil
	suite.eventBus.ExpectedCalls = nil
	suite.watchtower.ExpectedCalls = nil
	suite.rampart.ExpectedCalls = nil

	// Create new service instance for each test
	logger := zap.NewNop()
	
	config := &keep.Config{
		EmailProcessing: keep.ProcessingConfig{
			WorkerCount:     4,
			QueueSize:       1000,
			ProcessingTimeout: 30 * time.Second,
			EnableValidation:  true,
			EnableAnalytics:   true,
		},
		Storage: keep.StorageConfig{
			RetentionDays:    30,
			MaxEmailSize:     25 * 1024 * 1024, // 25MB
			CompressionEnabled: true,
			EncryptionEnabled:  true,
		},
		Search: keep.SearchConfig{
			IndexingEnabled:  true,
			FuzzySearchEnabled: true,
			MaxSearchResults: 1000,
			SearchTimeout:    10 * time.Second,
		},
		Analytics: keep.AnalyticsConfig{
			TrackingEnabled:    true,
			MetricsRetention:   7 * 24 * time.Hour,
			RealTimeStats:      true,
		},
		Validation: keep.ValidationConfig{
			ValidateHeaders:    true,
			ValidateContent:    true,
			MaxAttachmentSize:  10 * 1024 * 1024, // 10MB
			BlockedExtensions:  []string{".exe", ".bat", ".scr"},
		},
	}

	var err error
	suite.service, err = keep.NewKeepService(
		suite.ctx,
		config,
		suite.foundation,
		suite.eventBus,
		suite.watchtower,
		suite.rampart,
		logger,
	)
	require.NoError(suite.T(), err, "Failed to create Keep service")
}

// TearDownTest runs after each test
func (suite *FortressKeepServiceTestSuite) TearDownTest() {
	if suite.service != nil {
		suite.service.Stop(suite.ctx)
	}
}

// TearDownSuite cleans up the test suite
func (suite *FortressKeepServiceTestSuite) TearDownSuite() {
	suite.cancelFunc()
}

// TestFortressKeepServiceCreation tests service creation and initialization
func (suite *FortressKeepServiceTestSuite) TestFortressKeepServiceCreation() {
	suite.T().Run("Fortress Keep Service Creation Success", func(t *testing.T) {
		assert.NotNil(t, suite.service, "Keep service should be created successfully")
	})

	suite.T().Run("Fortress Keep Service Creation with Nil Config", func(t *testing.T) {
		logger := zap.NewNop()
		_, err := keep.NewKeepService(
			suite.ctx,
			nil, // nil config
			suite.foundation,
			suite.eventBus,
			suite.watchtower,
			suite.rampart,
			logger,
		)
		assert.Error(t, err, "Should fail with nil config")
		assert.Contains(t, err.Error(), "config cannot be nil", "Error should mention config")
	})

	suite.T().Run("Fortress Keep Service Creation with Nil Dependencies", func(t *testing.T) {
		logger := zap.NewNop()
		config := &keep.Config{}
		
		_, err := keep.NewKeepService(
			suite.ctx,
			config,
			nil, // nil foundation
			suite.eventBus,
			suite.watchtower,
			suite.rampart,
			logger,
		)
		assert.Error(t, err, "Should fail with nil foundation")
	})
}

// TestFortressKeepServiceLifecycle tests service start/stop lifecycle
func (suite *FortressKeepServiceTestSuite) TestFortressKeepServiceLifecycle() {
	suite.T().Run("Fortress Keep Service Start", func(t *testing.T) {
		// Setup expectations
		suite.foundation.On("Start", mock.Anything).Return(nil)
		suite.eventBus.On("Start", mock.Anything).Return(nil)
		suite.watchtower.On("StartMonitoring", mock.Anything).Return(nil)
		suite.rampart.On("Start", mock.Anything).Return(nil)
		
		suite.watchtower.On("LogEvent", 
			interfaces.LogLevelInfo, 
			mock.AnythingOfType("string"), 
			mock.Anything).Return()

		err := suite.service.Start(suite.ctx)
		assert.NoError(t, err, "Keep service should start successfully")
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
		suite.rampart.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Service Stop", func(t *testing.T) {
		// Setup expectations
		suite.foundation.On("Stop", mock.Anything).Return(nil)
		suite.eventBus.On("Stop", mock.Anything).Return(nil)
		suite.watchtower.On("StopMonitoring", mock.Anything).Return(nil)
		suite.rampart.On("Stop", mock.Anything).Return(nil)
		
		suite.watchtower.On("LogEvent", 
			interfaces.LogLevelInfo, 
			mock.AnythingOfType("string"), 
			mock.Anything).Return()

		err := suite.service.Stop(suite.ctx)
		assert.NoError(t, err, "Keep service should stop successfully")
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
		suite.rampart.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Service Health Check", func(t *testing.T) {
		expectedHealth := suite.testUtils.CreateTestHealthStatus(
			"keep",
			interfaces.HealthStatusHealthy,
			"Keep service operational",
		)
		
		health := suite.service.Health(suite.ctx)
		assert.NotNil(t, health, "Health status should not be nil")
		suite.testUtils.AssertHealthStatusValid(health, "keep")
	})
}

// TestFortressKeepEmailProcessing tests core email processing functionality
func (suite *FortressKeepServiceTestSuite) TestFortressKeepEmailProcessing() {
	suite.T().Run("Fortress Keep Process Email Success", func(t *testing.T) {
		testEmail := suite.testUtils.CreateTestEmail(
			utils.WithSubject("Test Email Processing"),
			utils.WithFrom("sender@fortress.test"),
			utils.WithTo([]string{"recipient@fortress.test"}),
		)

		// Setup expectations
		suite.rampart.On("ScanEmail", mock.Anything, testEmail).Return(&interfaces.ScanResult{
			Safe: true,
			Threats: []string{},
			Score: 95.0,
		}, nil)
		
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		
		suite.eventBus.On("Publish", mock.Anything, mock.MatchedBy(func(event *interfaces.Event) bool {
			return event.Type == "email.processed"
		})).Return(nil)
		
		suite.watchtower.On("LogEmail", testEmail, "processed", mock.Anything).Return()
		suite.watchtower.On("RecordMetric", "emails.processed", float64(1), mock.Anything).Return()

		err := suite.service.ProcessEmail(suite.ctx, testEmail)
		assert.NoError(t, err, "Email should be processed successfully")
		
		suite.rampart.AssertExpectations(t)
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Process Email with Security Threat", func(t *testing.T) {
		maliciousEmail := suite.testUtils.CreateTestEmail(
			utils.WithSubject("Malicious Email"),
			utils.WithFrom("attacker@malicious.com"),
			utils.WithAttachment("virus.exe", "application/octet-stream", []byte("malicious content")),
		)

		// Setup expectations for security scan
		suite.rampart.On("ScanEmail", mock.Anything, maliciousEmail).Return(&interfaces.ScanResult{
			Safe: false,
			Threats: []string{"malware.detected", "suspicious.attachment"},
			Score: 15.0,
			Details: map[string]interface{}{
				"blocked_reason": "malicious attachment detected",
			},
		}, nil)
		
		suite.watchtower.On("LogError", mock.AnythingOfType("*errors.errorString"), mock.Anything).Return()
		suite.watchtower.On("TriggerAlert", interfaces.AlertLevelHigh, mock.AnythingOfType("string"), mock.Anything).Return()

		err := suite.service.ProcessEmail(suite.ctx, maliciousEmail)
		assert.Error(t, err, "Malicious email should be rejected")
		assert.Contains(t, err.Error(), "security threat detected", "Error should mention security threat")
		
		suite.rampart.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Process Email with Validation Errors", func(t *testing.T) {
		invalidEmail := &interfaces.Email{
			ID: "invalid-email",
			// Missing required fields
		}

		err := suite.service.ProcessEmail(suite.ctx, invalidEmail)
		assert.Error(t, err, "Invalid email should be rejected")
		assert.Contains(t, err.Error(), "validation failed", "Error should mention validation")
	})
}

// TestFortressKeepEmailStorage tests email storage functionality
func (suite *FortressKeepServiceTestSuite) TestFortressKeepEmailStorage() {
	suite.T().Run("Fortress Keep Store Email Success", func(t *testing.T) {
		testEmail := suite.testUtils.CreateTestEmail()

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		suite.watchtower.On("RecordMetric", "emails.stored", float64(1), mock.Anything).Return()
		suite.watchtower.On("LogEmail", testEmail, "stored", mock.Anything).Return()

		err := suite.service.StoreEmail(suite.ctx, testEmail)
		assert.NoError(t, err, "Email should be stored successfully")
		
		suite.foundation.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Store Email Size Limit", func(t *testing.T) {
		largeEmail := suite.testUtils.CreateTestEmail()
		largeEmail.Size = 50 * 1024 * 1024 // 50MB (exceeds 25MB limit)

		err := suite.service.StoreEmail(suite.ctx, largeEmail)
		assert.Error(t, err, "Large email should be rejected")
		assert.Contains(t, err.Error(), "size limit exceeded", "Error should mention size limit")
	})

	suite.T().Run("Fortress Keep Retrieve Email Success", func(t *testing.T) {
		emailID := "test-email-123"
		expectedEmail := suite.testUtils.CreateTestEmail()
		expectedEmail.ID = emailID

		// Setup expectations
		queryResult := &interfaces.QueryResult{
			Rows: []map[string]interface{}{
				{
					"id":          emailID,
					"message_id":  expectedEmail.MessageID,
					"from_addr":   expectedEmail.From,
					"to_addrs":    expectedEmail.To,
					"subject":     expectedEmail.Subject,
					"body":        expectedEmail.Body,
					"received_at": expectedEmail.ReceivedAt,
					"size":        expectedEmail.Size,
				},
			},
			Count:    1,
			Duration: time.Millisecond * 10,
		}
		
		suite.foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(queryResult, nil)

		retrievedEmail, err := suite.service.RetrieveEmail(suite.ctx, emailID)
		assert.NoError(t, err, "Email should be retrieved successfully")
		assert.NotNil(t, retrievedEmail, "Retrieved email should not be nil")
		assert.Equal(t, emailID, retrievedEmail.ID, "Email IDs should match")
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Retrieve Email Not Found", func(t *testing.T) {
		emailID := "non-existent-email"

		// Setup expectations for empty result
		queryResult := &interfaces.QueryResult{
			Rows:     []map[string]interface{}{},
			Count:    0,
			Duration: time.Millisecond * 5,
		}
		
		suite.foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(queryResult, nil)

		retrievedEmail, err := suite.service.RetrieveEmail(suite.ctx, emailID)
		assert.Error(t, err, "Should return error for non-existent email")
		assert.Nil(t, retrievedEmail, "Retrieved email should be nil")
		assert.Contains(t, err.Error(), "not found", "Error should mention not found")
		
		suite.foundation.AssertExpectations(t)
	})
}

// TestFortressKeepEmailSearch tests email search functionality
func (suite *FortressKeepServiceTestSuite) TestFortressKeepEmailSearch() {
	suite.T().Run("Fortress Keep Search Emails Success", func(t *testing.T) {
		searchQuery := suite.testUtils.CreateTestSearchQuery(
			"test subject",
			utils.WithSearchFields([]string{"subject", "body"}),
			utils.WithSearchFuzzy(true),
		)

		// Create expected search results
		testEmails := suite.testUtils.FortressTestEmailBatch(5)
		expectedResults := &interfaces.SearchResults{
			Emails:      testEmails,
			Total:       5,
			Took:        time.Millisecond * 150,
			Facets:      make(map[string]interface{}),
			Highlights:  make(map[string][]string),
			Suggestions: []string{},
		}

		// Setup expectations
		suite.foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(&interfaces.QueryResult{
			Rows:     make([]map[string]interface{}, 5), // Simplified for test
			Count:    5,
			Duration: time.Millisecond * 150,
		}, nil)
		
		suite.watchtower.On("RecordMetric", "searches.performed", float64(1), mock.Anything).Return()
		suite.watchtower.On("RecordHistogram", "search.duration", mock.AnythingOfType("float64"), mock.Anything).Return()

		results, err := suite.service.SearchEmails(suite.ctx, searchQuery)
		assert.NoError(t, err, "Search should complete successfully")
		assert.NotNil(t, results, "Search results should not be nil")
		assert.True(t, results.Total >= 0, "Total should be non-negative")
		
		suite.foundation.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Search with Complex Filter", func(t *testing.T) {
		complexFilter := suite.testUtils.CreateTestFilter(
			utils.WithFilterFrom("sender@fortress.test"),
			utils.WithFilterSubject("important"),
			utils.WithFilterDateRange(time.Now().Add(-24*time.Hour), time.Now()),
			utils.WithFilterLimit(50),
		)

		// Setup expectations
		queryResult := &interfaces.QueryResult{
			Rows:     make([]map[string]interface{}, 3),
			Count:    3,
			Duration: time.Millisecond * 75,
		}
		
		suite.foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(queryResult, nil)

		emails, err := suite.service.RetrieveEmails(suite.ctx, complexFilter)
		assert.NoError(t, err, "Complex filter should work successfully")
		assert.NotNil(t, emails, "Emails should not be nil")
		
		suite.foundation.AssertExpectations(t)
	})
}

// TestFortressKeepEmailManagement tests email management operations
func (suite *FortressKeepServiceTestSuite) TestFortressKeepEmailManagement() {
	suite.T().Run("Fortress Keep Delete Email Success", func(t *testing.T) {
		emailID := "email-to-delete"

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		suite.eventBus.On("Publish", mock.Anything, mock.MatchedBy(func(event *interfaces.Event) bool {
			return event.Type == "email.deleted"
		})).Return(nil)
		suite.watchtower.On("LogEvent", interfaces.LogLevelInfo, mock.AnythingOfType("string"), mock.Anything).Return()

		err := suite.service.DeleteEmail(suite.ctx, emailID)
		assert.NoError(t, err, "Email should be deleted successfully")
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Update Email Success", func(t *testing.T) {
		emailID := "email-to-update"
		updates := map[string]interface{}{
			"subject": "Updated Subject",
			"tags":    []string{"updated", "modified"},
		}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		suite.watchtower.On("LogEvent", interfaces.LogLevelInfo, mock.AnythingOfType("string"), mock.Anything).Return()

		err := suite.service.UpdateEmail(suite.ctx, emailID, updates)
		assert.NoError(t, err, "Email should be updated successfully")
		
		suite.foundation.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Tag Email Success", func(t *testing.T) {
		emailID := "email-to-tag"
		tags := []string{"important", "customer-support", "fortress"}

		// Setup expectations
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
		suite.watchtower.On("LogEvent", interfaces.LogLevelInfo, mock.AnythingOfType("string"), mock.Anything).Return()

		err := suite.service.TagEmail(suite.ctx, emailID, tags)
		assert.NoError(t, err, "Email should be tagged successfully")
		
		suite.foundation.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Release Email Success", func(t *testing.T) {
		emailID := "email-to-release"
		releaseTo := "recipient@fortress.test"

		// Setup expectations
		suite.foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(&interfaces.QueryResult{
			Rows: []map[string]interface{}{
				{"id": emailID, "subject": "Test Email"},
			},
			Count: 1,
		}, nil)
		
		suite.eventBus.On("Publish", mock.Anything, mock.MatchedBy(func(event *interfaces.Event) bool {
			return event.Type == "email.released"
		})).Return(nil)
		
		suite.watchtower.On("LogEvent", interfaces.LogLevelInfo, mock.AnythingOfType("string"), mock.Anything).Return()

		err := suite.service.ReleaseEmail(suite.ctx, emailID, releaseTo)
		assert.NoError(t, err, "Email should be released successfully")
		
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})
}

// TestFortressKeepStatistics tests statistics and analytics functionality
func (suite *FortressKeepServiceTestSuite) TestFortressKeepStatistics() {
	suite.T().Run("Fortress Keep Get Email Stats", func(t *testing.T) {
		filter := suite.testUtils.CreateTestFilter()

		// Setup expectations
		statsResult := &interfaces.QueryResult{
			Rows: []map[string]interface{}{
				{
					"total_emails":    100,
					"total_size":      1024000,
					"emails_today":    25,
					"emails_week":     150,
					"emails_month":    400,
					"average_size":    10240,
				},
			},
			Count:    1,
			Duration: time.Millisecond * 50,
		}
		
		suite.foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(statsResult, nil)

		stats, err := suite.service.GetEmailStats(suite.ctx, filter)
		assert.NoError(t, err, "Should get email stats successfully")
		assert.NotNil(t, stats, "Stats should not be nil")
		assert.True(t, stats.TotalEmails >= 0, "Total emails should be non-negative")
		
		suite.foundation.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Get Storage Stats", func(t *testing.T) {
		// Setup expectations
		storageResult := &interfaces.QueryResult{
			Rows: []map[string]interface{}{
				{
					"total_storage":     1024000000,
					"available_storage": 5120000000,
					"storage_percent":   20.0,
				},
			},
			Count:    1,
			Duration: time.Millisecond * 25,
		}
		
		suite.foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(storageResult, nil)

		storageStats, err := suite.service.GetStorageStats(suite.ctx)
		assert.NoError(t, err, "Should get storage stats successfully")
		assert.NotNil(t, storageStats, "Storage stats should not be nil")
		
		suite.foundation.AssertExpectations(t)
	})
}

// TestFortressKeepConcurrency tests concurrent operations
func (suite *FortressKeepServiceTestSuite) TestFortressKeepConcurrency() {
	suite.T().Run("Fortress Keep Concurrent Email Processing", func(t *testing.T) {
		workerCount := 10
		emailsPerWorker := 5
		
		// Setup expectations for concurrent processing
		suite.rampart.On("ScanEmail", mock.Anything, mock.AnythingOfType("*interfaces.Email")).Return(&interfaces.ScanResult{
			Safe: true,
			Threats: []string{},
			Score: 95.0,
		}, nil).Times(workerCount * emailsPerWorker)
		
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil).Times(workerCount * emailsPerWorker)
		suite.eventBus.On("Publish", mock.Anything, mock.AnythingOfType("*interfaces.Event")).Return(nil).Times(workerCount * emailsPerWorker)
		suite.watchtower.On("LogEmail", mock.AnythingOfType("*interfaces.Email"), "processed", mock.Anything).Return().Times(workerCount * emailsPerWorker)
		suite.watchtower.On("RecordMetric", "emails.processed", float64(1), mock.Anything).Return().Times(workerCount * emailsPerWorker)

		suite.testUtils.FortressTestConcurrentExecution(workerCount, func(workerID int) {
			for i := 0; i < emailsPerWorker; i++ {
				email := suite.testUtils.CreateTestEmail(
					utils.WithSubject(fmt.Sprintf("Concurrent Email W%d-E%d", workerID, i)),
					utils.WithFrom(fmt.Sprintf("worker%d@fortress.test", workerID)),
				)
				
				err := suite.service.ProcessEmail(suite.ctx, email)
				assert.NoError(suite.T(), err, "Concurrent email processing should succeed")
			}
		})
		
		// Give some time for all operations to complete
		time.Sleep(100 * time.Millisecond)
		
		suite.rampart.AssertExpectations(t)
		suite.foundation.AssertExpectations(t)
		suite.eventBus.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})
}

// TestFortressKeepErrorScenarios tests error handling and edge cases
func (suite *FortressKeepServiceTestSuite) TestFortressKeepErrorScenarios() {
	suite.T().Run("Fortress Keep Database Connection Error", func(t *testing.T) {
		testEmail := suite.testUtils.CreateTestEmail()

		// Setup expectations for database error
		suite.rampart.On("ScanEmail", mock.Anything, testEmail).Return(&interfaces.ScanResult{
			Safe: true,
		}, nil)
		
		dbError := fmt.Errorf("database connection failed")
		suite.foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(dbError)
		suite.watchtower.On("LogError", dbError, mock.Anything).Return()

		err := suite.service.ProcessEmail(suite.ctx, testEmail)
		assert.Error(t, err, "Should fail with database error")
		assert.Contains(t, err.Error(), "database", "Error should mention database")
		
		suite.rampart.AssertExpectations(t)
		suite.foundation.AssertExpectations(t)
		suite.watchtower.AssertExpectations(t)
	})

	suite.T().Run("Fortress Keep Context Timeout", func(t *testing.T) {
		// Create a context with very short timeout
		shortCtx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		
		// Wait for context to timeout
		time.Sleep(time.Millisecond)

		testEmail := suite.testUtils.CreateTestEmail()
		err := suite.service.ProcessEmail(shortCtx, testEmail)
		assert.Error(t, err, "Should fail with context timeout")
		assert.Contains(t, err.Error(), "context", "Error should mention context")
	})
}

// Run the test suite
func TestFortressKeepServiceTestSuite(t *testing.T) {
	suite.Run(t, new(FortressKeepServiceTestSuite))
}

// Benchmark tests for performance validation
func BenchmarkFortressKeepEmailProcessing(b *testing.B) {
	// Setup
	foundation := mocks.NewMockFoundation()
	eventBus := mocks.NewMockEventBus()
	watchtower := mocks.NewMockWatchtower()
	rampart := mocks.NewMockRampart()
	
	foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
	eventBus.On("Publish", mock.Anything, mock.AnythingOfType("*interfaces.Event")).Return(nil)
	watchtower.On("LogEmail", mock.AnythingOfType("*interfaces.Email"), "processed", mock.Anything).Return()
	watchtower.On("RecordMetric", "emails.processed", float64(1), mock.Anything).Return()
	rampart.On("ScanEmail", mock.Anything, mock.AnythingOfType("*interfaces.Email")).Return(&interfaces.ScanResult{
		Safe: true,
	}, nil)

	config := &keep.Config{
		EmailProcessing: keep.ProcessingConfig{
			WorkerCount:     1,
			QueueSize:       100,
			ProcessingTimeout: 30 * time.Second,
		},
		Storage: keep.StorageConfig{
			MaxEmailSize: 25 * 1024 * 1024,
		},
	}

	logger := zap.NewNop()
	ctx := context.Background()
	
	service, err := keep.NewKeepService(ctx, config, foundation, eventBus, watchtower, rampart, logger)
	require.NoError(b, err)
	
	testUtils := utils.NewFortressTestUtils(&testing.T{})
	testEmail := testUtils.CreateTestEmail()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := service.ProcessEmail(ctx, testEmail)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkFortressKeepEmailSearch(b *testing.B) {
	// Setup
	foundation := mocks.NewMockFoundation()
	watchtower := mocks.NewMockWatchtower()
	
	searchResult := &interfaces.QueryResult{
		Rows:     make([]map[string]interface{}, 10),
		Count:    10,
		Duration: time.Millisecond * 50,
	}
	
	foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(searchResult, nil)
	watchtower.On("RecordMetric", "searches.performed", float64(1), mock.Anything).Return()
	watchtower.On("RecordHistogram", "search.duration", mock.AnythingOfType("float64"), mock.Anything).Return()

	config := &keep.Config{
		Search: keep.SearchConfig{
			IndexingEnabled:  true,
			MaxSearchResults: 1000,
			SearchTimeout:    10 * time.Second,
		},
	}

	logger := zap.NewNop()
	ctx := context.Background()
	
	service, err := keep.NewKeepService(ctx, config, foundation, mocks.NewMockEventBus(), watchtower, mocks.NewMockRampart(), logger)
	require.NoError(b, err)
	
	testUtils := utils.NewFortressTestUtils(&testing.T{})
	searchQuery := testUtils.CreateTestSearchQuery("test search")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := service.SearchEmails(ctx, searchQuery)
			if err != nil {
				b.Error(err)
			}
		}
	})
}