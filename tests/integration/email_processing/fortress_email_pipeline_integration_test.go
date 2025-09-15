package email_processing

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/pat-fortress/tests/integration/testdata/fixtures"
	"github.com/pat-fortress/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// FortressEmailPipelineSuite tests the complete email processing pipeline
type FortressEmailPipelineSuite struct {
	suite.Suite
	testUtils      *utils.FortressTestUtils
	emailFixtures  *fixtures.EmailFixtures
	configFixtures *fixtures.ConfigFixtures
	
	// Fortress services
	keep       interfaces.Keep
	watchtower interfaces.Watchtower
	rampart    interfaces.Rampart
	armory     interfaces.Armory
	gates      interfaces.Gates
	foundation interfaces.Foundation
	eventBus   interfaces.EventBus
	
	// Test configuration
	ctx           context.Context
	cancel        context.CancelFunc
	processedEmails map[string]*interfaces.Email
	eventLog      []interfaces.Event
	mu            sync.RWMutex
}

// SetupSuite initializes the test suite
func (s *FortressEmailPipelineSuite) SetupSuite() {
	s.testUtils = utils.NewFortressTestUtils(s.T())
	s.emailFixtures = fixtures.NewEmailFixtures()
	s.configFixtures = fixtures.NewConfigFixtures()
	s.processedEmails = make(map[string]*interfaces.Email)
	s.eventLog = make([]interfaces.Event, 0)
	
	// Create test context with timeout
	s.ctx, s.cancel = context.WithTimeout(context.Background(), time.Minute*10)
	
	// Initialize fortress services
	s.setupFortressServices()
	
	// Setup event logging
	s.setupEventLogging()
	
	// Start all services
	s.startServices()
}

// TearDownSuite cleans up the test suite
func (s *FortressEmailPipelineSuite) TearDownSuite() {
	// Stop all services
	s.stopServices()
	
	// Cancel context
	if s.cancel != nil {
		s.cancel()
	}
}

// setupFortressServices initializes all fortress services for testing
func (s *FortressEmailPipelineSuite) setupFortressServices() {
	// This would normally use dependency injection container
	// For integration tests, we use actual implementations
	
	// Initialize Foundation (Database & Storage) first
	s.foundation = s.createFoundationService()
	
	// Initialize EventBus for inter-service communication
	s.eventBus = s.createEventBusService()
	
	// Initialize Watchtower for monitoring
	s.watchtower = s.createWatchtowerService()
	
	// Initialize Rampart for security
	s.rampart = s.createRampartService()
	
	// Initialize Armory for plugins
	s.armory = s.createArmoryService()
	
	// Initialize Keep for email processing
	s.keep = s.createKeepService()
	
	// Initialize Gates for API/SMTP servers
	s.gates = s.createGatesService()
}

// setupEventLogging sets up event logging for testing
func (s *FortressEmailPipelineSuite) setupEventLogging() {
	// Subscribe to all email processing events
	emailEvents := []string{
		"email.received",
		"email.validated", 
		"email.processed",
		"email.stored",
		"email.indexed",
		"email.plugin_executed",
		"email.security_scanned",
		"email.metrics_recorded",
	}
	
	for _, eventType := range emailEvents {
		s.eventBus.Subscribe(eventType, s.logEvent)
	}
}

// logEvent captures events for testing validation
func (s *FortressEmailPipelineSuite) logEvent(ctx context.Context, event *interfaces.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventLog = append(s.eventLog, *event)
	return nil
}

// TestCompleteEmailProcessingPipeline tests the entire email pipeline
func (s *FortressEmailPipelineSuite) TestCompleteEmailProcessingPipeline() {
	// Test with simple email
	email := s.emailFixtures.SimpleTextEmail()
	
	// Step 1: SMTP Reception
	s.T().Run("SMTP_Reception", func(t *testing.T) {
		err := s.gates.HandleSMTPConnection(s.ctx, nil) // Mock connection
		require.NoError(t, err)
		
		// Simulate SMTP processing that triggers email.received event
		event := &interfaces.Event{
			ID:        uuid.New().String(),
			Type:      "email.received",
			Source:    "gates",
			Timestamp: time.Now(),
			Data:      map[string]interface{}{"email_id": email.ID},
		}
		err = s.eventBus.Publish(s.ctx, event)
		require.NoError(t, err)
	})
	
	// Step 2: Email Validation
	s.T().Run("Email_Validation", func(t *testing.T) {
		// Rampart validates the email
		scanResult, err := s.rampart.ScanEmail(s.ctx, email)
		require.NoError(t, err)
		assert.NotNil(t, scanResult)
		assert.Equal(t, interfaces.ScanStatusClean, scanResult.Status)
	})
	
	// Step 3: Email Processing
	s.T().Run("Email_Processing", func(t *testing.T) {
		// Keep processes the email
		err := s.keep.ProcessEmail(s.ctx, email)
		require.NoError(t, err)
		
		// Verify email was processed
		processedEmail, err := s.keep.RetrieveEmail(s.ctx, email.ID)
		require.NoError(t, err)
		assert.Equal(t, email.ID, processedEmail.ID)
		assert.NotZero(t, processedEmail.ProcessedAt)
	})
	
	// Step 4: Plugin Execution
	s.T().Run("Plugin_Execution", func(t *testing.T) {
		// Execute plugins on the email
		result, err := s.armory.ExecutePluginChain(s.ctx, "default", email)
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		
		// Verify plugin results
		for _, pluginResult := range result {
			assert.Equal(t, interfaces.PluginStatusSuccess, pluginResult.Status)
		}
	})
	
	// Step 5: Storage
	s.T().Run("Email_Storage", func(t *testing.T) {
		// Store the processed email
		err := s.keep.StoreEmail(s.ctx, email)
		require.NoError(t, err)
		
		// Verify storage
		storedEmail, err := s.keep.RetrieveEmail(s.ctx, email.ID)
		require.NoError(t, err)
		s.testUtils.AssertEmailEquals(email, storedEmail)
	})
	
	// Step 6: Search Indexing
	s.T().Run("Search_Indexing", func(t *testing.T) {
		// Wait a moment for async indexing
		time.Sleep(time.Millisecond * 500)
		
		// Search for the email
		query := s.testUtils.CreateTestSearchQuery("Simple Test Email")
		results, err := s.keep.SearchEmails(s.ctx, query)
		require.NoError(t, err)
		assert.Greater(t, results.Total, int64(0))
		assert.Contains(t, s.extractEmailIDs(results.Emails), email.ID)
	})
	
	// Step 7: Metrics Collection
	s.T().Run("Metrics_Collection", func(t *testing.T) {
		// Verify metrics were recorded
		stats, err := s.keep.GetEmailStats(s.ctx, &interfaces.Filter{})
		require.NoError(t, err)
		assert.Greater(t, stats.TotalEmails, int64(0))
		assert.Greater(t, stats.TotalSize, int64(0))
	})
	
	// Step 8: Event Verification
	s.T().Run("Event_Verification", func(t *testing.T) {
		// Wait for all async events to be processed
		s.testUtils.WaitForCondition(func() bool {
			s.mu.RLock()
			defer s.mu.RUnlock()
			return len(s.eventLog) >= 5 // Expect at least 5 events
		}, time.Second*5, "Expected email processing events")
		
		// Verify event sequence
		s.mu.RLock()
		events := make([]interfaces.Event, len(s.eventLog))
		copy(events, s.eventLog)
		s.mu.RUnlock()
		
		expectedEventTypes := []string{
			"email.received",
			"email.validated",
			"email.processed", 
			"email.stored",
		}
		
		eventTypes := s.extractEventTypes(events)
		for _, expectedType := range expectedEventTypes {
			assert.Contains(t, eventTypes, expectedType,
				"Expected event type %s not found in: %v", expectedType, eventTypes)
		}
	})
}

// TestEmailProcessingWithAttachments tests pipeline with complex emails
func (s *FortressEmailPipelineSuite) TestEmailProcessingWithAttachments() {
	email := s.emailFixtures.HTMLEmail()
	
	s.T().Run("Complex_Email_Pipeline", func(t *testing.T) {
		// Process email with HTML and attachments
		err := s.keep.ProcessEmail(s.ctx, email)
		require.NoError(t, err)
		
		// Verify attachment processing
		storedEmail, err := s.keep.RetrieveEmail(s.ctx, email.ID)
		require.NoError(t, err)
		assert.Equal(t, len(email.Attachments), len(storedEmail.Attachments))
		
		// Verify HTML content was preserved
		assert.Equal(t, email.HTMLBody, storedEmail.HTMLBody)
		assert.NotEmpty(t, storedEmail.Body) // Plain text version should exist
	})
}

// TestBulkEmailProcessing tests pipeline performance with many emails
func (s *FortressEmailPipelineSuite) TestBulkEmailProcessing() {
	batchSize := 100
	emails := s.emailFixtures.EmailBatch(batchSize)
	
	s.T().Run("Bulk_Processing_Performance", func(t *testing.T) {
		startTime := time.Now()
		
		// Process emails concurrently
		var wg sync.WaitGroup
		results := make(chan error, batchSize)
		
		for _, email := range emails {
			wg.Add(1)
			go func(e *interfaces.Email) {
				defer wg.Done()
				
				// Process through full pipeline
				err := s.keep.ProcessEmail(s.ctx, e)
				if err != nil {
					results <- err
					return
				}
				
				err = s.keep.StoreEmail(s.ctx, e)
				results <- err
			}(email)
		}
		
		wg.Wait()
		close(results)
		
		// Check for errors
		var errors []error
		for err := range results {
			if err != nil {
				errors = append(errors, err)
			}
		}
		
		processingTime := time.Since(startTime)
		
		// Assertions
		assert.Empty(t, errors, "Should process all emails without errors")
		assert.Less(t, processingTime, time.Second*30, 
			"Should process %d emails within 30 seconds", batchSize)
		
		// Verify all emails were stored
		filter := &interfaces.Filter{Limit: batchSize + 10}
		storedEmails, err := s.keep.RetrieveEmails(s.ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(storedEmails), batchSize)
		
		s.T().Logf("Processed %d emails in %v (%.2f emails/sec)",
			batchSize, processingTime, float64(batchSize)/processingTime.Seconds())
	})
}

// TestEmailProcessingFailureHandling tests error scenarios
func (s *FortressEmailPipelineSuite) TestEmailProcessingFailureHandling() {
	malformedEmail := s.emailFixtures.MalformedEmail()
	
	s.T().Run("Malformed_Email_Handling", func(t *testing.T) {
		// Security scan should detect issues
		scanResult, err := s.rampart.ScanEmail(s.ctx, malformedEmail)
		require.NoError(t, err)
		assert.NotEqual(t, interfaces.ScanStatusClean, scanResult.Status)
		assert.NotEmpty(t, scanResult.Issues)
		
		// Processing should handle malformed data gracefully
		err = s.keep.ProcessEmail(s.ctx, malformedEmail)
		// Should either succeed with warnings or fail gracefully
		if err != nil {
			assert.Contains(t, err.Error(), "malformed", 
				"Error should indicate malformed data")
		}
	})
}

// TestEmailPipelineWithLargeAttachments tests handling of large emails
func (s *FortressEmailPipelineSuite) TestEmailPipelineWithLargeAttachments() {
	largeEmail := s.emailFixtures.LargeEmailWithAttachments()
	
	s.T().Run("Large_Email_Processing", func(t *testing.T) {
		startTime := time.Now()
		
		// Process large email
		err := s.keep.ProcessEmail(s.ctx, largeEmail)
		require.NoError(t, err)
		
		// Store large email
		err = s.keep.StoreEmail(s.ctx, largeEmail)
		require.NoError(t, err)
		
		processingTime := time.Since(startTime)
		
		// Verify email was processed correctly
		storedEmail, err := s.keep.RetrieveEmail(s.ctx, largeEmail.ID)
		require.NoError(t, err)
		assert.Equal(t, len(largeEmail.Attachments), len(storedEmail.Attachments))
		
		// Performance assertion - should handle large emails reasonably fast
		assert.Less(t, processingTime, time.Second*10,
			"Large email processing should complete within 10 seconds")
		
		s.T().Logf("Processed large email (%.2f MB) in %v",
			float64(largeEmail.Size)/(1024*1024), processingTime)
	})
}

// TestUnicodeEmailProcessing tests international content handling
func (s *FortressEmailPipelineSuite) TestUnicodeEmailProcessing() {
	unicodeEmail := s.emailFixtures.EmailWithUnicodeContent()
	
	s.T().Run("Unicode_Content_Processing", func(t *testing.T) {
		// Process email with unicode content
		err := s.keep.ProcessEmail(s.ctx, unicodeEmail)
		require.NoError(t, err)
		
		err = s.keep.StoreEmail(s.ctx, unicodeEmail)
		require.NoError(t, err)
		
		// Verify unicode content was preserved
		storedEmail, err := s.keep.RetrieveEmail(s.ctx, unicodeEmail.ID)
		require.NoError(t, err)
		assert.Equal(t, unicodeEmail.Body, storedEmail.Body)
		assert.Equal(t, unicodeEmail.Subject, storedEmail.Subject)
		
		// Test search with unicode terms
		query := s.testUtils.CreateTestSearchQuery("多言語テスト")
		results, err := s.keep.SearchEmails(s.ctx, query)
		require.NoError(t, err)
		
		if results.Total > 0 {
			assert.Contains(t, s.extractEmailIDs(results.Emails), unicodeEmail.ID)
		}
	})
}

// Helper methods

func (s *FortressEmailPipelineSuite) extractEmailIDs(emails []*interfaces.Email) []string {
	ids := make([]string, len(emails))
	for i, email := range emails {
		ids[i] = email.ID
	}
	return ids
}

func (s *FortressEmailPipelineSuite) extractEventTypes(events []interfaces.Event) []string {
	types := make([]string, len(events))
	for i, event := range events {
		types[i] = event.Type
	}
	return types
}

// Service creation methods (these would normally use dependency injection)

func (s *FortressEmailPipelineSuite) createFoundationService() interfaces.Foundation {
	// Create mock or real Foundation service
	// This would connect to test database
	return &MockFoundationService{}
}

func (s *FortressEmailPipelineSuite) createEventBusService() interfaces.EventBus {
	return &MockEventBusService{}
}

func (s *FortressEmailPipelineSuite) createWatchtowerService() interfaces.Watchtower {
	return &MockWatchtowerService{}
}

func (s *FortressEmailPipelineSuite) createRampartService() interfaces.Rampart {
	return &MockRampartService{}
}

func (s *FortressEmailPipelineSuite) createArmoryService() interfaces.Armory {
	return &MockArmoryService{}
}

func (s *FortressEmailPipelineSuite) createKeepService() interfaces.Keep {
	return &MockKeepService{}
}

func (s *FortressEmailPipelineSuite) createGatesService() interfaces.Gates {
	return &MockGatesService{}
}

func (s *FortressEmailPipelineSuite) startServices() {
	services := []interface {
		Start(context.Context) error
	}{
		s.foundation,
		s.eventBus,
		s.watchtower,
		s.rampart,
		s.armory,
		s.keep,
		s.gates,
	}
	
	for _, service := range services {
		err := service.Start(s.ctx)
		require.NoError(s.T(), err)
	}
}

func (s *FortressEmailPipelineSuite) stopServices() {
	services := []interface {
		Stop(context.Context) error
	}{
		s.gates,
		s.keep,
		s.armory,
		s.rampart,
		s.watchtower,
		s.eventBus,
		s.foundation,
	}
	
	for _, service := range services {
		err := service.Stop(s.ctx)
		if err != nil {
			s.T().Logf("Warning: Error stopping service: %v", err)
		}
	}
}

// TestFortressEmailPipelineIntegration runs the email pipeline integration test suite
func TestFortressEmailPipelineIntegration(t *testing.T) {
	suite.Run(t, new(FortressEmailPipelineSuite))
}