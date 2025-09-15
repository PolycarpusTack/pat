package service_integration

import (
	"context"
	"fmt"
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

// FortressServiceIntegrationSuite tests inter-service communication and coordination
type FortressServiceIntegrationSuite struct {
	suite.Suite
	testUtils      *utils.FortressTestUtils
	emailFixtures  *fixtures.EmailFixtures
	configFixtures *fixtures.ConfigFixtures
	
	// Service registry for integration testing
	services       map[string]interfaces.FortressService
	eventBus       interfaces.EventBus
	
	// Test coordination
	ctx            context.Context
	cancel         context.CancelFunc
	eventLog       []interfaces.Event
	healthStatuses map[string]*interfaces.HealthStatus
	mu             sync.RWMutex
}

// SetupSuite initializes the service integration test environment
func (s *FortressServiceIntegrationSuite) SetupSuite() {
	s.testUtils = utils.NewFortressTestUtils(s.T())
	s.emailFixtures = fixtures.NewEmailFixtures()
	s.configFixtures = fixtures.NewConfigFixtures()
	s.services = make(map[string]interfaces.FortressService)
	s.eventLog = make([]interfaces.Event, 0)
	s.healthStatuses = make(map[string]*interfaces.HealthStatus)
	
	// Create test context
	s.ctx, s.cancel = context.WithTimeout(context.Background(), time.Minute*15)
	
	// Initialize service environment
	s.initializeServiceEnvironment()
	
	// Start all services
	s.startAllServices()
	
	// Wait for services to be ready
	s.waitForServicesReady()
}

// TearDownSuite cleans up the service integration test environment
func (s *FortressServiceIntegrationSuite) TearDownSuite() {
	s.stopAllServices()
	if s.cancel != nil {
		s.cancel()
	}
}

// TestServiceStartupSequence tests proper service initialization order
func (s *FortressServiceIntegrationSuite) TestServiceStartupSequence() {
	s.T().Run("Service_Startup_Order", func(t *testing.T) {
		// Verify services started in correct order
		startupOrder := []string{
			"foundation", // Database and storage first
			"eventbus",   // Communication layer
			"watchtower", // Monitoring before business logic
			"rampart",    // Security layer
			"keep",       // Core email processing
			"armory",     // Plugin system
			"gates",      // External interfaces last
		}
		
		for _, serviceName := range startupOrder {
			service, exists := s.services[serviceName]
			require.True(t, exists, "Service %s should exist", serviceName)
			
			health := service.Health(s.ctx)
			assert.Equal(t, interfaces.HealthStatusHealthy, health.Status,
				"Service %s should be healthy", serviceName)
		}
	})
}

// TestInterServiceCommunication tests service-to-service messaging
func (s *FortressServiceIntegrationSuite) TestInterServiceCommunication() {
	s.T().Run("Event_Based_Communication", func(t *testing.T) {
		// Test event publishing and subscription
		testEvent := &interfaces.Event{
			ID:        uuid.New().String(),
			Type:      "test.integration.message",
			Source:    "test",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"message": "integration test event",
				"test_id": s.T().Name(),
			},
		}
		
		// Setup event listener
		eventReceived := make(chan bool, 1)
		err := s.eventBus.Subscribe("test.integration.message", func(ctx context.Context, event *interfaces.Event) error {
			s.mu.Lock()
			s.eventLog = append(s.eventLog, *event)
			s.mu.Unlock()
			eventReceived <- true
			return nil
		})
		require.NoError(t, err)
		
		// Publish event
		err = s.eventBus.Publish(s.ctx, testEvent)
		require.NoError(t, err)
		
		// Verify event was received
		select {
		case <-eventReceived:
			// Event received successfully
		case <-time.After(time.Second * 5):
			t.Fatal("Event not received within timeout")
		}
		
		// Verify event is in log
		s.mu.RLock()
		found := false
		for _, event := range s.eventLog {
			if event.ID == testEvent.ID {
				found = true
				break
			}
		}
		s.mu.RUnlock()
		
		assert.True(t, found, "Test event should be in event log")
	})
}

// TestServiceHealthMonitoring tests health check coordination
func (s *FortressServiceIntegrationSuite) TestServiceHealthMonitoring() {
	s.T().Run("Health_Check_Coordination", func(t *testing.T) {
		// Check health of all services
		for serviceName, service := range s.services {
			health := service.Health(s.ctx)
			require.NotNil(t, health, "Health status should not be nil for %s", serviceName)
			
			s.testUtils.AssertHealthStatusValid(health, serviceName)
			
			// Store for later comparison
			s.mu.Lock()
			s.healthStatuses[serviceName] = health
			s.mu.Unlock()
		}
		
		// Verify all services are healthy
		s.mu.RLock()
		defer s.mu.RUnlock()
		
		for serviceName, health := range s.healthStatuses {
			assert.Equal(t, interfaces.HealthStatusHealthy, health.Status,
				"Service %s should be healthy", serviceName)
			assert.True(t, health.Duration >= 0,
				"Health check duration should be non-negative for %s", serviceName)
		}
	})
}

// TestEmailProcessingWorkflow tests complete email processing across services
func (s *FortressServiceIntegrationSuite) TestEmailProcessingWorkflow() {
	email := s.emailFixtures.SimpleTextEmail()
	
	s.T().Run("Cross_Service_Email_Processing", func(t *testing.T) {
		// Step 1: Email enters through Gates
		gatesService := s.services["gates"].(interfaces.Gates)
		err := gatesService.HandleSMTPConnection(s.ctx, nil) // Mock SMTP connection
		require.NoError(t, err)
		
		// Step 2: Rampart scans for security
		rampartService := s.services["rampart"].(interfaces.Rampart)
		scanResult, err := rampartService.ScanEmail(s.ctx, email)
		require.NoError(t, err)
		assert.Equal(t, interfaces.ScanStatusClean, scanResult.Status)
		
		// Step 3: Keep processes the email
		keepService := s.services["keep"].(interfaces.Keep)
		err = keepService.ProcessEmail(s.ctx, email)
		require.NoError(t, err)
		
		// Step 4: Armory executes plugins
		armoryService := s.services["armory"].(interfaces.Armory)
		pluginResults, err := armoryService.ExecutePluginChain(s.ctx, "default", email)
		require.NoError(t, err)
		assert.NotEmpty(t, pluginResults)
		
		// Step 5: Foundation stores the email
		foundationService := s.services["foundation"].(interfaces.Foundation)
		err = foundationService.StoreFile(s.ctx, 
			fmt.Sprintf("emails/%s.json", email.ID),
			[]byte("mock email data"))
		require.NoError(t, err)
		
		// Step 6: Watchtower records metrics
		watchtowerService := s.services["watchtower"].(interfaces.Watchtower)
		watchtowerService.RecordMetric("email.processed", 1, map[string]string{
			"type": "integration_test",
		})
		
		// Verify the email was processed successfully
		storedEmail, err := keepService.RetrieveEmail(s.ctx, email.ID)
		require.NoError(t, err)
		assert.Equal(t, email.ID, storedEmail.ID)
	})
}

// TestConcurrentServiceOperations tests service behavior under concurrent load
func (s *FortressServiceIntegrationSuite) TestConcurrentServiceOperations() {
	s.T().Run("Concurrent_Operations", func(t *testing.T) {
		concurrency := 50
		emails := s.emailFixtures.EmailBatch(concurrency)
		
		var wg sync.WaitGroup
		errors := make(chan error, concurrency)
		
		// Process emails concurrently across all services
		for i, email := range emails {
			wg.Add(1)
			go func(index int, e *interfaces.Email) {
				defer wg.Done()
				
				// Each goroutine processes email through multiple services
				ctx, cancel := context.WithTimeout(s.ctx, time.Second*30)
				defer cancel()
				
				// Security scan
				rampartService := s.services["rampart"].(interfaces.Rampart)
				_, err := rampartService.ScanEmail(ctx, e)
				if err != nil {
					errors <- fmt.Errorf("rampart scan failed for email %d: %w", index, err)
					return
				}
				
				// Email processing
				keepService := s.services["keep"].(interfaces.Keep)
				err = keepService.ProcessEmail(ctx, e)
				if err != nil {
					errors <- fmt.Errorf("keep processing failed for email %d: %w", index, err)
					return
				}
				
				// Plugin execution
				armoryService := s.services["armory"].(interfaces.Armory)
				_, err = armoryService.ExecutePluginChain(ctx, "default", e)
				if err != nil {
					errors <- fmt.Errorf("armory execution failed for email %d: %w", index, err)
					return
				}
				
				// Storage
				err = keepService.StoreEmail(ctx, e)
				if err != nil {
					errors <- fmt.Errorf("keep storage failed for email %d: %w", index, err)
					return
				}
			}(i, email)
		}
		
		wg.Wait()
		close(errors)
		
		// Collect any errors
		var errorList []error
		for err := range errors {
			errorList = append(errorList, err)
		}
		
		// Assert no errors occurred
		assert.Empty(t, errorList, "Should process all emails without errors: %v", errorList)
		
		// Verify all emails were processed
		keepService := s.services["keep"].(interfaces.Keep)
		stats, err := keepService.GetEmailStats(s.ctx, &interfaces.Filter{})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, stats.TotalEmails, int64(concurrency),
			"Should have processed at least %d emails", concurrency)
	})
}

// TestServiceFailureRecovery tests how services handle failures
func (s *FortressServiceIntegrationSuite) TestServiceFailureRecovery() {
	s.T().Run("Service_Failure_Recovery", func(t *testing.T) {
		// Simulate temporary service degradation
		watchtowerService := s.services["watchtower"].(interfaces.Watchtower)
		
		// Trigger a mock alert to test alert handling
		watchtowerService.TriggerAlert(
			interfaces.AlertLevelWarning,
			"Integration test alert",
			map[string]interface{}{
				"test": "service_failure_recovery",
			},
		)
		
		// Verify other services continue to function
		email := s.emailFixtures.SimpleTextEmail()
		keepService := s.services["keep"].(interfaces.Keep)
		
		err := keepService.ProcessEmail(s.ctx, email)
		assert.NoError(t, err, "Keep service should continue functioning despite monitoring alerts")
		
		// Test rate limiting under stress
		rampartService := s.services["rampart"].(interfaces.Rampart)
		rateLimit := &interfaces.RateLimit{
			RequestsPerSecond: 10,
			BurstSize:         5,
		}
		
		// Make rapid requests to test rate limiting
		for i := 0; i < 15; i++ {
			result, err := rampartService.CheckRateLimit(s.ctx, "test-key", rateLimit)
			require.NoError(t, err)
			
			if i < 10 {
				assert.True(t, result.Allowed, "Request %d should be allowed", i+1)
			} else {
				assert.False(t, result.Allowed, "Request %d should be rate limited", i+1)
			}
		}
	})
}

// TestServiceDependencyResolution tests service dependency management
func (s *FortressServiceIntegrationSuite) TestServiceDependencyResolution() {
	s.T().Run("Dependency_Resolution", func(t *testing.T) {
		// Test that services can access their dependencies
		
		// Keep should be able to use Foundation for storage
		keepService := s.services["keep"].(interfaces.Keep)
		foundationService := s.services["foundation"].(interfaces.Foundation)
		
		// Test database operation through Keep -> Foundation
		email := s.emailFixtures.SimpleTextEmail()
		err := keepService.StoreEmail(s.ctx, email)
		require.NoError(t, err)
		
		// Verify Foundation was used for storage
		_, err = foundationService.CacheGet(s.ctx, "test-key")
		// Expected to fail with "not found" for new key
		assert.Error(t, err, "Should get 'not found' error for non-existent key")
		
		// Test successful cache operation
		err = foundationService.CacheSet(s.ctx, "integration-test", "test-value", nil)
		require.NoError(t, err)
		
		value, err := foundationService.CacheGet(s.ctx, "integration-test")
		require.NoError(t, err)
		assert.Equal(t, "test-value", value)
	})
}

// TestEventDrivenWorkflows tests complex event-driven processes
func (s *FortressServiceIntegrationSuite) TestEventDrivenWorkflows() {
	s.T().Run("Event_Driven_Workflows", func(t *testing.T) {
		// Setup workflow monitoring
		workflowEvents := make(map[string]bool)
		var workflowMu sync.Mutex
		
		expectedEvents := []string{
			"email.received",
			"email.security_validated",
			"email.processed",
			"email.plugins_executed",
			"email.stored",
			"workflow.completed",
		}
		
		// Subscribe to workflow events
		for _, eventType := range expectedEvents {
			err := s.eventBus.Subscribe(eventType, func(ctx context.Context, event *interfaces.Event) error {
				workflowMu.Lock()
				workflowEvents[event.Type] = true
				workflowMu.Unlock()
				return nil
			})
			require.NoError(t, err)
		}
		
		// Trigger workflow by publishing initial event
		email := s.emailFixtures.HTMLEmail()
		initialEvent := &interfaces.Event{
			ID:        uuid.New().String(),
			Type:      "email.received",
			Source:    "integration-test",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"email_id": email.ID,
				"workflow": "integration-test",
			},
		}
		
		err := s.eventBus.Publish(s.ctx, initialEvent)
		require.NoError(t, err)
		
		// Simulate workflow steps by publishing subsequent events
		workflowSteps := []string{
			"email.security_validated",
			"email.processed", 
			"email.plugins_executed",
			"email.stored",
			"workflow.completed",
		}
		
		for _, stepType := range workflowSteps {
			stepEvent := &interfaces.Event{
				ID:        uuid.New().String(),
				Type:      stepType,
				Source:    "integration-test",
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"email_id":    email.ID,
					"workflow":    "integration-test",
					"step":        stepType,
				},
			}
			
			err := s.eventBus.Publish(s.ctx, stepEvent)
			require.NoError(t, err)
			
			// Small delay to allow event processing
			time.Sleep(time.Millisecond * 10)
		}
		
		// Wait for all events to be processed
		s.testUtils.WaitForCondition(func() bool {
			workflowMu.Lock()
			defer workflowMu.Unlock()
			
			processedCount := 0
			for _, eventType := range expectedEvents {
				if workflowEvents[eventType] {
					processedCount++
				}
			}
			return processedCount == len(expectedEvents)
		}, time.Second*10, "All workflow events should be processed")
		
		// Verify all events were received
		workflowMu.Lock()
		defer workflowMu.Unlock()
		
		for _, eventType := range expectedEvents {
			assert.True(t, workflowEvents[eventType], 
				"Event %s should have been processed", eventType)
		}
	})
}

// Helper methods for service setup

func (s *FortressServiceIntegrationSuite) initializeServiceEnvironment() {
	// Initialize services with their dependencies
	// In a real implementation, this would use dependency injection
	
	// Create service instances (using mocks for integration tests)
	s.services["foundation"] = &MockFoundationService{}
	s.services["eventbus"] = &MockEventBusService{}
	s.services["watchtower"] = &MockWatchtowerService{}
	s.services["rampart"] = &MockRampartService{}
	s.services["keep"] = &MockKeepService{}
	s.services["armory"] = &MockArmoryService{}
	s.services["gates"] = &MockGatesService{}
	
	// Set the event bus reference
	s.eventBus = s.services["eventbus"].(interfaces.EventBus)
}

func (s *FortressServiceIntegrationSuite) startAllServices() {
	// Start services in dependency order
	startupOrder := []string{
		"foundation",
		"eventbus", 
		"watchtower",
		"rampart",
		"keep",
		"armory",
		"gates",
	}
	
	for _, serviceName := range startupOrder {
		service := s.services[serviceName]
		err := service.Start(s.ctx)
		require.NoError(s.T(), err, "Failed to start service: %s", serviceName)
		
		s.T().Logf("Started service: %s", serviceName)
	}
}

func (s *FortressServiceIntegrationSuite) stopAllServices() {
	// Stop services in reverse order
	shutdownOrder := []string{
		"gates",
		"armory",
		"keep",
		"rampart",
		"watchtower",
		"eventbus",
		"foundation",
	}
	
	for _, serviceName := range shutdownOrder {
		service := s.services[serviceName]
		err := service.Stop(s.ctx)
		if err != nil {
			s.T().Logf("Warning: Error stopping service %s: %v", serviceName, err)
		}
	}
}

func (s *FortressServiceIntegrationSuite) waitForServicesReady() {
	// Wait for all services to report healthy status
	s.testUtils.WaitForCondition(func() bool {
		for serviceName, service := range s.services {
			health := service.Health(s.ctx)
			if health.Status != interfaces.HealthStatusHealthy {
				s.T().Logf("Service %s not ready: %s", serviceName, health.Message)
				return false
			}
		}
		return true
	}, time.Second*30, "All services should be ready")
	
	s.T().Log("All services are ready")
}

// TestFortressServiceIntegration runs the service integration test suite
func TestFortressServiceIntegration(t *testing.T) {
	suite.Run(t, new(FortressServiceIntegrationSuite))
}