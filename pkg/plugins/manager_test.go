package plugins

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// PluginManagerTestSuite provides comprehensive test coverage for the plugin manager
type PluginManagerTestSuite struct {
	suite.Suite
	manager         *Manager
	mockRegistry    *MockRegistry
	mockRuntime     *MockPluginRuntime
	mockSecurity    *MockSecurityScanner
	mockEventBus    *MockEventBus
	mockMetrics     *MockMetricsCollector
	mockLogger      *MockLogger
	testContext     context.Context
	testTenantID    string
}

// Mock implementations for testing

type MockRegistry struct {
	mock.Mock
}

func (m *MockRegistry) Register(plugin *Plugin) error {
	args := m.Called(plugin)
	return args.Error(0)
}

func (m *MockRegistry) GetPlugin(id string) (*Plugin, error) {
	args := m.Called(id)
	return args.Get(0).(*Plugin), args.Error(1)
}

func (m *MockRegistry) ListPlugins() []*Plugin {
	args := m.Called()
	return args.Get(0).([]*Plugin)
}

func (m *MockRegistry) RemovePlugin(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

type MockPluginRuntime struct {
	mock.Mock
}

func (m *MockPluginRuntime) LoadPlugin(plugin *Plugin) (*PluginInstance, error) {
	args := m.Called(plugin)
	return args.Get(0).(*PluginInstance), args.Error(1)
}

func (m *MockPluginRuntime) ExecuteHook(instance *PluginInstance, hook string, data interface{}) (interface{}, error) {
	args := m.Called(instance, hook, data)
	return args.Get(0), args.Error(1)
}

func (m *MockPluginRuntime) UnloadPlugin(instanceID string) error {
	args := m.Called(instanceID)
	return args.Error(0)
}

type MockSecurityScanner struct {
	mock.Mock
}

func (m *MockSecurityScanner) ScanPlugin(plugin *Plugin) (*SecurityReport, error) {
	args := m.Called(plugin)
	return args.Get(0).(*SecurityReport), args.Error(1)
}

type MockEventBus struct {
	mock.Mock
}

func (m *MockEventBus) Publish(event *Event) error {
	args := m.Called(event)
	return args.Error(0)
}

func (m *MockEventBus) Subscribe(eventType string, handler EventHandler) error {
	args := m.Called(eventType, handler)
	return args.Error(0)
}

type MockMetricsCollector struct {
	mock.Mock
}

func (m *MockMetricsCollector) RecordPluginExecution(pluginID string, duration time.Duration, success bool) {
	m.Called(pluginID, duration, success)
}

func (m *MockMetricsCollector) RecordPluginLoad(pluginID string, success bool) {
	m.Called(pluginID, success)
}

type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Info(msg string, fields ...interface{}) {
	m.Called(msg, fields)
}

func (m *MockLogger) Error(msg string, err error, fields ...interface{}) {
	m.Called(msg, err, fields)
}

func (m *MockLogger) Debug(msg string, fields ...interface{}) {
	m.Called(msg, fields)
}

func (m *MockLogger) Warn(msg string, fields ...interface{}) {
	m.Called(msg, fields)
}

// SetupTest initializes test environment before each test
func (suite *PluginManagerTestSuite) SetupTest() {
	suite.mockRegistry = new(MockRegistry)
	suite.mockRuntime = new(MockPluginRuntime)
	suite.mockSecurity = new(MockSecurityScanner)
	suite.mockEventBus = new(MockEventBus)
	suite.mockMetrics = new(MockMetricsCollector)
	suite.mockLogger = new(MockLogger)
	
	suite.testContext = context.Background()
	suite.testTenantID = "test-tenant-123"
	
	config := &ManagerConfig{
		MaxConcurrentExecutions: 10,
		ExecutionTimeout:        30 * time.Second,
		MaxPluginsPerTenant:     5,
		EnableSandbox:           true,
		EnableMetrics:           true,
		MemoryLimitMB:          128,
		CPUTimeLimitMS:         1000,
	}
	
	suite.manager = &Manager{
		registry:  suite.mockRegistry,
		runtime:   suite.mockRuntime,
		security:  suite.mockSecurity,
		eventBus:  suite.mockEventBus,
		metrics:   suite.mockMetrics,
		logger:    suite.mockLogger,
		instances: make(map[string]*PluginInstance),
		hooks:     make(map[string][]string),
		config:    config,
	}
}

// TearDownTest cleans up after each test
func (suite *PluginManagerTestSuite) TearDownTest() {
	// Assert all expectations were met
	suite.mockRegistry.AssertExpectations(suite.T())
	suite.mockRuntime.AssertExpectations(suite.T())
	suite.mockSecurity.AssertExpectations(suite.T())
	suite.mockEventBus.AssertExpectations(suite.T())
	suite.mockMetrics.AssertExpectations(suite.T())
	suite.mockLogger.AssertExpectations(suite.T())
}

// Test LoadPlugin functionality
func (suite *PluginManagerTestSuite) TestLoadPlugin_Success() {
	t := suite.T()
	
	// Arrange
	plugin := &Plugin{
		ID:       "test-plugin",
		Name:     "Test Plugin",
		Version:  "1.0.0",
		TenantID: suite.testTenantID,
		Hooks:    []string{"email_received", "email_validated"},
	}
	
	expectedInstance := &PluginInstance{
		ID:       uuid.New().String(),
		TenantID: suite.testTenantID,
		PluginID: plugin.ID,
		Status:   StatusLoaded,
		LoadedAt: time.Now(),
	}
	
	securityReport := &SecurityReport{
		Safe:        true,
		Issues:      []SecurityIssue{},
		RiskScore:   0.1,
		ScannedAt:   time.Now(),
	}
	
	// Set up expectations
	suite.mockSecurity.On("ScanPlugin", plugin).Return(securityReport, nil)
	suite.mockRuntime.On("LoadPlugin", plugin).Return(expectedInstance, nil)
	suite.mockEventBus.On("Publish", mock.AnythingOfType("*plugins.Event")).Return(nil)
	suite.mockMetrics.On("RecordPluginLoad", plugin.ID, true)
	suite.mockLogger.On("Info", mock.AnythingOfType("string"), mock.Anything)
	
	// Act
	instance, err := suite.manager.LoadPlugin(suite.testContext, plugin)
	
	// Assert
	require.NoError(t, err)
	assert.NotNil(t, instance)
	assert.Equal(t, expectedInstance.ID, instance.ID)
	assert.Equal(t, plugin.ID, instance.PluginID)
	assert.Equal(t, suite.testTenantID, instance.TenantID)
	assert.Equal(t, StatusLoaded, instance.Status)
	
	// Verify plugin is registered in instances
	suite.manager.instancesMu.RLock()
	registeredInstance, exists := suite.manager.instances[instance.ID]
	suite.manager.instancesMu.RUnlock()
	
	assert.True(t, exists)
	assert.Equal(t, instance.ID, registeredInstance.ID)
	
	// Verify hooks are registered
	suite.manager.hooksMu.RLock()
	for _, hook := range plugin.Hooks {
		plugins, exists := suite.manager.hooks[hook]
		assert.True(t, exists, "Hook %s should be registered", hook)
		assert.Contains(t, plugins, instance.ID)
	}
	suite.manager.hooksMu.RUnlock()
}

func (suite *PluginManagerTestSuite) TestLoadPlugin_SecurityScanFailed() {
	t := suite.T()
	
	// Arrange
	plugin := &Plugin{
		ID:       "malicious-plugin",
		Name:     "Malicious Plugin",
		Version:  "1.0.0",
		TenantID: suite.testTenantID,
	}
	
	securityReport := &SecurityReport{
		Safe: false,
		Issues: []SecurityIssue{
			{
				Type:        "malicious_code",
				Severity:    "critical",
				Description: "Detected potential malicious code execution",
			},
		},
		RiskScore: 0.9,
		ScannedAt: time.Now(),
	}
	
	// Set up expectations
	suite.mockSecurity.On("ScanPlugin", plugin).Return(securityReport, nil)
	suite.mockMetrics.On("RecordPluginLoad", plugin.ID, false)
	suite.mockLogger.On("Error", mock.AnythingOfType("string"), mock.AnythingOfType("error"), mock.Anything)
	
	// Act
	instance, err := suite.manager.LoadPlugin(suite.testContext, plugin)
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, instance)
	assert.Contains(t, err.Error(), "security scan failed")
}

func (suite *PluginManagerTestSuite) TestLoadPlugin_MaxPluginsExceeded() {
	t := suite.T()
	
	// Arrange - Load plugins up to the limit
	suite.manager.config.MaxPluginsPerTenant = 2
	
	for i := 0; i < 2; i++ {
		instance := &PluginInstance{
			ID:       uuid.New().String(),
			TenantID: suite.testTenantID,
			PluginID: fmt.Sprintf("existing-plugin-%d", i),
			Status:   StatusLoaded,
		}
		suite.manager.instances[instance.ID] = instance
	}
	
	plugin := &Plugin{
		ID:       "new-plugin",
		Name:     "New Plugin",
		Version:  "1.0.0",
		TenantID: suite.testTenantID,
	}
	
	suite.mockLogger.On("Error", mock.AnythingOfType("string"), mock.AnythingOfType("error"), mock.Anything)
	
	// Act
	instance, err := suite.manager.LoadPlugin(suite.testContext, plugin)
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, instance)
	assert.Contains(t, err.Error(), "maximum plugins exceeded")
}

// Test ExecuteHook functionality
func (suite *PluginManagerTestSuite) TestExecuteHook_Success() {
	t := suite.T()
	
	// Arrange
	hookName := "email_received"
	hookData := map[string]interface{}{
		"email_id": "test-email-123",
		"from":     "sender@example.com",
		"to":       []string{"recipient@example.com"},
	}
	
	instance := &PluginInstance{
		ID:       uuid.New().String(),
		TenantID: suite.testTenantID,
		PluginID: "test-plugin",
		Status:   StatusLoaded,
		LoadedAt: time.Now(),
	}
	
	suite.manager.instances[instance.ID] = instance
	suite.manager.hooks[hookName] = []string{instance.ID}
	
	expectedResult := map[string]interface{}{
		"processed": true,
		"action":    "accept",
	}
	
	// Set up expectations
	suite.mockRuntime.On("ExecuteHook", instance, hookName, hookData).Return(expectedResult, nil)
	suite.mockEventBus.On("Publish", mock.AnythingOfType("*plugins.Event")).Return(nil)
	suite.mockMetrics.On("RecordPluginExecution", instance.PluginID, mock.AnythingOfType("time.Duration"), true)
	suite.mockLogger.On("Debug", mock.AnythingOfType("string"), mock.Anything)
	
	// Act
	results, err := suite.manager.ExecuteHook(suite.testContext, hookName, hookData)
	
	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, expectedResult, results[0].Result)
	assert.Equal(t, instance.ID, results[0].InstanceID)
	assert.True(t, results[0].Success)
}

func (suite *PluginManagerTestSuite) TestExecuteHook_NoPlugins() {
	t := suite.T()
	
	// Arrange
	hookName := "non_existent_hook"
	hookData := map[string]interface{}{}
	
	suite.mockLogger.On("Debug", mock.AnythingOfType("string"), mock.Anything)
	
	// Act
	results, err := suite.manager.ExecuteHook(suite.testContext, hookName, hookData)
	
	// Assert
	require.NoError(t, err)
	assert.Empty(t, results)
}

func (suite *PluginManagerTestSuite) TestExecuteHook_PluginExecutionFailed() {
	t := suite.T()
	
	// Arrange
	hookName := "email_received"
	hookData := map[string]interface{}{"test": "data"}
	
	instance := &PluginInstance{
		ID:       uuid.New().String(),
		TenantID: suite.testTenantID,
		PluginID: "failing-plugin",
		Status:   StatusLoaded,
	}
	
	suite.manager.instances[instance.ID] = instance
	suite.manager.hooks[hookName] = []string{instance.ID}
	
	executionError := fmt.Errorf("plugin execution failed")
	
	// Set up expectations
	suite.mockRuntime.On("ExecuteHook", instance, hookName, hookData).Return(nil, executionError)
	suite.mockEventBus.On("Publish", mock.AnythingOfType("*plugins.Event")).Return(nil)
	suite.mockMetrics.On("RecordPluginExecution", instance.PluginID, mock.AnythingOfType("time.Duration"), false)
	suite.mockLogger.On("Error", mock.AnythingOfType("string"), mock.AnythingOfType("error"), mock.Anything)
	
	// Act
	results, err := suite.manager.ExecuteHook(suite.testContext, hookName, hookData)
	
	// Assert
	require.NoError(t, err) // Manager doesn't fail on individual plugin failures
	assert.Len(t, results, 1)
	assert.False(t, results[0].Success)
	assert.Equal(t, executionError.Error(), results[0].Error)
}

// Test UnloadPlugin functionality
func (suite *PluginManagerTestSuite) TestUnloadPlugin_Success() {
	t := suite.T()
	
	// Arrange
	instance := &PluginInstance{
		ID:       uuid.New().String(),
		TenantID: suite.testTenantID,
		PluginID: "test-plugin",
		Status:   StatusLoaded,
		LoadedAt: time.Now(),
	}
	
	suite.manager.instances[instance.ID] = instance
	suite.manager.hooks["email_received"] = []string{instance.ID}
	
	// Set up expectations
	suite.mockRuntime.On("UnloadPlugin", instance.ID).Return(nil)
	suite.mockEventBus.On("Publish", mock.AnythingOfType("*plugins.Event")).Return(nil)
	suite.mockLogger.On("Info", mock.AnythingOfType("string"), mock.Anything)
	
	// Act
	err := suite.manager.UnloadPlugin(suite.testContext, instance.ID)
	
	// Assert
	require.NoError(t, err)
	
	// Verify plugin is removed from instances
	suite.manager.instancesMu.RLock()
	_, exists := suite.manager.instances[instance.ID]
	suite.manager.instancesMu.RUnlock()
	assert.False(t, exists)
	
	// Verify hooks are unregistered
	suite.manager.hooksMu.RLock()
	plugins := suite.manager.hooks["email_received"]
	suite.manager.hooksMu.RUnlock()
	assert.NotContains(t, plugins, instance.ID)
}

func (suite *PluginManagerTestSuite) TestUnloadPlugin_NotFound() {
	t := suite.T()
	
	// Arrange
	nonExistentID := uuid.New().String()
	
	suite.mockLogger.On("Error", mock.AnythingOfType("string"), mock.AnythingOfType("error"), mock.Anything)
	
	// Act
	err := suite.manager.UnloadPlugin(suite.testContext, nonExistentID)
	
	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "plugin instance not found")
}

// Test concurrent operations
func (suite *PluginManagerTestSuite) TestConcurrentOperations() {
	t := suite.T()
	
	// Arrange
	numPlugins := 10
	plugins := make([]*Plugin, numPlugins)
	instances := make([]*PluginInstance, numPlugins)
	
	for i := 0; i < numPlugins; i++ {
		plugins[i] = &Plugin{
			ID:       fmt.Sprintf("plugin-%d", i),
			Name:     fmt.Sprintf("Plugin %d", i),
			Version:  "1.0.0",
			TenantID: suite.testTenantID,
			Hooks:    []string{"test_hook"},
		}
		
		instances[i] = &PluginInstance{
			ID:       uuid.New().String(),
			TenantID: suite.testTenantID,
			PluginID: plugins[i].ID,
			Status:   StatusLoaded,
			LoadedAt: time.Now(),
		}
	}
	
	// Set up expectations for all operations
	for i := 0; i < numPlugins; i++ {
		securityReport := &SecurityReport{Safe: true, Issues: []SecurityIssue{}, RiskScore: 0.1}
		
		suite.mockSecurity.On("ScanPlugin", plugins[i]).Return(securityReport, nil)
		suite.mockRuntime.On("LoadPlugin", plugins[i]).Return(instances[i], nil)
		suite.mockRuntime.On("UnloadPlugin", instances[i].ID).Return(nil)
		suite.mockEventBus.On("Publish", mock.AnythingOfType("*plugins.Event")).Return(nil)
		suite.mockMetrics.On("RecordPluginLoad", plugins[i].ID, true)
	}
	
	suite.mockLogger.On("Info", mock.AnythingOfType("string"), mock.Anything).Maybe()
	suite.mockLogger.On("Debug", mock.AnythingOfType("string"), mock.Anything).Maybe()
	
	// Act - Load plugins concurrently
	var wg sync.WaitGroup
	errors := make([]error, numPlugins)
	loadedInstances := make([]*PluginInstance, numPlugins)
	
	for i := 0; i < numPlugins; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			var err error
			loadedInstances[index], err = suite.manager.LoadPlugin(suite.testContext, plugins[index])
			errors[index] = err
		}(i)
	}
	
	wg.Wait()
	
	// Assert all loads succeeded
	for i := 0; i < numPlugins; i++ {
		assert.NoError(t, errors[i], "Plugin %d load should succeed", i)
		assert.NotNil(t, loadedInstances[i], "Plugin %d instance should not be nil", i)
	}
	
	// Verify all instances are registered
	suite.manager.instancesMu.RLock()
	assert.Equal(t, numPlugins, len(suite.manager.instances))
	suite.manager.instancesMu.RUnlock()
	
	// Act - Unload plugins concurrently
	for i := 0; i < numPlugins; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			errors[index] = suite.manager.UnloadPlugin(suite.testContext, loadedInstances[index].ID)
		}(i)
	}
	
	wg.Wait()
	
	// Assert all unloads succeeded
	for i := 0; i < numPlugins; i++ {
		assert.NoError(t, errors[i], "Plugin %d unload should succeed", i)
	}
	
	// Verify all instances are removed
	suite.manager.instancesMu.RLock()
	assert.Equal(t, 0, len(suite.manager.instances))
	suite.manager.instancesMu.RUnlock()
}

// Test plugin execution timeout
func (suite *PluginManagerTestSuite) TestExecuteHook_Timeout() {
	t := suite.T()
	
	// Arrange
	suite.manager.config.ExecutionTimeout = 100 * time.Millisecond
	
	instance := &PluginInstance{
		ID:       uuid.New().String(),
		TenantID: suite.testTenantID,
		PluginID: "slow-plugin",
		Status:   StatusLoaded,
	}
	
	suite.manager.instances[instance.ID] = instance
	suite.manager.hooks["slow_hook"] = []string{instance.ID}
	
	// Mock a slow execution that exceeds timeout
	suite.mockRuntime.On("ExecuteHook", instance, "slow_hook", mock.Anything).Return(
		func(instance *PluginInstance, hook string, data interface{}) interface{} {
			time.Sleep(200 * time.Millisecond) // Longer than timeout
			return map[string]interface{}{"result": "slow"}
		},
		func(instance *PluginInstance, hook string, data interface{}) error {
			time.Sleep(200 * time.Millisecond)
			return nil
		},
	)
	
	suite.mockEventBus.On("Publish", mock.AnythingOfType("*plugins.Event")).Return(nil)
	suite.mockMetrics.On("RecordPluginExecution", instance.PluginID, mock.AnythingOfType("time.Duration"), false)
	suite.mockLogger.On("Error", mock.AnythingOfType("string"), mock.AnythingOfType("error"), mock.Anything)
	
	// Act
	results, err := suite.manager.ExecuteHook(suite.testContext, "slow_hook", map[string]interface{}{})
	
	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.False(t, results[0].Success)
	assert.Contains(t, results[0].Error, "timeout")
}

// Test metrics collection
func (suite *PluginManagerTestSuite) TestMetricsCollection() {
	t := suite.T()
	
	// Arrange
	plugin := &Plugin{
		ID:       "metrics-test-plugin",
		Name:     "Metrics Test Plugin",
		Version:  "1.0.0",
		TenantID: suite.testTenantID,
		Hooks:    []string{"test_hook"},
	}
	
	instance := &PluginInstance{
		ID:       uuid.New().String(),
		TenantID: suite.testTenantID,
		PluginID: plugin.ID,
		Status:   StatusLoaded,
		LoadedAt: time.Now(),
	}
	
	securityReport := &SecurityReport{Safe: true, Issues: []SecurityIssue{}, RiskScore: 0.1}
	
	// Set up expectations for load
	suite.mockSecurity.On("ScanPlugin", plugin).Return(securityReport, nil)
	suite.mockRuntime.On("LoadPlugin", plugin).Return(instance, nil)
	suite.mockEventBus.On("Publish", mock.AnythingOfType("*plugins.Event")).Return(nil)
	suite.mockMetrics.On("RecordPluginLoad", plugin.ID, true)
	suite.mockLogger.On("Info", mock.AnythingOfType("string"), mock.Anything)
	
	// Set up expectations for execution
	suite.mockRuntime.On("ExecuteHook", instance, "test_hook", mock.Anything).Return(
		map[string]interface{}{"success": true}, nil)
	suite.mockMetrics.On("RecordPluginExecution", plugin.ID, mock.AnythingOfType("time.Duration"), true)
	suite.mockLogger.On("Debug", mock.AnythingOfType("string"), mock.Anything)
	
	// Act
	loadedInstance, err := suite.manager.LoadPlugin(suite.testContext, plugin)
	require.NoError(t, err)
	
	_, err = suite.manager.ExecuteHook(suite.testContext, "test_hook", map[string]interface{}{})
	require.NoError(t, err)
	
	// Assert - Verify metrics were recorded
	suite.mockMetrics.AssertCalled(t, "RecordPluginLoad", plugin.ID, true)
	suite.mockMetrics.AssertCalled(t, "RecordPluginExecution", plugin.ID, mock.AnythingOfType("time.Duration"), true)
}

// Test plugin lifecycle events
func (suite *PluginManagerTestSuite) TestPluginLifecycleEvents() {
	t := suite.T()
	
	// Arrange
	plugin := &Plugin{
		ID:       "lifecycle-test-plugin",
		Name:     "Lifecycle Test Plugin",
		Version:  "1.0.0",
		TenantID: suite.testTenantID,
	}
	
	instance := &PluginInstance{
		ID:       uuid.New().String(),
		TenantID: suite.testTenantID,
		PluginID: plugin.ID,
		Status:   StatusLoaded,
		LoadedAt: time.Now(),
	}
	
	securityReport := &SecurityReport{Safe: true, Issues: []SecurityIssue{}, RiskScore: 0.1}
	
	// Set up expectations
	suite.mockSecurity.On("ScanPlugin", plugin).Return(securityReport, nil)
	suite.mockRuntime.On("LoadPlugin", plugin).Return(instance, nil)
	suite.mockRuntime.On("UnloadPlugin", instance.ID).Return(nil)
	suite.mockMetrics.On("RecordPluginLoad", plugin.ID, true)
	suite.mockLogger.On("Info", mock.AnythingOfType("string"), mock.Anything)
	
	// Expect lifecycle events
	suite.mockEventBus.On("Publish", mock.MatchedBy(func(event *Event) bool {
		return event.Type == "plugin.loaded" && event.PluginID == plugin.ID
	})).Return(nil)
	
	suite.mockEventBus.On("Publish", mock.MatchedBy(func(event *Event) bool {
		return event.Type == "plugin.unloaded" && event.InstanceID == instance.ID
	})).Return(nil)
	
	// Act
	loadedInstance, err := suite.manager.LoadPlugin(suite.testContext, plugin)
	require.NoError(t, err)
	
	err = suite.manager.UnloadPlugin(suite.testContext, loadedInstance.ID)
	require.NoError(t, err)
	
	// Assert - Events are verified in the mock expectations
}

// Run the test suite
func TestPluginManagerSuite(t *testing.T) {
	suite.Run(t, new(PluginManagerTestSuite))
}

// Benchmark tests for performance validation
func BenchmarkPluginManager_LoadPlugin(b *testing.B) {
	// Setup
	manager := setupBenchmarkManager()
	plugin := &Plugin{
		ID:       "benchmark-plugin",
		Name:     "Benchmark Plugin",
		Version:  "1.0.0",
		TenantID: "benchmark-tenant",
	}
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			pluginCopy := *plugin
			pluginCopy.ID = fmt.Sprintf("benchmark-plugin-%d", i)
			
			instance, err := manager.LoadPlugin(ctx, &pluginCopy)
			if err == nil && instance != nil {
				// Clean up to prevent memory growth
				manager.UnloadPlugin(ctx, instance.ID)
			}
			i++
		}
	})
}

func BenchmarkPluginManager_ExecuteHook(b *testing.B) {
	// Setup
	manager := setupBenchmarkManager()
	
	// Pre-load a plugin
	plugin := &Plugin{
		ID:       "benchmark-plugin",
		Name:     "Benchmark Plugin",
		Version:  "1.0.0",
		TenantID: "benchmark-tenant",
		Hooks:    []string{"benchmark_hook"},
	}
	
	ctx := context.Background()
	instance, _ := manager.LoadPlugin(ctx, plugin)
	
	hookData := map[string]interface{}{
		"test_data": "benchmark_value",
		"timestamp": time.Now(),
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			manager.ExecuteHook(ctx, "benchmark_hook", hookData)
		}
	})
}

// Helper function to setup benchmark manager
func setupBenchmarkManager() *Manager {
	// This would return a real manager instance for benchmarking
	// For now, return a minimal implementation
	return &Manager{
		instances: make(map[string]*PluginInstance),
		hooks:     make(map[string][]string),
		config: &ManagerConfig{
			MaxConcurrentExecutions: 100,
			ExecutionTimeout:        5 * time.Second,
			MaxPluginsPerTenant:     100,
		},
	}
}