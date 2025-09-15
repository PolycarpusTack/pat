package container

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// FortressContainerTestSuite provides comprehensive test coverage for the fortress container
type FortressContainerTestSuite struct {
	suite.Suite
	container   *Container
	testContext context.Context
}

// Test services for dependency injection testing
type TestService interface {
	GetName() string
	Initialize() error
	IsHealthy() bool
}

type TestServiceImpl struct {
	name        string
	initialized bool
	healthy     bool
	dependency  TestDependency
}

func (ts *TestServiceImpl) GetName() string {
	return ts.name
}

func (ts *TestServiceImpl) Initialize() error {
	ts.initialized = true
	ts.healthy = true
	return nil
}

func (ts *TestServiceImpl) IsHealthy() bool {
	return ts.healthy
}

type TestDependency interface {
	GetValue() string
}

type TestDependencyImpl struct {
	value string
}

func (td *TestDependencyImpl) GetValue() string {
	return td.value
}

// Factory functions for testing
func NewTestService(dep TestDependency) TestService {
	return &TestServiceImpl{
		name:       "test-service",
		dependency: dep,
	}
}

func NewTestDependency() TestDependency {
	return &TestDependencyImpl{
		value: "test-value",
	}
}

// SetupTest initializes test environment
func (suite *FortressContainerTestSuite) SetupTest() {
	suite.container = NewContainer()
	suite.testContext = context.Background()
}

// TestRegisterService tests service registration
func (suite *FortressContainerTestSuite) TestRegisterService_Success() {
	t := suite.T()
	
	// Arrange
	serviceName := "test-service"
	factory := func() TestService {
		return &TestServiceImpl{name: serviceName}
	}
	
	// Act
	err := suite.container.RegisterService(serviceName, factory)
	
	// Assert
	require.NoError(t, err)
	
	// Verify service is registered
	suite.container.mu.RLock()
	registration, exists := suite.container.services[serviceName]
	suite.container.mu.RUnlock()
	
	assert.True(t, exists)
	assert.Equal(t, serviceName, registration.name)
	assert.Equal(t, reflect.TypeOf((*TestService)(nil)).Elem(), registration.serviceType)
	assert.False(t, registration.singleton)
	assert.Nil(t, registration.instance)
}

func (suite *FortressContainerTestSuite) TestRegisterService_Duplicate() {
	t := suite.T()
	
	// Arrange
	serviceName := "duplicate-service"
	factory := func() TestService {
		return &TestServiceImpl{name: serviceName}
	}
	
	// Act - Register first time
	err1 := suite.container.RegisterService(serviceName, factory)
	require.NoError(t, err1)
	
	// Act - Register same service again
	err2 := suite.container.RegisterService(serviceName, factory)
	
	// Assert
	assert.Error(t, err2)
	assert.Contains(t, err2.Error(), "already registered")
}

// TestRegisterSingleton tests singleton service registration
func (suite *FortressContainerTestSuite) TestRegisterSingleton_Success() {
	t := suite.T()
	
	// Arrange
	serviceName := "singleton-service"
	factory := func() TestService {
		return &TestServiceImpl{name: serviceName}
	}
	
	// Act
	err := suite.container.RegisterSingleton(serviceName, factory)
	
	// Assert
	require.NoError(t, err)
	
	// Verify singleton is registered
	suite.container.mu.RLock()
	registration, exists := suite.container.services[serviceName]
	suite.container.mu.RUnlock()
	
	assert.True(t, exists)
	assert.True(t, registration.singleton)
}

// TestResolve tests service resolution
func (suite *FortressContainerTestSuite) TestResolve_Success() {
	t := suite.T()
	
	// Arrange
	serviceName := "resolvable-service"
	expectedName := "test-resolvable"
	
	factory := func() TestService {
		return &TestServiceImpl{name: expectedName}
	}
	
	err := suite.container.RegisterService(serviceName, factory)
	require.NoError(t, err)
	
	// Act
	service, err := suite.container.Resolve(serviceName)
	
	// Assert
	require.NoError(t, err)
	require.NotNil(t, service)
	
	testService, ok := service.(TestService)
	require.True(t, ok, "Service should implement TestService interface")
	assert.Equal(t, expectedName, testService.GetName())
}

func (suite *FortressContainerTestSuite) TestResolve_NotFound() {
	t := suite.T()
	
	// Act
	service, err := suite.container.Resolve("non-existent-service")
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "service not found")
}

func (suite *FortressContainerTestSuite) TestResolve_Singleton() {
	t := suite.T()
	
	// Arrange
	serviceName := "singleton-test"
	factory := func() TestService {
		return &TestServiceImpl{name: serviceName}
	}
	
	err := suite.container.RegisterSingleton(serviceName, factory)
	require.NoError(t, err)
	
	// Act - Resolve multiple times
	service1, err1 := suite.container.Resolve(serviceName)
	service2, err2 := suite.container.Resolve(serviceName)
	
	// Assert
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NotNil(t, service1)
	require.NotNil(t, service2)
	
	// Both should be the same instance
	assert.Same(t, service1, service2, "Singleton should return same instance")
}

func (suite *FortressContainerTestSuite) TestResolve_NonSingleton() {
	t := suite.T()
	
	// Arrange
	serviceName := "non-singleton-test"
	factory := func() TestService {
		return &TestServiceImpl{name: serviceName}
	}
	
	err := suite.container.RegisterService(serviceName, factory)
	require.NoError(t, err)
	
	// Act - Resolve multiple times
	service1, err1 := suite.container.Resolve(serviceName)
	service2, err2 := suite.container.Resolve(serviceName)
	
	// Assert
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NotNil(t, service1)
	require.NotNil(t, service2)
	
	// Should be different instances
	assert.NotSame(t, service1, service2, "Non-singleton should return different instances")
}

// TestDependencyInjection tests dependency injection
func (suite *FortressContainerTestSuite) TestDependencyInjection_Success() {
	t := suite.T()
	
	// Arrange - Register dependency first
	depName := "test-dependency"
	err := suite.container.RegisterSingleton(depName, NewTestDependency)
	require.NoError(t, err)
	
	// Register service that depends on the dependency
	serviceName := "dependent-service"
	err = suite.container.RegisterService(serviceName, func() TestService {
		dep, _ := suite.container.Resolve(depName)
		return NewTestService(dep.(TestDependency))
	})
	require.NoError(t, err)
	
	// Act
	service, err := suite.container.Resolve(serviceName)
	
	// Assert
	require.NoError(t, err)
	require.NotNil(t, service)
	
	testService := service.(TestService)
	assert.Equal(t, "test-service", testService.GetName())
}

// TestCircularDependency tests circular dependency detection
func (suite *FortressContainerTestSuite) TestCircularDependency_Detection() {
	t := suite.T()
	
	// Arrange - Create services with circular dependencies
	serviceA := "service-a"
	serviceB := "service-b"
	
	// Service A depends on Service B
	err1 := suite.container.RegisterService(serviceA, func() interface{} {
		suite.container.Resolve(serviceB) // This creates circular dependency
		return &TestServiceImpl{name: "service-a"}
	})
	require.NoError(t, err1)
	
	// Service B depends on Service A
	err2 := suite.container.RegisterService(serviceB, func() interface{} {
		suite.container.Resolve(serviceA) // This creates circular dependency
		return &TestServiceImpl{name: "service-b"}
	})
	require.NoError(t, err2)
	
	// Act - Try to resolve, should detect circular dependency
	service, err := suite.container.Resolve(serviceA)
	
	// Assert - Should fail with circular dependency error
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "circular dependency")
}

// TestInitializeServices tests service initialization
func (suite *FortressContainerTestSuite) TestInitializeServices_Success() {
	t := suite.T()
	
	// Arrange
	serviceName := "initializable-service"
	factory := func() TestService {
		return &TestServiceImpl{name: serviceName}
	}
	
	err := suite.container.RegisterService(serviceName, factory)
	require.NoError(t, err)
	
	// Act
	err = suite.container.InitializeServices(suite.testContext)
	
	// Assert
	require.NoError(t, err)
	
	// Verify service was initialized
	service, err := suite.container.Resolve(serviceName)
	require.NoError(t, err)
	
	testService := service.(*TestServiceImpl)
	assert.True(t, testService.initialized, "Service should be initialized")
}

func (suite *FortressContainerTestSuite) TestInitializeServices_WithInitializer() {
	t := suite.T()
	
	// Arrange
	serviceName := "service-with-initializer"
	
	// Create service that implements ServiceInitializer
	type InitializableService struct {
		*TestServiceImpl
		initCalled bool
	}
	
	factory := func() *InitializableService {
		return &InitializableService{
			TestServiceImpl: &TestServiceImpl{name: serviceName},
		}
	}
	
	err := suite.container.RegisterService(serviceName, factory)
	require.NoError(t, err)
	
	// Mock the Initialize method to track if it was called
	// In a real scenario, the service would implement ServiceInitializer interface
	
	// Act
	err = suite.container.InitializeServices(suite.testContext)
	
	// Assert
	require.NoError(t, err)
}

// TestShutdownServices tests service shutdown
func (suite *FortressContainerTestSuite) TestShutdownServices_Success() {
	t := suite.T()
	
	// Arrange
	serviceName := "shutdownable-service"
	
	type ShutdownableService struct {
		*TestServiceImpl
		shutdownCalled bool
	}
	
	factory := func() *ShutdownableService {
		return &ShutdownableService{
			TestServiceImpl: &TestServiceImpl{name: serviceName},
		}
	}
	
	err := suite.container.RegisterService(serviceName, factory)
	require.NoError(t, err)
	
	// Initialize first
	err = suite.container.InitializeServices(suite.testContext)
	require.NoError(t, err)
	
	// Act
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = suite.container.ShutdownServices(ctx)
	
	// Assert
	require.NoError(t, err)
}

// TestHealthCheck tests health checking
func (suite *FortressContainerTestSuite) TestHealthCheck_AllHealthy() {
	t := suite.T()
	
	// Arrange
	serviceName1 := "healthy-service-1"
	serviceName2 := "healthy-service-2"
	
	err1 := suite.container.RegisterService(serviceName1, func() TestService {
		return &TestServiceImpl{name: serviceName1, healthy: true}
	})
	require.NoError(t, err1)
	
	err2 := suite.container.RegisterService(serviceName2, func() TestService {
		return &TestServiceImpl{name: serviceName2, healthy: true}
	})
	require.NoError(t, err2)
	
	// Initialize services
	err := suite.container.InitializeServices(suite.testContext)
	require.NoError(t, err)
	
	// Act
	healthStatus := suite.container.HealthCheck(suite.testContext)
	
	// Assert
	assert.True(t, healthStatus.Healthy)
	assert.Equal(t, 2, len(healthStatus.Services))
	
	for _, serviceHealth := range healthStatus.Services {
		assert.True(t, serviceHealth.Healthy)
		assert.Empty(t, serviceHealth.Error)
	}
}

func (suite *FortressContainerTestSuite) TestHealthCheck_SomeUnhealthy() {
	t := suite.T()
	
	// Arrange
	healthyServiceName := "healthy-service"
	unhealthyServiceName := "unhealthy-service"
	
	err1 := suite.container.RegisterService(healthyServiceName, func() TestService {
		return &TestServiceImpl{name: healthyServiceName, healthy: true}
	})
	require.NoError(t, err1)
	
	err2 := suite.container.RegisterService(unhealthyServiceName, func() TestService {
		return &TestServiceImpl{name: unhealthyServiceName, healthy: false}
	})
	require.NoError(t, err2)
	
	// Initialize services
	err := suite.container.InitializeServices(suite.testContext)
	require.NoError(t, err)
	
	// Act
	healthStatus := suite.container.HealthCheck(suite.testContext)
	
	// Assert
	assert.False(t, healthStatus.Healthy, "Overall health should be false if any service is unhealthy")
	assert.Equal(t, 2, len(healthStatus.Services))
	
	// Find the unhealthy service
	var unhealthyFound bool
	for _, serviceHealth := range healthStatus.Services {
		if serviceHealth.Name == unhealthyServiceName {
			assert.False(t, serviceHealth.Healthy)
			unhealthyFound = true
		}
	}
	assert.True(t, unhealthyFound, "Should find the unhealthy service in status")
}

// TestConcurrentAccess tests concurrent access to container
func (suite *FortressContainerTestSuite) TestConcurrentAccess() {
	t := suite.T()
	
	// Arrange
	numServices := 10
	numGoroutines := 20
	
	// Register services
	for i := 0; i < numServices; i++ {
		serviceName := fmt.Sprintf("concurrent-service-%d", i)
		serviceIndex := i // Capture for closure
		
		factory := func() TestService {
			return &TestServiceImpl{name: fmt.Sprintf("service-%d", serviceIndex)}
		}
		
		err := suite.container.RegisterService(serviceName, factory)
		require.NoError(t, err)
	}
	
	// Act - Resolve services concurrently
	errChan := make(chan error, numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < numServices; j++ {
				serviceName := fmt.Sprintf("concurrent-service-%d", j)
				service, err := suite.container.Resolve(serviceName)
				
				if err != nil {
					errChan <- err
					return
				}
				
				if service == nil {
					errChan <- fmt.Errorf("service is nil for %s", serviceName)
					return
				}
			}
			errChan <- nil
		}(i)
	}
	
	// Assert - Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		assert.NoError(t, err, "Goroutine %d should not have errors", i)
	}
}

// Benchmark tests
func (suite *FortressContainerTestSuite) TestBenchmarkResolve() {
	// This would be a benchmark test in practice
	// For now, we'll do a simple performance verification
	
	// Arrange
	serviceName := "benchmark-service"
	factory := func() TestService {
		return &TestServiceImpl{name: serviceName}
	}
	
	err := suite.container.RegisterService(serviceName, factory)
	require.NoError(suite.T(), err)
	
	// Act - Resolve many times and measure
	start := time.Now()
	iterations := 1000
	
	for i := 0; i < iterations; i++ {
		service, err := suite.container.Resolve(serviceName)
		require.NoError(suite.T(), err)
		require.NotNil(suite.T(), service)
	}
	
	duration := time.Since(start)
	
	// Assert - Should be reasonably fast
	averageTime := duration / time.Duration(iterations)
	suite.T().Logf("Average resolution time: %v", averageTime)
	
	// Should resolve in under 1ms on average
	assert.Less(suite.T(), averageTime, 1*time.Millisecond, 
		"Service resolution should be fast")
}

// Test edge cases
func (suite *FortressContainerTestSuite) TestNilFactory() {
	t := suite.T()
	
	// Act
	err := suite.container.RegisterService("nil-factory", nil)
	
	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "factory cannot be nil")
}

func (suite *FortressContainerTestSuite) TestEmptyServiceName() {
	t := suite.T()
	
	// Act
	err := suite.container.RegisterService("", func() TestService {
		return &TestServiceImpl{}
	})
	
	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service name cannot be empty")
}

// Run the test suite
func TestFortressContainerSuite(t *testing.T) {
	suite.Run(t, new(FortressContainerTestSuite))
}

// Standalone benchmark tests
func BenchmarkContainer_Resolve(b *testing.B) {
	container := NewContainer()
	
	// Register a service
	container.RegisterService("benchmark-service", func() TestService {
		return &TestServiceImpl{name: "benchmark"}
	})
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := container.Resolve("benchmark-service")
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkContainer_ResolveSingleton(b *testing.B) {
	container := NewContainer()
	
	// Register a singleton service
	container.RegisterSingleton("benchmark-singleton", func() TestService {
		return &TestServiceImpl{name: "benchmark-singleton"}
	})
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := container.Resolve("benchmark-singleton")
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkContainer_RegisterService(b *testing.B) {
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			container := NewContainer()
			serviceName := fmt.Sprintf("benchmark-service-%d", i)
			
			err := container.RegisterService(serviceName, func() TestService {
				return &TestServiceImpl{name: serviceName}
			})
			
			if err != nil {
				b.Error(err)
			}
			i++
		}
	})
}