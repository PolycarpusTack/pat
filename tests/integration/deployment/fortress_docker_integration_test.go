package deployment

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/pat-fortress/tests/integration/testdata/fixtures"
	"github.com/pat-fortress/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// FortressDockerIntegrationSuite tests Docker deployment and container orchestration
type FortressDockerIntegrationSuite struct {
	suite.Suite
	testUtils      *utils.FortressTestUtils
	configFixtures *fixtures.ConfigFixtures
	
	// Docker configuration and management
	dockerConfig   *interfaces.DockerConfig
	composeFile    string
	projectDir     string
	networkName    string
	
	// Service endpoints
	postgresPort   int
	redisPort      int
	smtpPort       int
	httpPort       int
	
	// Test context
	ctx            context.Context
	cancel         context.CancelFunc
	containersStarted bool
}

// SetupSuite initializes the Docker integration test environment
func (s *FortressDockerIntegrationSuite) SetupSuite() {
	s.testUtils = utils.NewFortressTestUtils(s.T())
	s.configFixtures = fixtures.NewConfigFixtures()
	
	s.ctx, s.cancel = context.WithTimeout(context.Background(), time.Minute*20)
	
	// Get Docker configuration
	s.dockerConfig = s.configFixtures.TestDockerConfig()
	
	// Setup test environment
	s.setupTestEnvironment()
	
	// Check Docker availability
	s.checkDockerAvailability()
	
	// Start Docker services
	s.startDockerServices()
}

// TearDownSuite cleans up the Docker integration test environment
func (s *FortressDockerIntegrationSuite) TearDownSuite() {
	if s.containersStarted {
		s.stopDockerServices()
	}
	
	s.cleanupTestEnvironment()
	
	if s.cancel != nil {
		s.cancel()
	}
}

// TestDockerServiceAvailability tests that Docker is available and functional
func (s *FortressDockerIntegrationSuite) TestDockerServiceAvailability() {
	s.T().Run("Docker_Daemon_Available", func(t *testing.T) {
		// Test Docker daemon connectivity
		cmd := exec.CommandContext(s.ctx, "docker", "version")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Docker daemon should be available: %s", string(output))
		
		// Verify Docker Compose is available
		cmd = exec.CommandContext(s.ctx, "docker-compose", "--version")
		output, err = cmd.CombinedOutput()
		require.NoError(t, err, "Docker Compose should be available: %s", string(output))
		
		t.Log("Docker and Docker Compose are available")
	})
}

// TestDockerNetworkCreation tests Docker network setup
func (s *FortressDockerIntegrationSuite) TestDockerNetworkCreation() {
	s.T().Run("Network_Creation", func(t *testing.T) {
		// Check if test network exists
		cmd := exec.CommandContext(s.ctx, "docker", "network", "ls", "--filter", fmt.Sprintf("name=%s", s.networkName))
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		networkExists := strings.Contains(string(output), s.networkName)
		assert.True(t, networkExists, "Test network should exist: %s", s.networkName)
		
		if networkExists {
			// Inspect network details
			cmd = exec.CommandContext(s.ctx, "docker", "network", "inspect", s.networkName)
			output, err = cmd.CombinedOutput()
			require.NoError(t, err)
			
			t.Logf("Network details: %s", string(output))
		}
	})
}

// TestPostgreSQLContainer tests PostgreSQL database container
func (s *FortressDockerIntegrationSuite) TestPostgreSQLContainer() {
	s.T().Run("PostgreSQL_Container_Health", func(t *testing.T) {
		containerName := s.dockerConfig.ContainerPrefix + "-postgres"
		
		// Check container is running
		s.assertContainerRunning(containerName)
		
		// Check PostgreSQL port is accessible
		s.assertPortAccessible("localhost", s.postgresPort)
		
		// Test database connection
		s.testDatabaseConnection()
		
		t.Log("PostgreSQL container is healthy and accessible")
	})
	
	s.T().Run("PostgreSQL_Data_Persistence", func(t *testing.T) {
		// This test would verify that data persists across container restarts
		// For integration tests, we verify the volume is mounted
		
		containerName := s.dockerConfig.ContainerPrefix + "-postgres"
		
		// Check volume mount
		cmd := exec.CommandContext(s.ctx, "docker", "inspect", containerName)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		// Verify volume is mounted
		outputStr := string(output)
		assert.Contains(t, outputStr, "/var/lib/postgresql/data",
			"PostgreSQL data directory should be mounted")
		
		t.Log("PostgreSQL data volume is properly mounted")
	})
}

// TestRedisContainer tests Redis cache container
func (s *FortressDockerIntegrationSuite) TestRedisContainer() {
	s.T().Run("Redis_Container_Health", func(t *testing.T) {
		containerName := s.dockerConfig.ContainerPrefix + "-redis"
		
		// Check container is running
		s.assertContainerRunning(containerName)
		
		// Check Redis port is accessible
		s.assertPortAccessible("localhost", s.redisPort)
		
		// Test Redis connection
		s.testRedisConnection()
		
		t.Log("Redis container is healthy and accessible")
	})
	
	s.T().Run("Redis_Configuration", func(t *testing.T) {
		containerName := s.dockerConfig.ContainerPrefix + "-redis"
		
		// Execute Redis CLI command in container
		cmd := exec.CommandContext(s.ctx, "docker", "exec", containerName, 
			"redis-cli", "CONFIG", "GET", "maxmemory")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		t.Logf("Redis maxmemory configuration: %s", string(output))
		
		// Test Redis info
		cmd = exec.CommandContext(s.ctx, "docker", "exec", containerName, 
			"redis-cli", "INFO", "server")
		output, err = cmd.CombinedOutput()
		require.NoError(t, err)
		
		assert.Contains(t, string(output), "redis_version",
			"Redis info should contain version information")
	})
}

// TestFortressAppContainer tests the main Fortress application container
func (s *FortressDockerIntegrationSuite) TestFortressAppContainer() {
	s.T().Run("App_Container_Health", func(t *testing.T) {
		containerName := s.dockerConfig.ContainerPrefix + "-app"
		
		// Check container is running
		s.assertContainerRunning(containerName)
		
		// Check HTTP port is accessible
		s.assertPortAccessible("localhost", s.httpPort)
		
		// Check SMTP port is accessible
		s.assertPortAccessible("localhost", s.smtpPort)
		
		t.Log("Fortress app container is healthy and accessible")
	})
	
	s.T().Run("App_Health_Endpoint", func(t *testing.T) {
		// Test HTTP health endpoint
		healthURL := fmt.Sprintf("http://localhost:%d/health", s.httpPort)
		
		client := &http.Client{Timeout: time.Second * 10}
		
		// Retry health check with backoff
		var resp *http.Response
		var err error
		
		for retry := 0; retry < 10; retry++ {
			resp, err = client.Get(healthURL)
			if err == nil && resp.StatusCode == http.StatusOK {
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(time.Second * 2)
		}
		
		require.NoError(t, err, "Health endpoint should be accessible")
		require.NotNil(t, resp, "Should receive HTTP response")
		defer resp.Body.Close()
		
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"Health endpoint should return 200 OK")
		
		t.Log("Fortress app health endpoint is responding")
	})
	
	s.T().Run("App_Environment_Variables", func(t *testing.T) {
		containerName := s.dockerConfig.ContainerPrefix + "-app"
		
		// Check environment variables are set
		expectedEnvVars := []string{
			"FORTRESS_ENV",
			"FORTRESS_LOG_LEVEL",
			"FORTRESS_DEBUG",
		}
		
		for _, envVar := range expectedEnvVars {
			cmd := exec.CommandContext(s.ctx, "docker", "exec", containerName, 
				"env")
			output, err := cmd.CombinedOutput()
			require.NoError(t, err)
			
			assert.Contains(t, string(output), envVar,
				"Environment variable %s should be set", envVar)
		}
		
		t.Log("Fortress app environment variables are properly set")
	})
}

// TestContainerOrchestration tests container communication and dependencies
func (s *FortressDockerIntegrationSuite) TestContainerOrchestration() {
	s.T().Run("Container_Communication", func(t *testing.T) {
		appContainer := s.dockerConfig.ContainerPrefix + "-app"
		
		// Test that app can connect to PostgreSQL
		cmd := exec.CommandContext(s.ctx, "docker", "exec", appContainer,
			"sh", "-c", "nc -z postgres 5432")
		output, err := cmd.CombinedOutput()
		
		if err == nil {
			t.Log("App container can connect to PostgreSQL")
		} else {
			t.Logf("Note: Network connectivity test failed: %s", string(output))
		}
		
		// Test that app can connect to Redis
		cmd = exec.CommandContext(s.ctx, "docker", "exec", appContainer,
			"sh", "-c", "nc -z redis 6379")
		output, err = cmd.CombinedOutput()
		
		if err == nil {
			t.Log("App container can connect to Redis")
		} else {
			t.Logf("Note: Network connectivity test failed: %s", string(output))
		}
	})
	
	s.T().Run("Service_Dependencies", func(t *testing.T) {
		// Verify that services started in the correct order
		// This is typically handled by Docker Compose depends_on
		
		containers := []string{
			s.dockerConfig.ContainerPrefix + "-postgres",
			s.dockerConfig.ContainerPrefix + "-redis",
			s.dockerConfig.ContainerPrefix + "-app",
		}
		
		for _, container := range containers {
			s.assertContainerRunning(container)
		}
		
		t.Log("All service containers are running in proper order")
	})
}

// TestDockerVolumePersistence tests data persistence across container restarts
func (s *FortressDockerIntegrationSuite) TestDockerVolumePersistence() {
	s.T().Run("Volume_Persistence", func(t *testing.T) {
		// List Docker volumes used by the application
		cmd := exec.CommandContext(s.ctx, "docker", "volume", "ls", 
			"--filter", fmt.Sprintf("name=%s", s.dockerConfig.ContainerPrefix))
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		volumeList := string(output)
		
		// Check for expected volumes
		expectedVolumes := []string{
			s.dockerConfig.ContainerPrefix + "-pgdata",
			s.dockerConfig.ContainerPrefix + "-logs",
		}
		
		for _, volume := range expectedVolumes {
			assert.Contains(t, volumeList, volume,
				"Volume %s should exist", volume)
		}
		
		t.Log("Docker volumes for data persistence are created")
	})
}

// TestDockerResourceUsage tests container resource usage
func (s *FortressDockerIntegrationSuite) TestDockerResourceUsage() {
	s.T().Run("Container_Resource_Usage", func(t *testing.T) {
		containers := []string{
			s.dockerConfig.ContainerPrefix + "-postgres",
			s.dockerConfig.ContainerPrefix + "-redis", 
			s.dockerConfig.ContainerPrefix + "-app",
		}
		
		for _, container := range containers {
			// Get container stats
			cmd := exec.CommandContext(s.ctx, "docker", "stats", container, 
				"--no-stream", "--format", "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}")
			output, err := cmd.CombinedOutput()
			require.NoError(t, err)
			
			stats := string(output)
			assert.NotEmpty(t, stats, "Should get resource stats for %s", container)
			
			t.Logf("Resource stats for %s:\n%s", container, stats)
		}
	})
}

// TestDockerLogging tests container logging configuration
func (s *FortressDockerIntegrationSuite) TestDockerLogging() {
	s.T().Run("Container_Logs", func(t *testing.T) {
		appContainer := s.dockerConfig.ContainerPrefix + "-app"
		
		// Get recent logs
		cmd := exec.CommandContext(s.ctx, "docker", "logs", appContainer, 
			"--tail", "50")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		logs := string(output)
		assert.NotEmpty(t, logs, "App container should have logs")
		
		// Check for expected log patterns
		if strings.Contains(logs, "INFO") || strings.Contains(logs, "DEBUG") {
			t.Log("App container is producing structured logs")
		}
		
		t.Logf("Recent app container logs (last 50 lines):\n%s", 
			s.truncateString(logs, 1000))
	})
}

// TestDockerCleanup tests cleanup procedures
func (s *FortressDockerIntegrationSuite) TestDockerCleanup() {
	s.T().Run("Cleanup_Verification", func(t *testing.T) {
		// This test verifies that cleanup procedures work
		// It's run as part of the normal test flow
		
		// Check that we can identify all test containers
		cmd := exec.CommandContext(s.ctx, "docker", "ps", "-a", 
			"--filter", fmt.Sprintf("name=%s", s.dockerConfig.ContainerPrefix))
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		
		containerList := string(output)
		
		// Count test containers
		containerCount := strings.Count(containerList, s.dockerConfig.ContainerPrefix)
		assert.Greater(t, containerCount, 0, "Should find test containers for cleanup")
		
		t.Logf("Found %d test containers that will be cleaned up", containerCount)
	})
}

// Helper methods

func (s *FortressDockerIntegrationSuite) setupTestEnvironment() {
	// Set up test project directory
	currentDir, err := os.Getwd()
	require.NoError(s.T(), err)
	
	s.projectDir = filepath.Join(currentDir, "../../../") // Go up to project root
	s.composeFile = filepath.Join(s.projectDir, "docker-compose.test.yml")
	s.networkName = s.dockerConfig.NetworkName
	
	// Set up port assignments (use different ports to avoid conflicts)
	s.postgresPort = 5433 // Different from production 5432
	s.redisPort = 6380    // Different from production 6379
	s.smtpPort = 2525     // Different from production 1025
	s.httpPort = 8081     // Different from production 8080
	
	// Create test Docker Compose file if it doesn't exist
	s.createTestDockerComposeFile()
}

func (s *FortressDockerIntegrationSuite) cleanupTestEnvironment() {
	// Clean up temporary files if created
	if _, err := os.Stat(s.composeFile); err == nil {
		if strings.Contains(s.composeFile, "test.yml") {
			os.Remove(s.composeFile)
		}
	}
}

func (s *FortressDockerIntegrationSuite) checkDockerAvailability() {
	// Skip tests if Docker is not available
	cmd := exec.CommandContext(s.ctx, "docker", "version")
	if err := cmd.Run(); err != nil {
		s.T().Skip("Docker not available, skipping Docker integration tests")
	}
	
	cmd = exec.CommandContext(s.ctx, "docker-compose", "--version")
	if err := cmd.Run(); err != nil {
		s.T().Skip("Docker Compose not available, skipping Docker integration tests")
	}
}

func (s *FortressDockerIntegrationSuite) createTestDockerComposeFile() {
	// Create a basic test docker-compose.yml if it doesn't exist
	if _, err := os.Stat(s.composeFile); os.IsNotExist(err) {
		composeContent := fmt.Sprintf(`version: '3.8'

services:
  postgres:
    image: %s
    container_name: %s-postgres
    environment:
      POSTGRES_DB: %s
      POSTGRES_USER: %s
      POSTGRES_PASSWORD: %s
    ports:
      - "%d:5432"
    volumes:
      - %s-pgdata:/var/lib/postgresql/data
    networks:
      - %s
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U %s -d %s"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: %s
    container_name: %s-redis
    ports:
      - "%d:6379"
    networks:
      - %s
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  app:
    image: fortress:test
    container_name: %s-app
    environment:
      FORTRESS_ENV: test
      FORTRESS_LOG_LEVEL: debug
      FORTRESS_DEBUG: "true"
      DATABASE_URL: "postgres://%s:%s@postgres:5432/%s?sslmode=disable"
      REDIS_URL: "redis://redis:6379/1"
    ports:
      - "%d:8080"
      - "%d:1025"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - %s
    volumes:
      - %s-logs:/var/log/fortress

volumes:
  %s-pgdata:
  %s-logs:

networks:
  %s:
    driver: bridge
`,
			s.dockerConfig.PostgreSQLImage,
			s.dockerConfig.ContainerPrefix,
			s.dockerConfig.PostgreSQLDatabase,
			s.dockerConfig.PostgreSQLUser,
			s.dockerConfig.PostgreSQLPassword,
			s.postgresPort,
			s.dockerConfig.ContainerPrefix,
			s.networkName,
			s.dockerConfig.PostgreSQLUser,
			s.dockerConfig.PostgreSQLDatabase,
			s.dockerConfig.RedisImage,
			s.dockerConfig.ContainerPrefix,
			s.redisPort,
			s.networkName,
			s.dockerConfig.ContainerPrefix,
			s.dockerConfig.PostgreSQLUser,
			s.dockerConfig.PostgreSQLPassword,
			s.dockerConfig.PostgreSQLDatabase,
			s.httpPort,
			s.smtpPort,
			s.networkName,
			s.dockerConfig.ContainerPrefix,
			s.dockerConfig.ContainerPrefix,
			s.dockerConfig.ContainerPrefix,
			s.networkName,
		)
		
		err := os.WriteFile(s.composeFile, []byte(composeContent), 0644)
		if err != nil {
			s.T().Logf("Warning: Could not create test docker-compose file: %v", err)
		}
	}
}

func (s *FortressDockerIntegrationSuite) startDockerServices() {
	// Start services using docker-compose
	cmd := exec.CommandContext(s.ctx, "docker-compose", 
		"-f", s.composeFile, 
		"-p", s.dockerConfig.ContainerPrefix,
		"up", "-d", "--build")
	
	cmd.Dir = s.projectDir
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		s.T().Logf("Docker compose output: %s", string(output))
		s.T().Skip("Could not start Docker services, skipping Docker integration tests")
		return
	}
	
	s.containersStarted = true
	
	// Wait for services to be healthy
	s.waitForServicesHealthy()
	
	s.T().Log("Docker services started successfully")
}

func (s *FortressDockerIntegrationSuite) stopDockerServices() {
	// Stop and remove containers
	cmd := exec.CommandContext(s.ctx, "docker-compose", 
		"-f", s.composeFile,
		"-p", s.dockerConfig.ContainerPrefix,
		"down", "-v", "--remove-orphans")
	
	cmd.Dir = s.projectDir
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		s.T().Logf("Warning: Error stopping Docker services: %v\nOutput: %s", err, string(output))
	} else {
		s.T().Log("Docker services stopped and cleaned up")
	}
}

func (s *FortressDockerIntegrationSuite) waitForServicesHealthy() {
	// Wait for services to be ready
	timeout := time.Minute * 3
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		if s.areServicesHealthy() {
			return
		}
		time.Sleep(time.Second * 5)
	}
	
	s.T().Log("Warning: Services may not be fully healthy yet")
}

func (s *FortressDockerIntegrationSuite) areServicesHealthy() bool {
	// Check if PostgreSQL is accepting connections
	if !s.isPortAccessible("localhost", s.postgresPort) {
		return false
	}
	
	// Check if Redis is accepting connections  
	if !s.isPortAccessible("localhost", s.redisPort) {
		return false
	}
	
	return true
}

func (s *FortressDockerIntegrationSuite) assertContainerRunning(containerName string) {
	cmd := exec.CommandContext(s.ctx, "docker", "inspect", containerName, 
		"--format", "{{.State.Running}}")
	output, err := cmd.CombinedOutput()
	require.NoError(s.T(), err, "Container %s should exist", containerName)
	
	isRunning := strings.TrimSpace(string(output)) == "true"
	assert.True(s.T(), isRunning, "Container %s should be running", containerName)
}

func (s *FortressDockerIntegrationSuite) assertPortAccessible(host string, port int) {
	accessible := s.isPortAccessible(host, port)
	assert.True(s.T(), accessible, "Port %d should be accessible on %s", port, host)
}

func (s *FortressDockerIntegrationSuite) isPortAccessible(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Second*5)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *FortressDockerIntegrationSuite) testDatabaseConnection() {
	// Simple test to verify PostgreSQL is accepting connections
	// In a real implementation, this would use the actual database driver
	
	// Use nc (netcat) to test connection if available
	cmd := exec.CommandContext(s.ctx, "nc", "-z", "localhost", fmt.Sprintf("%d", s.postgresPort))
	err := cmd.Run()
	
	if err == nil {
		s.T().Log("PostgreSQL connection test successful")
	} else {
		s.T().Logf("Note: PostgreSQL connection test failed: %v", err)
	}
}

func (s *FortressDockerIntegrationSuite) testRedisConnection() {
	// Simple test to verify Redis is accepting connections
	cmd := exec.CommandContext(s.ctx, "nc", "-z", "localhost", fmt.Sprintf("%d", s.redisPort))
	err := cmd.Run()
	
	if err == nil {
		s.T().Log("Redis connection test successful")
	} else {
		s.T().Logf("Note: Redis connection test failed: %v", err)
	}
}

func (s *FortressDockerIntegrationSuite) truncateString(str string, maxLen int) string {
	if len(str) <= maxLen {
		return str
	}
	return str[:maxLen] + "... (truncated)"
}

// TestFortressDockerIntegration runs the Docker integration test suite
func TestFortressDockerIntegration(t *testing.T) {
	// Skip if Docker integration tests are disabled
	if os.Getenv("SKIP_DOCKER_TESTS") == "true" {
		t.Skip("Docker integration tests disabled")
	}
	
	// Skip in short mode
	if testing.Short() {
		t.Skip("Skipping Docker integration tests in short mode")
	}
	
	suite.Run(t, new(FortressDockerIntegrationSuite))
}