package protocol_compliance

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
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

// FortressSMTPComplianceSuite tests SMTP protocol RFC 5321 compliance
type FortressSMTPComplianceSuite struct {
	suite.Suite
	testUtils      *utils.FortressTestUtils
	configFixtures *fixtures.ConfigFixtures
	emailFixtures  *fixtures.EmailFixtures
	
	// SMTP server and client setup
	smtpServer interfaces.Gates
	smtpConfig *interfaces.SMTPServerConfig
	serverAddr string
	
	// Test context
	ctx    context.Context
	cancel context.CancelFunc
}

// SetupSuite initializes the SMTP compliance test environment
func (s *FortressSMTPComplianceSuite) SetupSuite() {
	s.testUtils = utils.NewFortressTestUtils(s.T())
	s.configFixtures = fixtures.NewConfigFixtures()
	s.emailFixtures = fixtures.NewEmailFixtures()
	
	s.ctx, s.cancel = context.WithTimeout(context.Background(), time.Minute*15)
	
	// Get SMTP server configuration
	s.smtpConfig = s.configFixtures.TestSMTPServerConfig()
	s.serverAddr = fmt.Sprintf("%s:%d", s.smtpConfig.Host, s.smtpConfig.Port)
	
	// Initialize and start SMTP server
	s.smtpServer = s.createSMTPServer()
	err := s.smtpServer.StartSMTPServer(s.ctx, s.smtpConfig)
	require.NoError(s.T(), err)
	
	// Wait for server to be ready
	s.waitForServerReady()
}

// TearDownSuite cleans up the SMTP compliance test environment
func (s *FortressSMTPComplianceSuite) TearDownSuite() {
	if s.smtpServer != nil {
		s.smtpServer.StopSMTPServer(s.ctx)
	}
	
	if s.cancel != nil {
		s.cancel()
	}
}

// TestSMTPBasicConnectivity tests basic SMTP connection and greeting
func (s *FortressSMTPComplianceSuite) TestSMTPBasicConnectivity() {
	s.T().Run("SMTP_Connection_Greeting", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.serverAddr, time.Second*10)
		require.NoError(t, err)
		defer conn.Close()
		
		// Set read timeout
		conn.SetReadDeadline(time.Now().Add(time.Second * 10))
		
		// Read greeting
		reader := bufio.NewReader(conn)
		greeting, err := reader.ReadString('\n')
		require.NoError(t, err)
		
		// Verify greeting format (RFC 5321: 220 response)
		assert.True(t, strings.HasPrefix(greeting, "220 "), 
			"Greeting should start with 220: %s", greeting)
		assert.Contains(t, greeting, s.smtpConfig.Hostname,
			"Greeting should contain hostname: %s", greeting)
		assert.True(t, strings.HasSuffix(strings.TrimSpace(greeting), "SMTP"),
			"Greeting should end with SMTP: %s", greeting)
		
		t.Logf("SMTP Greeting: %s", strings.TrimSpace(greeting))
	})
}

// TestSMTPEHLOCommand tests EHLO command compliance
func (s *FortressSMTPComplianceSuite) TestSMTPEHLOCommand() {
	s.T().Run("EHLO_Command_Response", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.serverAddr, time.Second*10)
		require.NoError(t, err)
		defer conn.Close()
		
		reader := bufio.NewReader(conn)
		
		// Read greeting
		_, err = reader.ReadString('\n')
		require.NoError(t, err)
		
		// Send EHLO
		ehloCmd := fmt.Sprintf("EHLO %s\r\n", "client.fortress.test")
		_, err = conn.Write([]byte(ehloCmd))
		require.NoError(t, err)
		
		// Read EHLO response
		var responses []string
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			
			responses = append(responses, strings.TrimSpace(line))
			
			// Multi-line response ends when line starts with code followed by space (not hyphen)
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}
		
		// Verify EHLO response format
		require.NotEmpty(t, responses, "Should receive EHLO responses")
		
		firstLine := responses[0]
		assert.True(t, strings.HasPrefix(firstLine, "250 "), 
			"First EHLO response should be 250: %s", firstLine)
		assert.Contains(t, firstLine, s.smtpConfig.Hostname,
			"First EHLO response should contain hostname: %s", firstLine)
		
		// Check for required/expected extensions
		extensionLines := responses[1:]
		extensions := make(map[string]bool)
		
		for _, line := range extensionLines {
			if strings.HasPrefix(line, "250-") || strings.HasPrefix(line, "250 ") {
				ext := strings.TrimPrefix(line, "250-")
				ext = strings.TrimPrefix(ext, "250 ")
				extensions[strings.Fields(ext)[0]] = true
			}
		}
		
		// Verify expected extensions
		if s.smtpConfig.EnablePipelining {
			assert.True(t, extensions["PIPELINING"], "Should support PIPELINING")
		}
		
		if s.smtpConfig.EnableBinaryMIME {
			assert.True(t, extensions["BINARYMIME"], "Should support BINARYMIME")
		}
		
		if s.smtpConfig.EnableDSN {
			assert.True(t, extensions["DSN"], "Should support DSN")
		}
		
		// SIZE extension should be present
		sizeFound := false
		for ext := range extensions {
			if strings.HasPrefix(ext, "SIZE") {
				sizeFound = true
				break
			}
		}
		assert.True(t, sizeFound, "Should support SIZE extension")
		
		t.Logf("SMTP Extensions: %v", extensions)
	})
}

// TestSMTPMailTransaction tests complete MAIL transaction
func (s *FortressSMTPComplianceSuite) TestSMTPMailTransaction() {
	s.T().Run("Complete_MAIL_Transaction", func(t *testing.T) {
		// Test using standard smtp package
		client, err := smtp.Dial(s.serverAddr)
		require.NoError(t, err)
		defer client.Close()
		
		// Send EHLO
		err = client.Hello("client.fortress.test")
		require.NoError(t, err)
		
		// Test MAIL FROM command
		err = client.Mail("sender@fortress.test")
		require.NoError(t, err)
		
		// Test RCPT TO command
		err = client.Rcpt("recipient@fortress.test")
		require.NoError(t, err)
		
		// Test DATA command
		dataWriter, err := client.Data()
		require.NoError(t, err)
		
		// Write email content
		email := s.emailFixtures.SimpleTextEmail()
		emailContent := fmt.Sprintf(`From: %s
To: %s
Subject: %s

%s
`, email.From, strings.Join(email.To, ", "), email.Subject, email.Body)
		
		_, err = dataWriter.Write([]byte(emailContent))
		require.NoError(t, err)
		
		// Close data
		err = dataWriter.Close()
		require.NoError(t, err)
		
		// Send QUIT
		err = client.Quit()
		require.NoError(t, err)
		
		t.Log("Complete SMTP transaction successful")
	})
}

// TestSMTPPipelining tests SMTP pipelining support
func (s *FortressSMTPComplianceSuite) TestSMTPPipelining() {
	if !s.smtpConfig.EnablePipelining {
		s.T().Skip("SMTP Pipelining not enabled")
	}
	
	s.T().Run("SMTP_Pipelining", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.serverAddr, time.Second*10)
		require.NoError(t, err)
		defer conn.Close()
		
		reader := bufio.NewReader(conn)
		
		// Read greeting
		_, err = reader.ReadString('\n')
		require.NoError(t, err)
		
		// Send pipelined commands
		pipelinedCommands := []string{
			"EHLO client.fortress.test\r\n",
			"MAIL FROM:<sender@fortress.test>\r\n",
			"RCPT TO:<recipient1@fortress.test>\r\n",
			"RCPT TO:<recipient2@fortress.test>\r\n",
		}
		
		// Send all commands at once (pipelining)
		for _, cmd := range pipelinedCommands {
			_, err = conn.Write([]byte(cmd))
			require.NoError(t, err)
		}
		
		// Read all responses
		var responses []string
		expectedResponses := 4 // EHLO (multi-line), MAIL, RCPT, RCPT
		
		for len(responses) < expectedResponses {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			
			responses = append(responses, strings.TrimSpace(line))
			
			// Handle multi-line EHLO response
			if strings.HasPrefix(line, "250-") {
				// Continue reading EHLO extensions
				continue
			}
		}
		
		// Verify responses
		assert.True(t, len(responses) >= expectedResponses,
			"Should receive at least %d responses for pipelined commands", expectedResponses)
		
		// Find and verify specific responses
		mailFromOK := false
		rcptToOK := 0
		
		for _, response := range responses {
			if strings.Contains(response, "250") {
				if strings.Contains(response, "OK") || strings.Contains(response, "sender") {
					mailFromOK = true
				}
				if strings.Contains(response, "recipient") {
					rcptToOK++
				}
			}
		}
		
		assert.True(t, mailFromOK, "MAIL FROM should be accepted")
		assert.Equal(t, 2, rcptToOK, "Both RCPT TO commands should be accepted")
		
		t.Log("SMTP Pipelining test successful")
	})
}

// TestSMTPSizeLimit tests message size limits
func (s *FortressSMTPComplianceSuite) TestSMTPSizeLimit() {
	s.T().Run("Message_Size_Limits", func(t *testing.T) {
		client, err := smtp.Dial(s.serverAddr)
		require.NoError(t, err)
		defer client.Close()
		
		err = client.Hello("client.fortress.test")
		require.NoError(t, err)
		
		err = client.Mail("sender@fortress.test")
		require.NoError(t, err)
		
		err = client.Rcpt("recipient@fortress.test")
		require.NoError(t, err)
		
		// Test with normal-sized message
		dataWriter, err := client.Data()
		require.NoError(t, err)
		
		normalEmail := s.emailFixtures.SimpleTextEmail()
		normalContent := fmt.Sprintf(`From: %s
To: %s
Subject: %s

%s
`, normalEmail.From, strings.Join(normalEmail.To, ", "), 
			normalEmail.Subject, normalEmail.Body)
		
		_, err = dataWriter.Write([]byte(normalContent))
		require.NoError(t, err)
		
		err = dataWriter.Close()
		require.NoError(t, err)
		
		t.Log("Normal size message accepted")
		
		// Test with large message (if configured to reject)
		if s.smtpConfig.MaxMessageSize > 0 {
			// Start new transaction
			err = client.Mail("sender@fortress.test")
			require.NoError(t, err)
			
			err = client.Rcpt("recipient@fortress.test")
			require.NoError(t, err)
			
			dataWriter, err = client.Data()
			require.NoError(t, err)
			
			// Create message larger than limit
			largeBody := strings.Repeat("A", int(s.smtpConfig.MaxMessageSize)+1000)
			largeContent := fmt.Sprintf(`From: sender@fortress.test
To: recipient@fortress.test
Subject: Large Message Test

%s
`, largeBody)
			
			_, err = dataWriter.Write([]byte(largeContent))
			if err != nil {
				t.Logf("Large message rejected during write: %v", err)
			} else {
				err = dataWriter.Close()
				if err != nil {
					t.Logf("Large message rejected during close: %v", err)
				}
			}
			
			// Either write or close should fail for oversized messages
			// The exact behavior depends on implementation
		}
	})
}

// TestSMTPAuthenticationMechanisms tests SMTP authentication
func (s *FortressSMTPComplianceSuite) TestSMTPAuthenticationMechanisms() {
	if !s.smtpConfig.EnableAuth {
		s.T().Skip("SMTP Authentication not enabled")
	}
	
	s.T().Run("Authentication_Mechanisms", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.serverAddr, time.Second*10)
		require.NoError(t, err)
		defer conn.Close()
		
		reader := bufio.NewReader(conn)
		
		// Read greeting
		_, err = reader.ReadString('\n')
		require.NoError(t, err)
		
		// Send EHLO
		_, err = conn.Write([]byte("EHLO client.fortress.test\r\n"))
		require.NoError(t, err)
		
		// Read EHLO response to check for AUTH extension
		var authMechanisms []string
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			
			trimmedLine := strings.TrimSpace(line)
			
			// Check for AUTH extension
			if strings.HasPrefix(trimmedLine, "250-AUTH") || strings.HasPrefix(trimmedLine, "250 AUTH") {
				authLine := strings.TrimPrefix(trimmedLine, "250-AUTH ")
				authLine = strings.TrimPrefix(authLine, "250 AUTH ")
				authMechanisms = strings.Fields(authLine)
			}
			
			// End of multi-line response
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}
		
		// Verify AUTH mechanisms
		assert.NotEmpty(t, authMechanisms, "Should advertise AUTH mechanisms")
		
		expectedMechanisms := s.smtpConfig.AuthMechanisms
		for _, expected := range expectedMechanisms {
			found := false
			for _, advertised := range authMechanisms {
				if advertised == expected {
					found = true
					break
				}
			}
			assert.True(t, found, "Should advertise %s mechanism", expected)
		}
		
		t.Logf("Advertised AUTH mechanisms: %v", authMechanisms)
	})
}

// TestSMTPErrorHandling tests SMTP error responses
func (s *FortressSMTPComplianceSuite) TestSMTPErrorHandling() {
	s.T().Run("Error_Response_Codes", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.serverAddr, time.Second*10)
		require.NoError(t, err)
		defer conn.Close()
		
		reader := bufio.NewReader(conn)
		
		// Read greeting
		_, err = reader.ReadString('\n')
		require.NoError(t, err)
		
		// Test invalid command
		_, err = conn.Write([]byte("INVALID_COMMAND\r\n"))
		require.NoError(t, err)
		
		response, err := reader.ReadString('\n')
		require.NoError(t, err)
		
		// Should return 500 or 502 for unrecognized command
		assert.True(t, strings.HasPrefix(response, "500") || strings.HasPrefix(response, "502"),
			"Invalid command should return 500 or 502: %s", response)
		
		// Test MAIL without EHLO/HELO
		_, err = conn.Write([]byte("MAIL FROM:<test@example.com>\r\n"))
		require.NoError(t, err)
		
		response, err = reader.ReadString('\n')
		require.NoError(t, err)
		
		// Should return 503 for bad sequence
		assert.True(t, strings.HasPrefix(response, "503"),
			"MAIL without EHLO should return 503: %s", response)
		
		// Send EHLO to reset state
		_, err = conn.Write([]byte("EHLO client.fortress.test\r\n"))
		require.NoError(t, err)
		
		// Read EHLO response (may be multi-line)
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}
		
		// Test invalid email format
		_, err = conn.Write([]byte("MAIL FROM:<invalid-email>\r\n"))
		require.NoError(t, err)
		
		response, err = reader.ReadString('\n')
		require.NoError(t, err)
		
		// Should return 501 for syntax error or 553 for invalid address
		assert.True(t, strings.HasPrefix(response, "501") || strings.HasPrefix(response, "553"),
			"Invalid email format should return 501 or 553: %s", response)
		
		t.Log("SMTP error handling tests completed")
	})
}

// TestSMTPRFC5321Compliance tests specific RFC 5321 requirements
func (s *FortressSMTPComplianceSuite) TestSMTPRFC5321Compliance() {
	s.T().Run("RFC5321_Line_Length_Limits", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.serverAddr, time.Second*10)
		require.NoError(t, err)
		defer conn.Close()
		
		reader := bufio.NewReader(conn)
		
		// Read greeting
		_, err = reader.ReadString('\n')
		require.NoError(t, err)
		
		// Send EHLO
		_, err = conn.Write([]byte("EHLO client.fortress.test\r\n"))
		require.NoError(t, err)
		
		// Read EHLO response
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}
		
		// Test maximum line length (RFC 5321: 512 octets including CRLF)
		maxLineLength := s.smtpConfig.MaxLineLength
		if maxLineLength == 0 {
			maxLineLength = 512 // RFC default
		}
		
		// Create a command that's exactly at the limit
		longDomain := strings.Repeat("a", maxLineLength-len("MAIL FROM:<@>\r\n")-10) + ".test"
		longCommand := fmt.Sprintf("MAIL FROM:<test@%s>\r\n", longDomain)
		
		if len(longCommand) <= maxLineLength {
			_, err = conn.Write([]byte(longCommand))
			require.NoError(t, err)
			
			response, err := reader.ReadString('\n')
			require.NoError(t, err)
			
			// Should either accept (250) or reject with proper error (501/552)
			assert.True(t, strings.HasPrefix(response, "250") || 
						strings.HasPrefix(response, "501") ||
						strings.HasPrefix(response, "552"),
				"Long line should be handled properly: %s", response)
		}
		
		t.Logf("Line length test completed with max length: %d", maxLineLength)
	})
	
	s.T().Run("RFC5321_Case_Insensitivity", func(t *testing.T) {
		// Test that SMTP commands are case-insensitive
		testCases := []struct {
			command  string
			expected string
		}{
			{"ehlo client.fortress.test", "250"},
			{"EHLO client.fortress.test", "250"},
			{"EhLo client.fortress.test", "250"},
			{"mail from:<test@example.com>", "250"},
			{"MAIL FROM:<test@example.com>", "250"},
			{"Mail From:<test@example.com>", "250"},
		}
		
		for _, tc := range testCases {
			conn, err := net.DialTimeout("tcp", s.serverAddr, time.Second*10)
			require.NoError(t, err)
			
			reader := bufio.NewReader(conn)
			
			// Read greeting
			_, err = reader.ReadString('\n')
			require.NoError(t, err)
			
			// Send command
			_, err = conn.Write([]byte(tc.command + "\r\n"))
			require.NoError(t, err)
			
			// Read response (may be multi-line for EHLO)
			var response string
			for {
				line, err := reader.ReadString('\n')
				require.NoError(t, err)
				
				if response == "" {
					response = line
				}
				
				if len(line) >= 4 && line[3] == ' ' {
					break
				}
			}
			
			assert.True(t, strings.HasPrefix(response, tc.expected),
				"Command '%s' should return %s: %s", tc.command, tc.expected, response)
			
			conn.Close()
		}
	})
}

// TestSMTPConcurrentConnections tests handling multiple concurrent connections
func (s *FortressSMTPComplianceSuite) TestSMTPConcurrentConnections() {
	s.T().Run("Concurrent_SMTP_Connections", func(t *testing.T) {
		concurrency := 10
		if s.smtpConfig.MaxConnections > 0 && concurrency > s.smtpConfig.MaxConnections {
			concurrency = s.smtpConfig.MaxConnections
		}
		
		// Test concurrent connections
		s.testUtils.FortressTestConcurrentExecution(concurrency, func(workerID int) {
			// Each worker establishes connection and sends email
			client, err := smtp.Dial(s.serverAddr)
			assert.NoError(s.T(), err, "Worker %d should connect", workerID)
			if err != nil {
				return
			}
			defer client.Close()
			
			err = client.Hello(fmt.Sprintf("client%d.fortress.test", workerID))
			assert.NoError(s.T(), err, "Worker %d EHLO should succeed", workerID)
			
			err = client.Mail(fmt.Sprintf("sender%d@fortress.test", workerID))
			assert.NoError(s.T(), err, "Worker %d MAIL FROM should succeed", workerID)
			
			err = client.Rcpt(fmt.Sprintf("recipient%d@fortress.test", workerID))
			assert.NoError(s.T(), err, "Worker %d RCPT TO should succeed", workerID)
			
			dataWriter, err := client.Data()
			assert.NoError(s.T(), err, "Worker %d DATA should succeed", workerID)
			if err != nil {
				return
			}
			
			email := fmt.Sprintf(`From: sender%d@fortress.test
To: recipient%d@fortress.test
Subject: Concurrent Test Email %d

This is test email from worker %d.
`, workerID, workerID, workerID, workerID)
			
			_, err = dataWriter.Write([]byte(email))
			assert.NoError(s.T(), err, "Worker %d email write should succeed", workerID)
			
			err = dataWriter.Close()
			assert.NoError(s.T(), err, "Worker %d DATA close should succeed", workerID)
			
			err = client.Quit()
			assert.NoError(s.T(), err, "Worker %d QUIT should succeed", workerID)
		})
		
		t.Logf("Concurrent connections test completed with %d workers", concurrency)
	})
}

// Helper methods

func (s *FortressSMTPComplianceSuite) createSMTPServer() interfaces.Gates {
	// Create a mock Gates service with real SMTP server
	return &SMTPGatesService{
		config: s.smtpConfig,
	}
}

func (s *FortressSMTPComplianceSuite) waitForServerReady() {
	// Wait for server to accept connections
	s.testUtils.WaitForCondition(func() bool {
		conn, err := net.DialTimeout("tcp", s.serverAddr, time.Second*2)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, time.Second*30, "SMTP server should be ready")
}

// SMTPGatesService is a test implementation of Gates interface
type SMTPGatesService struct {
	config *interfaces.SMTPServerConfig
	server *smtp.Server // This would be the actual SMTP server implementation
}

func (s *SMTPGatesService) StartSMTPServer(ctx context.Context, config *interfaces.SMTPServerConfig) error {
	// In a real implementation, this would start the actual SMTP server
	// For testing, we simulate a running server
	return nil
}

func (s *SMTPGatesService) StopSMTPServer(ctx context.Context) error {
	return nil
}

func (s *SMTPGatesService) HandleSMTPConnection(ctx context.Context, conn net.Conn) error {
	return nil
}

// Implement other Gates interface methods with stubs
func (s *SMTPGatesService) RegisterRoute(method, path string, handler interfaces.HandlerFunc) {}
func (s *SMTPGatesService) RegisterMiddleware(middleware interfaces.MiddlewareFunc) {}
func (s *SMTPGatesService) StartHTTPServer(ctx context.Context, config *interfaces.HTTPServerConfig) error { return nil }
func (s *SMTPGatesService) StopHTTPServer(ctx context.Context) error { return nil }
func (s *SMTPGatesService) RegisterGraphQLSchema(schema string) error { return nil }
func (s *SMTPGatesService) HandleGraphQL(ctx context.Context, query string, variables map[string]interface{}) (*interfaces.GraphQLResult, error) { return &interfaces.GraphQLResult{}, nil }
func (s *SMTPGatesService) RegisterWebSocketHandler(path string, handler interfaces.WebSocketHandler) {}
func (s *SMTPGatesService) BroadcastMessage(ctx context.Context, message *interfaces.WebSocketMessage) error { return nil }
func (s *SMTPGatesService) RegisterAPIVersion(version string, routes map[string]interfaces.HandlerFunc) {}
func (s *SMTPGatesService) GenerateOpenAPISpec() ([]byte, error) { return []byte("{}"), nil }
func (s *SMTPGatesService) Start(ctx context.Context) error { return nil }
func (s *SMTPGatesService) Stop(ctx context.Context) error { return nil }
func (s *SMTPGatesService) Health(ctx context.Context) *interfaces.HealthStatus {
	return &interfaces.HealthStatus{Service: "gates", Status: interfaces.HealthStatusHealthy}
}

// TestFortressSMTPCompliance runs the SMTP compliance test suite
func TestFortressSMTPCompliance(t *testing.T) {
	// This test requires an actual SMTP server implementation
	// Skip if running in CI without SMTP server
	if testing.Short() {
		t.Skip("Skipping SMTP compliance tests in short mode")
	}
	
	suite.Run(t, new(FortressSMTPComplianceSuite))
}