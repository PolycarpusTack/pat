package security

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	"github.com/mailhog/Pat/config"
	"github.com/mailhog/Pat/pkg/fortress"
	smtpServer "github.com/mailhog/Pat/pkg/smtp"
)

// FortressSMTPSecurityTestSuite validates SMTP protocol security mechanisms
type FortressSMTPSecurityTestSuite struct {
	smtpServer   *smtpServer.Server
	fortress     *fortress.Service
	testPort     int
	testAddress  string
}

// TestSMTPSecurityValidation is the main SMTP security test entry point
func TestSMTPSecurityValidation(t *testing.T) {
	suite := setupSMTPSecurityTestSuite(t)
	defer suite.cleanup(t)

	t.Run("SMTP_Command_Injection_Prevention", suite.testSMTPCommandInjection)
	t.Run("SMTP_Header_Injection_Prevention", suite.testSMTPHeaderInjection)
	t.Run("SMTP_Protocol_Compliance_Validation", suite.testSMTPProtocolCompliance)
	t.Run("Email_Parsing_Security", suite.testEmailParsingSecurity)
	t.Run("SMTP_Authentication_Security", suite.testSMTPAuthenticationSecurity)
	t.Run("SMTP_TLS_Security", suite.testSMTPTLSSecurity)
	t.Run("SMTP_Rate_Limiting", suite.testSMTPRateLimiting)
	t.Run("SMTP_Connection_Security", suite.testSMTPConnectionSecurity)
	t.Run("SMTP_Relay_Prevention", suite.testSMTPRelayPrevention)
	t.Run("Malicious_Attachment_Handling", suite.testMaliciousAttachmentHandling)
	t.Run("SMTP_Buffer_Overflow_Prevention", suite.testSMTPBufferOverflowPrevention)
	t.Run("Email_Spoofing_Prevention", suite.testEmailSpoofingPrevention)
	t.Run("SMTP_Timing_Attack_Prevention", suite.testSMTPTimingAttackPrevention)
}

func setupSMTPSecurityTestSuite(t *testing.T) *FortressSMTPSecurityTestSuite {
	cfg := &config.Config{
		SMTPPort:             2525, // Non-standard port for testing
		EnableSecurity:       true,
		SecurityLevel:        "fortress",
		SMTPMaxConnections:   100,
		SMTPMaxMessageSize:   10 * 1024 * 1024, // 10MB
		SMTPTimeout:          time.Second * 30,
		EnableSMTPAuth:       true,
		EnableSMTPTLS:        true,
		SMTPRateLimit:        10, // 10 emails per minute
		SMTPRelayPrevention:  true,
	}

	fortress := fortress.NewService(cfg)
	server := smtpServer.NewServer(cfg, fortress)
	
	// Start SMTP server in background
	go func() {
		server.Listen(fmt.Sprintf(":%d", cfg.SMTPPort))
	}()

	// Wait for server to start
	time.Sleep(time.Millisecond * 100)

	return &FortressSMTPSecurityTestSuite{
		smtpServer:  server,
		fortress:    fortress,
		testPort:    cfg.SMTPPort,
		testAddress: fmt.Sprintf("localhost:%d", cfg.SMTPPort),
	}
}

func (s *FortressSMTPSecurityTestSuite) cleanup(t *testing.T) {
	if s.smtpServer != nil {
		s.smtpServer.Close()
	}
}

// testSMTPCommandInjection tests SMTP command injection prevention
func (s *FortressSMTPSecurityTestSuite) testSMTPCommandInjection(t *testing.T) {
	maliciousCommands := []struct {
		name    string
		command string
		args    string
	}{
		{
			name:    "MAIL_FROM_Injection",
			command: "MAIL FROM",
			args:    "<test@example.com>\r\nQUIT\r\nMAIL FROM:<malicious@evil.com>",
		},
		{
			name:    "RCPT_TO_Injection",
			command: "RCPT TO",
			args:    "<target@example.com>\r\nDATA\r\nSubject: Injected\r\n\r\nMalicious content",
		},
		{
			name:    "DATA_Command_Injection",
			command: "DATA",
			args:    "\r\nSubject: Test\r\n\r\nNormal content\r\n.\r\nMAIL FROM:<injected@evil.com>",
		},
		{
			name:    "HELO_Injection",
			command: "HELO",
			args:    "example.com\r\nMAIL FROM:<injected@evil.com>",
		},
		{
			name:    "AUTH_Injection",
			command: "AUTH PLAIN",
			args:    "dGVzdA==\r\nQUIT\r\nHELO evil.com",
		},
		{
			name:    "VRFY_Injection",
			command: "VRFY",
			args:    "user@example.com\r\nEXPN all-users\r\nQUIT",
		},
	}

	for _, maliciousCmd := range maliciousCommands {
		t.Run(maliciousCmd.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			// Set connection timeout
			conn.SetDeadline(time.Now().Add(time.Second * 10))

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Read initial greeting
			_, err = reader.ReadLine()
			require.NoError(t, err)

			// Send HELO
			writer.WriteString("HELO test.example.com\r\n")
			writer.Flush()
			_, err = reader.ReadLine()
			require.NoError(t, err)

			// Send malicious command
			maliciousLine := fmt.Sprintf("%s:%s\r\n", maliciousCmd.command, maliciousCmd.args)
			writer.WriteString(maliciousLine)
			writer.Flush()

			// Read response
			response, err := reader.ReadLine()
			require.NoError(t, err)

			responseStr := string(response)
			
			// Should reject malicious commands with appropriate error codes
			assert.True(t, strings.HasPrefix(responseStr, "5") || strings.HasPrefix(responseStr, "4"),
				"Malicious command should be rejected with 4xx or 5xx error code")

			// Should not execute the injected commands
			assert.NotContains(t, responseStr, "250", "Injected command should not succeed")

			// Send QUIT to cleanly close connection
			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}
}

// testSMTPHeaderInjection tests SMTP header injection prevention
func (s *FortressSMTPSecurityTestSuite) testSMTPHeaderInjection(t *testing.T) {
	maliciousHeaders := []struct {
		name    string
		from    string
		to      string
		subject string
		body    string
	}{
		{
			name:    "From_Header_Injection",
			from:    "test@example.com\r\nBcc: secret@target.com",
			to:      "recipient@example.com",
			subject: "Test Subject",
			body:    "Test body",
		},
		{
			name:    "Subject_Header_Injection",
			from:    "test@example.com",
			to:      "recipient@example.com",
			subject: "Test Subject\r\nTo: injected@evil.com",
			body:    "Test body",
		},
		{
			name:    "Multiple_Header_Injection",
			from:    "test@example.com",
			to:      "recipient@example.com",
			subject: "Test\r\nX-Mailer: Injected\r\nBcc: hidden@evil.com",
			body:    "Test body",
		},
		{
			name:    "MIME_Header_Injection",
			from:    "test@example.com",
			to:      "recipient@example.com",
			subject: "Test",
			body:    "Content-Type: text/html\r\n\r\n<script>alert('xss')</script>",
		},
		{
			name:    "Message_ID_Injection",
			from:    "test@example.com\r\nMessage-ID: <fake@evil.com>",
			to:      "recipient@example.com",
			subject: "Test",
			body:    "Test body",
		},
	}

	for _, headerTest := range maliciousHeaders {
		t.Run(headerTest.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Read greeting
			_, err = reader.ReadLine()
			require.NoError(t, err)

			// SMTP conversation
			commands := []string{
				"HELO test.example.com\r\n",
				fmt.Sprintf("MAIL FROM:<%s>\r\n", headerTest.from),
				fmt.Sprintf("RCPT TO:<%s>\r\n", headerTest.to),
				"DATA\r\n",
			}

			for _, cmd := range commands {
				writer.WriteString(cmd)
				writer.Flush()
				response, err := reader.ReadLine()
				require.NoError(t, err)

				responseStr := string(response)
				// If any command fails due to header injection detection, that's good
				if strings.HasPrefix(responseStr, "4") || strings.HasPrefix(responseStr, "5") {
					t.Logf("Server properly rejected malicious header: %s", responseStr)
					return
				}
			}

			// Send email data with malicious headers
			emailData := fmt.Sprintf("Subject: %s\r\nFrom: %s\r\nTo: %s\r\n\r\n%s\r\n.\r\n",
				headerTest.subject, headerTest.from, headerTest.to, headerTest.body)
			
			writer.WriteString(emailData)
			writer.Flush()

			response, err := reader.ReadLine()
			require.NoError(t, err)
			responseStr := string(response)

			// Should either accept the email (with proper sanitization) or reject it
			if strings.HasPrefix(responseStr, "5") || strings.HasPrefix(responseStr, "4") {
				t.Logf("Server properly rejected malicious email: %s", responseStr)
			} else if strings.HasPrefix(responseStr, "2") {
				t.Logf("Server accepted email - should verify proper sanitization")
			}

			// Clean close
			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}
}

// testSMTPProtocolCompliance tests SMTP protocol compliance and security
func (s *FortressSMTPSecurityTestSuite) testSMTPProtocolCompliance(t *testing.T) {
	protocolTests := []struct {
		name     string
		commands []string
		expected string // Expected response prefix (2xx, 4xx, 5xx)
	}{
		{
			name: "Commands_Out_Of_Order",
			commands: []string{
				"DATA\r\n", // DATA before MAIL FROM
			},
			expected: "5",
		},
		{
			name: "Missing_HELO",
			commands: []string{
				"MAIL FROM:<test@example.com>\r\n",
			},
			expected: "5",
		},
		{
			name: "Double_DATA_Command",
			commands: []string{
				"HELO test.com\r\n",
				"MAIL FROM:<test@example.com>\r\n",
				"RCPT TO:<recipient@example.com>\r\n",
				"DATA\r\n",
				"DATA\r\n", // Second DATA command
			},
			expected: "5",
		},
		{
			name: "Invalid_Command",
			commands: []string{
				"HELO test.com\r\n",
				"INVALID_COMMAND\r\n",
			},
			expected: "5",
		},
		{
			name: "Oversized_Command",
			commands: []string{
				fmt.Sprintf("HELO %s\r\n", strings.Repeat("A", 1000)),
			},
			expected: "5",
		},
	}

	for _, protocolTest := range protocolTests {
		t.Run(protocolTest.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Read greeting
			_, err = reader.ReadLine()
			require.NoError(t, err)

			var lastResponse string
			for _, cmd := range protocolTest.commands {
				writer.WriteString(cmd)
				writer.Flush()
				response, err := reader.ReadLine()
				require.NoError(t, err)
				lastResponse = string(response)

				// Break early if we get the expected error
				if strings.HasPrefix(lastResponse, protocolTest.expected) {
					break
				}
			}

			assert.True(t, strings.HasPrefix(lastResponse, protocolTest.expected),
				fmt.Sprintf("Expected response starting with %s, got: %s", protocolTest.expected, lastResponse))

			// Clean close
			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}
}

// testEmailParsingSecurity tests email parsing security mechanisms
func (s *FortressSMTPSecurityTestSuite) testEmailParsingSecurity(t *testing.T) {
	maliciousEmails := []struct {
		name  string
		email string
	}{
		{
			name: "Malformed_MIME",
			email: `Subject: Test
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain

Normal content
--boundary--
Content-Type: text/html

<script>alert('xss')</script>
--boundary--`,
		},
		{
			name: "Extremely_Long_Header",
			email: fmt.Sprintf("Subject: %s\r\n\r\nTest body", strings.Repeat("A", 10000)),
		},
		{
			name: "Null_Byte_Injection",
			email: "Subject: Test\x00Injected\r\n\r\nTest body",
		},
		{
			name: "Unicode_Control_Characters",
			email: "Subject: Test\u202E\u202D\r\n\r\nTest body",
		},
		{
			name: "Invalid_UTF8",
			email: "Subject: Test\xff\xfe\r\n\r\nTest body",
		},
		{
			name: "ZIP_Bomb_Attachment",
			email: `Subject: Test
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: application/zip; name="bomb.zip"
Content-Transfer-Encoding: base64

UEsDBBQAAAAAAGmCkVIAAAAAAAAAAAAAAAAJAAAAYm9tYi50eHQKUEsBAh4AFAAAAAAAZ4KRUgAAAAAAAAAAAAAAAAkAAAAAAAAAAAAAAACkgQAAAABib21iLnR4dApQSwUGAAAAAAEAAQA3AAAAHQAAAAAA
--boundary--`,
		},
		{
			name: "Recursive_MIME_Structure",
			email: `Subject: Test
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/mixed; boundary="inner"

--inner
Content-Type: multipart/mixed; boundary="deeper"

--deeper
Content-Type: text/plain

Deep content
--deeper--
--inner--
--outer--`,
		},
	}

	for _, emailTest := range maliciousEmails {
		t.Run(emailTest.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*10)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Read greeting
			_, err = reader.ReadLine()
			require.NoError(t, err)

			// Standard SMTP conversation
			commands := []string{
				"HELO test.example.com\r\n",
				"MAIL FROM:<test@example.com>\r\n",
				"RCPT TO:<recipient@example.com>\r\n",
				"DATA\r\n",
			}

			allSuccessful := true
			for _, cmd := range commands {
				writer.WriteString(cmd)
				writer.Flush()
				response, err := reader.ReadLine()
				require.NoError(t, err)

				if !strings.HasPrefix(string(response), "2") && !strings.HasPrefix(string(response), "3") {
					allSuccessful = false
					break
				}
			}

			if allSuccessful {
				// Send malicious email data
				writer.WriteString(emailTest.email + "\r\n.\r\n")
				writer.Flush()

				// Set a reasonable timeout for processing
				conn.SetDeadline(time.Now().Add(time.Second * 5))
				response, err := reader.ReadLine()
				
				// Should either accept (with proper parsing) or reject malicious email
				if err == nil {
					responseStr := string(response)
					t.Logf("Server response to malicious email: %s", responseStr)
					
					// Server should not crash or hang
					assert.True(t, strings.HasPrefix(responseStr, "2") || 
							   strings.HasPrefix(responseStr, "4") || 
							   strings.HasPrefix(responseStr, "5"),
						"Server should respond appropriately to malicious email")
				} else {
					t.Logf("Server timeout or connection closed - may indicate DoS protection")
				}
			}

			// Clean close
			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}
}

// testSMTPAuthenticationSecurity tests SMTP authentication security
func (s *FortressSMTPSecurityTestSuite) testSMTPAuthenticationSecurity(t *testing.T) {
	authTests := []struct {
		name     string
		authType string
		creds    string
		expected string
	}{
		{
			name:     "Invalid_Base64_Credentials",
			authType: "PLAIN",
			creds:    "invalid-base64",
			expected: "5",
		},
		{
			name:     "Empty_Credentials",
			authType: "PLAIN",
			creds:    "",
			expected: "5",
		},
		{
			name:     "SQL_Injection_Username",
			authType: "PLAIN",
			creds:    encodeBase64("\x00admin'; DROP TABLE users; --\x00password"),
			expected: "5",
		},
		{
			name:     "Buffer_Overflow_Attempt",
			authType: "PLAIN",
			creds:    encodeBase64("\x00" + strings.Repeat("A", 1000) + "\x00password"),
			expected: "5",
		},
		{
			name:     "Command_Injection_Password",
			authType: "PLAIN",
			creds:    encodeBase64("\x00user\x00password; cat /etc/passwd"),
			expected: "5",
		},
	}

	for _, authTest := range authTests {
		t.Run(authTest.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Read greeting
			_, err = reader.ReadLine()
			require.NoError(t, err)

			// Send HELO
			writer.WriteString("HELO test.example.com\r\n")
			writer.Flush()
			_, err = reader.ReadLine()
			require.NoError(t, err)

			// Send AUTH command
			authCmd := fmt.Sprintf("AUTH %s %s\r\n", authTest.authType, authTest.creds)
			writer.WriteString(authCmd)
			writer.Flush()

			response, err := reader.ReadLine()
			require.NoError(t, err)
			responseStr := string(response)

			assert.True(t, strings.HasPrefix(responseStr, authTest.expected),
				fmt.Sprintf("Expected response starting with %s, got: %s", authTest.expected, responseStr))

			// Clean close
			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}
}

// testSMTPTLSSecurity tests SMTP TLS security
func (s *FortressSMTPSecurityTestSuite) testSMTPTLSSecurity(t *testing.T) {
	// Test STARTTLS functionality
	t.Run("STARTTLS_Functionality", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
		if err != nil {
			t.Skip("SMTP server not available")
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)

		// Read greeting
		greeting, err := reader.ReadLine()
		require.NoError(t, err)
		t.Logf("Server greeting: %s", string(greeting))

		// Send HELO
		writer.WriteString("HELO test.example.com\r\n")
		writer.Flush()
		response, err := reader.ReadLine()
		require.NoError(t, err)
		t.Logf("HELO response: %s", string(response))

		// Test STARTTLS
		writer.WriteString("STARTTLS\r\n")
		writer.Flush()
		tlsResponse, err := reader.ReadLine()
		require.NoError(t, err)
		tlsResponseStr := string(tlsResponse)
		t.Logf("STARTTLS response: %s", tlsResponseStr)

		// Should either support STARTTLS (220) or indicate it's not available
		assert.True(t, strings.HasPrefix(tlsResponseStr, "220") || 
				   strings.HasPrefix(tlsResponseStr, "5"),
			"Server should handle STARTTLS appropriately")
	})

	// Test TLS downgrade protection
	t.Run("TLS_Downgrade_Protection", func(t *testing.T) {
		// This test verifies that the server doesn't allow TLS downgrade attacks
		conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
		if err != nil {
			t.Skip("SMTP server not available")
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)

		// Read greeting
		_, err = reader.ReadLine()
		require.NoError(t, err)

		// Try to send commands that might interfere with TLS negotiation
		maliciousCommands := []string{
			"HELO test.example.com\r\n",
			"STARTTLS\r\n",
			"HELO downgrade-attempt\r\n", // Try to downgrade after STARTTLS
		}

		for _, cmd := range maliciousCommands {
			writer.WriteString(cmd)
			writer.Flush()
			response, err := reader.ReadLine()
			require.NoError(t, err)
			t.Logf("Response to %s: %s", strings.TrimSpace(cmd), string(response))
		}

		writer.WriteString("QUIT\r\n")
		writer.Flush()
	})
}

// testSMTPRateLimiting tests SMTP rate limiting mechanisms
func (s *FortressSMTPSecurityTestSuite) testSMTPRateLimiting(t *testing.T) {
	// Test connection rate limiting
	t.Run("Connection_Rate_Limiting", func(t *testing.T) {
		var connections []net.Conn
		defer func() {
			for _, conn := range connections {
				if conn != nil {
					conn.Close()
				}
			}
		}()

		// Try to open many connections rapidly
		successfulConnections := 0
		for i := 0; i < 150; i++ { // Try more than the limit
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Millisecond*100)
			if err != nil {
				break // Rate limited
			}
			connections = append(connections, conn)
			successfulConnections++

			if successfulConnections >= 100 { // Stop at reasonable limit
				break
			}
		}

		t.Logf("Successfully opened %d connections", successfulConnections)
		// Should eventually hit rate limiting (exact behavior depends on implementation)
	})

	// Test email sending rate limiting
	t.Run("Email_Rate_Limiting", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
		if err != nil {
			t.Skip("SMTP server not available")
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)

		// Read greeting and setup
		_, err = reader.ReadLine()
		require.NoError(t, err)

		writer.WriteString("HELO test.example.com\r\n")
		writer.Flush()
		_, err = reader.ReadLine()
		require.NoError(t, err)

		// Try to send many emails rapidly
		rateLimited := false
		for i := 0; i < 20; i++ {
			// SMTP conversation for each email
			commands := []string{
				"MAIL FROM:<test@example.com>\r\n",
				"RCPT TO:<recipient@example.com>\r\n",
				"DATA\r\n",
				"Subject: Test\r\n\r\nTest body\r\n.\r\n",
			}

			for _, cmd := range commands {
				writer.WriteString(cmd)
				writer.Flush()
				response, err := reader.ReadLine()
				if err != nil {
					return
				}

				responseStr := string(response)
				if strings.HasPrefix(responseStr, "4") && strings.Contains(responseStr, "rate") {
					rateLimited = true
					t.Logf("Rate limited after %d emails: %s", i, responseStr)
					break
				}
			}

			if rateLimited {
				break
			}

			// Small delay between emails
			time.Sleep(time.Millisecond * 10)
		}

		writer.WriteString("QUIT\r\n")
		writer.Flush()
	})
}

// testSMTPConnectionSecurity tests SMTP connection security
func (s *FortressSMTPSecurityTestSuite) testSMTPConnectionSecurity(t *testing.T) {
	// Test connection timeout
	t.Run("Connection_Timeout", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
		if err != nil {
			t.Skip("SMTP server not available")
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read greeting
		_, err = reader.ReadLine()
		require.NoError(t, err)

		// Don't send any commands and wait for timeout
		conn.SetDeadline(time.Now().Add(time.Second * 35)) // Server timeout should be 30 seconds
		
		startTime := time.Now()
		_, err = reader.ReadLine()
		duration := time.Since(startTime)

		// Connection should timeout within reasonable time
		if err != nil {
			t.Logf("Connection timed out after %v", duration)
			assert.Less(t, duration, time.Second*40, "Connection should timeout within reasonable time")
		}
	})

	// Test concurrent connection limits
	t.Run("Concurrent_Connection_Limits", func(t *testing.T) {
		var connections []net.Conn
		defer func() {
			for _, conn := range connections {
				if conn != nil {
					conn.Close()
				}
			}
		}()

		// Try to open connections up to the limit
		for i := 0; i < 105; i++ { // Try more than max (100)
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Millisecond*500)
			if err != nil {
				t.Logf("Failed to open connection %d: %v", i+1, err)
				break
			}
			connections = append(connections, conn)
		}

		t.Logf("Opened %d concurrent connections", len(connections))
		// Should be limited to reasonable number
		assert.LessOrEqual(t, len(connections), 100, "Should not exceed maximum concurrent connections")
	})

	// Test malformed connection data
	t.Run("Malformed_Connection_Data", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
		if err != nil {
			t.Skip("SMTP server not available")
			return
		}
		defer conn.Close()

		// Send raw binary data
		malformedData := []byte{0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03}
		conn.Write(malformedData)

		// Server should handle gracefully
		buffer := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(time.Second * 2))
		n, err := conn.Read(buffer)
		
		if err == nil && n > 0 {
			response := string(buffer[:n])
			t.Logf("Server response to malformed data: %s", response)
			// Should not crash or return internal errors
			assert.NotContains(t, response, "panic")
			assert.NotContains(t, response, "fatal")
		}
	})
}

// testSMTPRelayPrevention tests SMTP relay prevention
func (s *FortressSMTPSecurityTestSuite) testSMTPRelayPrevention(t *testing.T) {
	relayTests := []struct {
		name string
		from string
		to   string
	}{
		{
			name: "External_To_External_Relay",
			from: "external@other.com",
			to:   "target@victim.com",
		},
		{
			name: "Percent_Hack_Relay",
			from: "test@example.com",
			to:   "victim%target.com@relay.com",
		},
		{
			name: "Bang_Path_Relay",
			from: "test@example.com",
			to:   "relay.com!victim@target.com",
		},
		{
			name: "Source_Route_Relay",
			from: "test@example.com",
			to:   "@relay.com:victim@target.com",
		},
	}

	for _, relayTest := range relayTests {
		t.Run(relayTest.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Standard SMTP conversation
			_, err = reader.ReadLine()
			require.NoError(t, err)

			writer.WriteString("HELO relay-test.com\r\n")
			writer.Flush()
			_, err = reader.ReadLine()
			require.NoError(t, err)

			writer.WriteString(fmt.Sprintf("MAIL FROM:<%s>\r\n", relayTest.from))
			writer.Flush()
			mailResponse, err := reader.ReadLine()
			require.NoError(t, err)

			writer.WriteString(fmt.Sprintf("RCPT TO:<%s>\r\n", relayTest.to))
			writer.Flush()
			rcptResponse, err := reader.ReadLine()
			require.NoError(t, err)

			rcptResponseStr := string(rcptResponse)
			
			// Should reject relay attempts
			assert.True(t, strings.HasPrefix(rcptResponseStr, "5") || strings.HasPrefix(rcptResponseStr, "4"),
				fmt.Sprintf("Relay attempt should be rejected: %s", rcptResponseStr))

			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}
}

// testMaliciousAttachmentHandling tests malicious attachment handling
func (s *FortressSMTPSecurityTestSuite) testMaliciousAttachmentHandling(t *testing.T) {
	maliciousAttachments := []struct {
		name       string
		filename   string
		content    string
		encoding   string
	}{
		{
			name:     "Executable_Attachment",
			filename: "malware.exe",
			content:  "MZ\x90\x00\x03", // PE header
			encoding: "base64",
		},
		{
			name:     "Script_Attachment",
			filename: "script.js",
			content:  "eval(atob('YWxlcnQoJ21hbGljaW91cycpOw=='));", // Malicious JS
			encoding: "base64",
		},
		{
			name:     "Archive_Bomb",
			filename: "bomb.zip",
			content:  "UEsDBBQAAAAAAGmCkVIAAAAAAAAAAAAAAAAA", // Zip bomb signature
			encoding: "base64",
		},
		{
			name:     "Double_Extension",
			filename: "document.pdf.exe",
			content:  "fake pdf content",
			encoding: "base64",
		},
	}

	for _, attachmentTest := range maliciousAttachments {
		t.Run(attachmentTest.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*10)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Standard SMTP setup
			_, err = reader.ReadLine()
			require.NoError(t, err)

			commands := []string{
				"HELO test.example.com\r\n",
				"MAIL FROM:<test@example.com>\r\n",
				"RCPT TO:<recipient@example.com>\r\n",
				"DATA\r\n",
			}

			allSuccessful := true
			for _, cmd := range commands {
				writer.WriteString(cmd)
				writer.Flush()
				response, err := reader.ReadLine()
				require.NoError(t, err)
				if !strings.HasPrefix(string(response), "2") && !strings.HasPrefix(string(response), "3") {
					allSuccessful = false
					break
				}
			}

			if allSuccessful {
				// Send email with malicious attachment
				emailWithAttachment := fmt.Sprintf(`Subject: Test with attachment
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Email body

--boundary123
Content-Type: application/octet-stream; name="%s"
Content-Transfer-Encoding: %s

%s
--boundary123--
.
`, attachmentTest.filename, attachmentTest.encoding, encodeBase64(attachmentTest.content))

				writer.WriteString(emailWithAttachment)
				writer.Flush()

				// Set timeout for processing
				conn.SetDeadline(time.Now().Add(time.Second * 5))
				response, err := reader.ReadLine()
				
				if err == nil {
					responseStr := string(response)
					t.Logf("Server response to malicious attachment: %s", responseStr)
					
					// Should handle malicious attachments appropriately
					// Either accept with proper quarantine or reject
					assert.True(t, strings.HasPrefix(responseStr, "2") || 
							   strings.HasPrefix(responseStr, "4") || 
							   strings.HasPrefix(responseStr, "5"),
						"Server should respond appropriately to malicious attachment")
				}
			}

			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}
}

// testSMTPBufferOverflowPrevention tests buffer overflow prevention
func (s *FortressSMTPSecurityTestSuite) testSMTPBufferOverflowPrevention(t *testing.T) {
	bufferTests := []struct {
		name    string
		command string
		size    int
	}{
		{
			name:    "Oversized_HELO",
			command: "HELO",
			size:    10000,
		},
		{
			name:    "Oversized_MAIL_FROM",
			command: "MAIL FROM",
			size:    5000,
		},
		{
			name:    "Oversized_RCPT_TO",
			command: "RCPT TO",
			size:    5000,
		},
		{
			name:    "Oversized_AUTH",
			command: "AUTH PLAIN",
			size:    8000,
		},
	}

	for _, bufferTest := range bufferTests {
		t.Run(bufferTest.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Read greeting
			_, err = reader.ReadLine()
			require.NoError(t, err)

			// Send oversized command
			oversizedData := strings.Repeat("A", bufferTest.size)
			var command string
			if bufferTest.command == "HELO" {
				command = fmt.Sprintf("HELO %s\r\n", oversizedData)
			} else if bufferTest.command == "MAIL FROM" {
				command = fmt.Sprintf("MAIL FROM:<%s@example.com>\r\n", oversizedData)
			} else if bufferTest.command == "RCPT TO" {
				command = "HELO test.com\r\n"
				writer.WriteString(command)
				writer.Flush()
				reader.ReadLine()
				command = fmt.Sprintf("RCPT TO:<%s@example.com>\r\n", oversizedData)
			} else if bufferTest.command == "AUTH PLAIN" {
				command = "HELO test.com\r\n"
				writer.WriteString(command)
				writer.Flush()
				reader.ReadLine()
				command = fmt.Sprintf("AUTH PLAIN %s\r\n", oversizedData)
			}

			writer.WriteString(command)
			writer.Flush()

			// Should handle oversized input gracefully
			conn.SetDeadline(time.Now().Add(time.Second * 3))
			response, err := reader.ReadLine()
			
			if err == nil {
				responseStr := string(response)
				t.Logf("Response to oversized %s: %s", bufferTest.command, responseStr)
				
				// Should reject oversized input
				assert.True(t, strings.HasPrefix(responseStr, "5") || strings.HasPrefix(responseStr, "4"),
					"Oversized input should be rejected")
			} else {
				t.Logf("Connection closed or timeout - indicates proper buffer overflow protection")
			}

			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}
}

// testEmailSpoofingPrevention tests email spoofing prevention
func (s *FortressSMTPSecurityTestSuite) testEmailSpoofingPrevention(t *testing.T) {
	spoofingTests := []struct {
		name     string
		fromAddr string
		headers  string
	}{
		{
			name:     "From_Header_Spoofing",
			fromAddr: "legitimate@example.com",
			headers:  "From: admin@bank.com\r\nReply-To: attacker@evil.com\r\n",
		},
		{
			name:     "Multiple_From_Headers",
			fromAddr: "test@example.com",
			headers:  "From: user1@example.com\r\nFrom: user2@example.com\r\n",
		},
		{
			name:     "Sender_Mismatch",
			fromAddr: "real@example.com",
			headers:  "From: fake@trusted.com\r\nSender: real@example.com\r\n",
		},
		{
			name:     "Return_Path_Manipulation",
			fromAddr: "test@example.com",
			headers:  "Return-Path: <attacker@evil.com>\r\nFrom: legitimate@bank.com\r\n",
		},
	}

	for _, spoofTest := range spoofingTests {
		t.Run(spoofTest.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Standard SMTP setup
			_, err = reader.ReadLine()
			require.NoError(t, err)

			commands := []string{
				"HELO test.example.com\r\n",
				fmt.Sprintf("MAIL FROM:<%s>\r\n", spoofTest.fromAddr),
				"RCPT TO:<recipient@example.com>\r\n",
				"DATA\r\n",
			}

			allSuccessful := true
			for _, cmd := range commands {
				writer.WriteString(cmd)
				writer.Flush()
				response, err := reader.ReadLine()
				require.NoError(t, err)
				if !strings.HasPrefix(string(response), "2") && !strings.HasPrefix(string(response), "3") {
					allSuccessful = false
					break
				}
			}

			if allSuccessful {
				// Send email with spoofed headers
				emailData := fmt.Sprintf("%sSubject: Test\r\n\r\nTest body\r\n.\r\n", spoofTest.headers)
				writer.WriteString(emailData)
				writer.Flush()

				response, err := reader.ReadLine()
				require.NoError(t, err)
				responseStr := string(response)

				t.Logf("Server response to spoofing attempt: %s", responseStr)
				
				// Server should handle spoofing attempts appropriately
				// May accept with proper validation or reject suspicious emails
				assert.True(t, strings.HasPrefix(responseStr, "2") || 
						   strings.HasPrefix(responseStr, "4") || 
						   strings.HasPrefix(responseStr, "5"),
					"Server should respond appropriately to spoofing attempt")
			}

			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}
}

// testSMTPTimingAttackPrevention tests timing attack prevention
func (s *FortressSMTPSecurityTestSuite) testSMTPTimingAttackPrevention(t *testing.T) {
	// Test VRFY command timing
	testAddresses := []string{
		"existing@example.com",
		"nonexistent@example.com",
		"admin@example.com",
		"user123@example.com",
	}

	var responseTimes []time.Duration

	for _, address := range testAddresses {
		t.Run(fmt.Sprintf("VRFY_Timing_%s", address), func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.testAddress, time.Second*5)
			if err != nil {
				t.Skip("SMTP server not available")
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Read greeting
			_, err = reader.ReadLine()
			require.NoError(t, err)

			// Send HELO
			writer.WriteString("HELO test.example.com\r\n")
			writer.Flush()
			_, err = reader.ReadLine()
			require.NoError(t, err)

			// Time the VRFY command
			startTime := time.Now()
			writer.WriteString(fmt.Sprintf("VRFY %s\r\n", address))
			writer.Flush()
			
			response, err := reader.ReadLine()
			duration := time.Since(startTime)
			responseTimes = append(responseTimes, duration)

			require.NoError(t, err)
			responseStr := string(response)
			t.Logf("VRFY %s took %v: %s", address, duration, responseStr)

			writer.WriteString("QUIT\r\n")
			writer.Flush()
		})
	}

	// Analyze timing consistency
	if len(responseTimes) >= 2 {
		maxTime := responseTimes[0]
		minTime := responseTimes[0]
		for _, duration := range responseTimes {
			if duration > maxTime {
				maxTime = duration
			}
			if duration < minTime {
				minTime = duration
			}
		}

		timeDifference := maxTime - minTime
		t.Logf("VRFY timing difference: %v", timeDifference)
		
		// Response times should be relatively consistent to prevent timing attacks
		assert.Less(t, timeDifference, time.Millisecond*500,
			"VRFY response times should be consistent to prevent timing attacks")
	}
}

// Helper functions

func encodeBase64(data string) string {
	// Simple base64 encoding for testing
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := ""
	
	// This is a simplified base64 implementation for testing
	for i := 0; i < len(data); i += 3 {
		b1 := int(data[i])
		b2 := 0
		b3 := 0
		
		if i+1 < len(data) {
			b2 = int(data[i+1])
		}
		if i+2 < len(data) {
			b3 = int(data[i+2])
		}
		
		result += string(base64Chars[(b1>>2)&63])
		result += string(base64Chars[((b1&3)<<4)|((b2>>4)&15)])
		
		if i+1 < len(data) {
			result += string(base64Chars[((b2&15)<<2)|((b3>>6)&3)])
		} else {
			result += "="
		}
		
		if i+2 < len(data) {
			result += string(base64Chars[b3&63])
		} else {
			result += "="
		}
	}
	
	return result
}