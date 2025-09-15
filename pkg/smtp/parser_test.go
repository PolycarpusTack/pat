package smtp_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/pat/pkg/smtp"
)

// Mock connection for testing
type mockConn struct {
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
	closed      bool
	mu          sync.Mutex
}

func newMockConn() *mockConn {
	return &mockConn{
		readBuffer:  &bytes.Buffer{},
		writeBuffer: &bytes.Buffer{},
	}
}

func (c *mockConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readBuffer.Read(b)
}

func (c *mockConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeBuffer.Write(b)
}

func (c *mockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 25}
}

func (c *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321}
}

func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// Mock message handler
type mockHandler struct {
	validateFromFunc      func(*smtp.Session, string) error
	validateRecipientFunc func(*smtp.Session, string) error
	handleMessageFunc     func(*smtp.Session, smtp.Envelope) error
	messages              []smtp.Envelope
	mu                    sync.Mutex
}

func (h *mockHandler) ValidateFrom(session *smtp.Session, from string) error {
	if h.validateFromFunc != nil {
		return h.validateFromFunc(session, from)
	}
	return nil
}

func (h *mockHandler) ValidateRecipient(session *smtp.Session, to string) error {
	if h.validateRecipientFunc != nil {
		return h.validateRecipientFunc(session, to)
	}
	return nil
}

func (h *mockHandler) HandleMessage(session *smtp.Session, envelope smtp.Envelope) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	h.messages = append(h.messages, envelope)
	
	if h.handleMessageFunc != nil {
		return h.handleMessageFunc(session, envelope)
	}
	return nil
}

// Test basic SMTP flow
func TestSMTPBasicFlow(t *testing.T) {
	conn := newMockConn()
	handler := &mockHandler{}
	logger, _ := zap.NewDevelopment()
	
	config := &smtp.Config{
		Hostname:       "test.example.com",
		MaxMessageSize: 1024 * 1024,
		MaxRecipients:  10,
		Extensions:     []smtp.Extension{smtp.ExtensionPipelining, smtp.Extension8BitMIME},
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		DataTimeout:    10 * time.Second,
	}
	
	parser := smtp.NewParser(conn, config, handler, logger)
	
	// Simulate client commands
	commands := []string{
		"EHLO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient@example.com>",
		"DATA",
		"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message\r\n.",
		"QUIT",
	}
	
	for _, cmd := range commands {
		conn.readBuffer.WriteString(cmd + "\r\n")
	}
	
	// Run parser in background
	done := make(chan error)
	go func() {
		done <- parser.Handle()
	}()
	
	// Wait for completion
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Parser timed out")
	}
	
	// Verify handler received message
	assert.Len(t, handler.messages, 1)
	msg := handler.messages[0]
	assert.Equal(t, "sender@example.com", msg.From)
	assert.Equal(t, []string{"recipient@example.com"}, msg.Recipients)
	assert.Contains(t, string(msg.Data), "Test message")
	
	// Verify responses
	responses := strings.Split(conn.writeBuffer.String(), "\r\n")
	assert.Contains(t, responses[0], "220") // Greeting
	assert.Contains(t, responses[1], "250") // EHLO response
}

// Test SMTP with authentication
func TestSMTPAuthentication(t *testing.T) {
	conn := newMockConn()
	handler := &mockHandler{}
	logger, _ := zap.NewDevelopment()
	
	config := &smtp.Config{
		Hostname:       "test.example.com",
		MaxMessageSize: 1024 * 1024,
		RequireAuth:    true,
		Extensions:     []smtp.Extension{smtp.ExtensionAuth},
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
	}
	
	parser := smtp.NewParser(conn, config, handler, logger)
	
	// Test AUTH PLAIN
	authPlain := base64.StdEncoding.EncodeToString([]byte("\x00user\x00password"))
	commands := []string{
		"EHLO client.example.com",
		fmt.Sprintf("AUTH PLAIN %s", authPlain),
		"MAIL FROM:<user@example.com>",
		"RCPT TO:<recipient@example.com>",
		"DATA",
		"Test\r\n.",
		"QUIT",
	}
	
	for _, cmd := range commands {
		conn.readBuffer.WriteString(cmd + "\r\n")
	}
	
	// Run parser
	done := make(chan error)
	go func() {
		done <- parser.Handle()
	}()
	
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Parser timed out")
	}
	
	// Verify authentication success
	responses := conn.writeBuffer.String()
	assert.Contains(t, responses, "235") // Auth success
}

// Test STARTTLS
func TestSMTPStartTLS(t *testing.T) {
	t.Skip("TLS testing requires more setup")
	
	// This test would require setting up TLS certificates
	// and mocking the TLS handshake
}

// Test rate limiting and connection limits
func TestSMTPRateLimiting(t *testing.T) {
	// Test maximum recipients
	conn := newMockConn()
	handler := &mockHandler{}
	logger, _ := zap.NewDevelopment()
	
	config := &smtp.Config{
		Hostname:      "test.example.com",
		MaxRecipients: 3,
		ReadTimeout:   5 * time.Second,
		WriteTimeout:  5 * time.Second,
	}
	
	parser := smtp.NewParser(conn, config, handler, logger)
	
	// Try to add more recipients than allowed
	commands := []string{
		"HELO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient1@example.com>",
		"RCPT TO:<recipient2@example.com>",
		"RCPT TO:<recipient3@example.com>",
		"RCPT TO:<recipient4@example.com>", // Should fail
		"QUIT",
	}
	
	for _, cmd := range commands {
		conn.readBuffer.WriteString(cmd + "\r\n")
	}
	
	// Run parser
	done := make(chan error)
	go func() {
		done <- parser.Handle()
	}()
	
	select {
	case <-done:
		// Expected
	case <-time.After(2 * time.Second):
		t.Fatal("Parser timed out")
	}
	
	// Check for error response
	responses := conn.writeBuffer.String()
	assert.Contains(t, responses, "421") // Too many recipients
}

// Test malformed commands
func TestSMTPMalformedCommands(t *testing.T) {
	tests := []struct {
		name     string
		commands []string
		expected string
	}{
		{
			name: "Empty MAIL FROM",
			commands: []string{
				"EHLO test",
				"MAIL FROM:",
			},
			expected: "501",
		},
		{
			name: "Invalid RCPT TO",
			commands: []string{
				"EHLO test",
				"MAIL FROM:<sender@example.com>",
				"RCPT TO:invalid-email",
			},
			expected: "501",
		},
		{
			name: "DATA without recipients",
			commands: []string{
				"EHLO test",
				"MAIL FROM:<sender@example.com>",
				"DATA",
			},
			expected: "503",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConn()
			handler := &mockHandler{}
			logger, _ := zap.NewDevelopment()
			
			config := &smtp.Config{
				Hostname:     "test.example.com",
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 5 * time.Second,
			}
			
			parser := smtp.NewParser(conn, config, handler, logger)
			
			// Add commands
			for _, cmd := range tt.commands {
				conn.readBuffer.WriteString(cmd + "\r\n")
			}
			conn.readBuffer.WriteString("QUIT\r\n")
			
			// Run parser
			done := make(chan error)
			go func() {
				done <- parser.Handle()
			}()
			
			select {
			case <-done:
				// Expected
			case <-time.After(2 * time.Second):
				t.Fatal("Parser timed out")
			}
			
			// Check for expected error code
			responses := conn.writeBuffer.String()
			assert.Contains(t, responses, tt.expected)
		})
	}
}

// Test pipelining
func TestSMTPPipelining(t *testing.T) {
	conn := newMockConn()
	handler := &mockHandler{}
	logger, _ := zap.NewDevelopment()
	
	config := &smtp.Config{
		Hostname:    "test.example.com",
		Extensions:  []smtp.Extension{smtp.ExtensionPipelining},
		ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	
	parser := smtp.NewParser(conn, config, handler, logger)
	
	// Send multiple commands at once (pipelining)
	pipelined := strings.Join([]string{
		"EHLO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient@example.com>",
		"DATA",
	}, "\r\n") + "\r\n"
	
	conn.readBuffer.WriteString(pipelined)
	conn.readBuffer.WriteString("Test message\r\n.\r\n")
	conn.readBuffer.WriteString("QUIT\r\n")
	
	// Run parser
	done := make(chan error)
	go func() {
		done <- parser.Handle()
	}()
	
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Parser timed out")
	}
	
	// Verify message was received
	assert.Len(t, handler.messages, 1)
}

// Benchmark SMTP parsing performance
func BenchmarkSMTPParsing(b *testing.B) {
	logger, _ := zap.NewProduction()
	config := &smtp.Config{
		Hostname:       "test.example.com",
		MaxMessageSize: 10 * 1024 * 1024,
		MaxRecipients:  100,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		DataTimeout:    10 * time.Second,
	}
	
	// Prepare test data
	largeBody := strings.Repeat("This is a test message line.\r\n", 1000)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		conn := newMockConn()
		handler := &mockHandler{}
		
		// Simulate SMTP session
		session := fmt.Sprintf(
			"EHLO client.example.com\r\n"+
			"MAIL FROM:<sender@example.com>\r\n"+
			"RCPT TO:<recipient%d@example.com>\r\n"+
			"DATA\r\n"+
			"From: sender@example.com\r\n"+
			"To: recipient%d@example.com\r\n"+
			"Subject: Test %d\r\n"+
			"\r\n"+
			"%s\r\n"+
			".\r\n"+
			"QUIT\r\n",
			i, i, i, largeBody,
		)
		
		conn.readBuffer.WriteString(session)
		
		parser := smtp.NewParser(conn, config, handler, logger)
		parser.Handle()
	}
}

// Test concurrent SMTP sessions
func TestSMTPConcurrency(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	config := &smtp.Config{
		Hostname:     "test.example.com",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	
	var wg sync.WaitGroup
	errors := make(chan error, 10)
	
	// Run 10 concurrent SMTP sessions
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			conn := newMockConn()
			handler := &mockHandler{}
			
			// Unique session
			session := fmt.Sprintf(
				"HELO client%d.example.com\r\n"+
				"MAIL FROM:<sender%d@example.com>\r\n"+
				"RCPT TO:<recipient%d@example.com>\r\n"+
				"DATA\r\n"+
				"Test message %d\r\n"+
				".\r\n"+
				"QUIT\r\n",
				id, id, id, id,
			)
			
			conn.readBuffer.WriteString(session)
			
			parser := smtp.NewParser(conn, config, handler, logger)
			if err := parser.Handle(); err != nil {
				errors <- err
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent session error: %v", err)
	}
}