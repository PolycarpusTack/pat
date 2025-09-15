package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// SMTP response codes
	CodeReady          = 220
	CodeClosing        = 221
	CodeAuthSuccess    = 235
	CodeOK             = 250
	CodeStartData      = 354
	CodeNeedAuth       = 334
	CodeTempError      = 421
	CodeBadSequence    = 503
	CodeSyntaxError    = 500
	CodeNotImplemented = 502
	CodeBadAuth        = 535
	CodeMessageTooBig  = 552

	// Limits
	MaxLineLength     = 1000
	MaxMessageSize    = 50 * 1024 * 1024 // 50MB
	MaxRecipients     = 100
	CommandTimeout    = 5 * time.Minute
	DataTimeout       = 10 * time.Minute
	MaxHeaderSize     = 1024 * 1024 // 1MB
)

// Extension represents an SMTP extension
type Extension string

const (
	ExtensionStartTLS     Extension = "STARTTLS"
	ExtensionAuth         Extension = "AUTH"
	ExtensionPipelining   Extension = "PIPELINING"
	Extension8BitMIME     Extension = "8BITMIME"
	ExtensionSize         Extension = "SIZE"
	ExtensionEnhancedCodes Extension = "ENHANCEDSTATUSCODES"
	ExtensionDSN          Extension = "DSN"
)

// Session represents an SMTP session
type Session struct {
	ID           string
	RemoteAddr   string
	LocalAddr    string
	TLSState     *tls.ConnectionState
	HelloDomain  string
	AuthUser     string
	From         string
	Recipients   []string
	Data         []byte
	Extensions   map[Extension]string
	Authenticated bool
	TLS          bool
	logger       *zap.Logger
}

// Parser handles SMTP protocol parsing
type Parser struct {
	conn          net.Conn
	reader        *textproto.Reader
	writer        *textproto.Writer
	session       *Session
	config        *Config
	logger        *zap.Logger
	handlers      MessageHandler
}

// Config holds SMTP server configuration
type Config struct {
	Hostname        string
	MaxMessageSize  int64
	MaxRecipients   int
	RequireAuth     bool
	RequireTLS      bool
	TLSConfig       *tls.Config
	Extensions      []Extension
	AuthMechanisms  []string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	DataTimeout     time.Duration
}

// MessageHandler defines the interface for handling parsed messages
type MessageHandler interface {
	ValidateFrom(session *Session, from string) error
	ValidateRecipient(session *Session, to string) error
	HandleMessage(session *Session, envelope Envelope) error
}

// Envelope contains the parsed email data
type Envelope struct {
	From       string
	Recipients []string
	Data       []byte
	Headers    mail.Header
	MessageID  string
	Received   time.Time
}

// NewParser creates a new SMTP parser
func NewParser(conn net.Conn, config *Config, handlers MessageHandler, logger *zap.Logger) *Parser {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	session := &Session{
		ID:         uuid.New().String(),
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Recipients: make([]string, 0),
		Extensions: make(map[Extension]string),
		logger:     logger.With(zap.String("session_id", uuid.New().String())),
	}

	// Set default extensions
	for _, ext := range config.Extensions {
		switch ext {
		case ExtensionSize:
			session.Extensions[ext] = fmt.Sprintf("%d", config.MaxMessageSize)
		case ExtensionAuth:
			session.Extensions[ext] = strings.Join(config.AuthMechanisms, " ")
		default:
			session.Extensions[ext] = ""
		}
	}

	return &Parser{
		conn:     conn,
		reader:   textproto.NewReader(reader),
		writer:   textproto.NewWriter(writer),
		session:  session,
		config:   config,
		logger:   logger,
		handlers: handlers,
	}
}

// Handle processes the SMTP session
func (p *Parser) Handle() error {
	defer p.conn.Close()

	// Send greeting
	if err := p.sendResponse(CodeReady, fmt.Sprintf("%s ESMTP Pat Mail Server", p.config.Hostname)); err != nil {
		return err
	}

	// Main command loop
	for {
		if err := p.conn.SetReadDeadline(time.Now().Add(p.config.ReadTimeout)); err != nil {
			return err
		}

		line, err := p.reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}

		p.logger.Debug("SMTP command received", zap.String("command", line))

		if err := p.handleCommand(line); err != nil {
			if err == io.EOF {
				return nil
			}
			p.logger.Error("Command handler error", zap.Error(err))
			continue
		}
	}
}

// handleCommand processes a single SMTP command
func (p *Parser) handleCommand(line string) error {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 0 {
		return p.sendResponse(CodeSyntaxError, "Empty command")
	}

	command := strings.ToUpper(parts[0])
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}

	switch command {
	case "HELO":
		return p.handleHELO(args)
	case "EHLO":
		return p.handleEHLO(args)
	case "STARTTLS":
		return p.handleSTARTTLS()
	case "AUTH":
		return p.handleAUTH(args)
	case "MAIL":
		return p.handleMAIL(args)
	case "RCPT":
		return p.handleRCPT(args)
	case "DATA":
		return p.handleDATA()
	case "RSET":
		return p.handleRSET()
	case "NOOP":
		return p.handleNOOP()
	case "QUIT":
		return p.handleQUIT()
	case "VRFY", "EXPN":
		return p.sendResponse(CodeNotImplemented, "Command not implemented")
	default:
		return p.sendResponse(CodeSyntaxError, "Unrecognized command")
	}
}

// handleHELO handles the HELO command
func (p *Parser) handleHELO(domain string) error {
	if domain == "" {
		return p.sendResponse(CodeSyntaxError, "HELO requires domain")
	}

	p.session.HelloDomain = domain
	return p.sendResponse(CodeOK, fmt.Sprintf("%s Hello %s", p.config.Hostname, p.session.RemoteAddr))
}

// handleEHLO handles the EHLO command
func (p *Parser) handleEHLO(domain string) error {
	if domain == "" {
		return p.sendResponse(CodeSyntaxError, "EHLO requires domain")
	}

	p.session.HelloDomain = domain

	// Send multi-line response with extensions
	response := fmt.Sprintf("%s Hello %s", p.config.Hostname, p.session.RemoteAddr)
	lines := []string{response}

	for ext, params := range p.session.Extensions {
		if params != "" {
			lines = append(lines, fmt.Sprintf("%s %s", ext, params))
		} else {
			lines = append(lines, string(ext))
		}
	}

	return p.sendMultilineResponse(CodeOK, lines)
}

// handleSTARTTLS handles the STARTTLS command
func (p *Parser) handleSTARTTLS() error {
	if p.session.TLS {
		return p.sendResponse(CodeBadSequence, "Already in TLS")
	}

	if p.config.TLSConfig == nil {
		return p.sendResponse(CodeNotImplemented, "TLS not available")
	}

	if err := p.sendResponse(CodeReady, "Ready to start TLS"); err != nil {
		return err
	}

	// Upgrade connection to TLS
	tlsConn := tls.Server(p.conn, p.config.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Update connection and readers
	p.conn = tlsConn
	reader := bufio.NewReader(tlsConn)
	writer := bufio.NewWriter(tlsConn)
	p.reader = textproto.NewReader(reader)
	p.writer = textproto.NewWriter(writer)

	// Update session
	p.session.TLS = true
	state := tlsConn.ConnectionState()
	p.session.TLSState = &state

	// Reset session state
	p.session.HelloDomain = ""
	p.session.AuthUser = ""
	p.session.Authenticated = false

	return nil
}

// handleAUTH handles the AUTH command
func (p *Parser) handleAUTH(args string) error {
	if p.config.RequireTLS && !p.session.TLS {
		return p.sendResponse(CodeBadSequence, "Must use STARTTLS first")
	}

	if p.session.Authenticated {
		return p.sendResponse(CodeBadSequence, "Already authenticated")
	}

	parts := strings.SplitN(args, " ", 2)
	if len(parts) == 0 {
		return p.sendResponse(CodeSyntaxError, "AUTH requires mechanism")
	}

	mechanism := strings.ToUpper(parts[0])
	switch mechanism {
	case "PLAIN":
		return p.handleAuthPlain(parts)
	case "LOGIN":
		return p.handleAuthLogin()
	default:
		return p.sendResponse(CodeNotImplemented, "Unsupported AUTH mechanism")
	}
}

// handleAuthPlain handles PLAIN authentication
func (p *Parser) handleAuthPlain(parts []string) error {
	var credentials string
	
	if len(parts) > 1 {
		// Credentials provided with command
		credentials = parts[1]
	} else {
		// Request credentials
		if err := p.sendResponse(CodeNeedAuth, ""); err != nil {
			return err
		}
		
		line, err := p.reader.ReadLine()
		if err != nil {
			return err
		}
		credentials = line
	}

	// Decode and validate credentials
	// In production, this would validate against a real auth system
	if credentials != "" {
		p.session.Authenticated = true
		p.session.AuthUser = "authenticated@example.com"
		return p.sendResponse(CodeAuthSuccess, "Authentication successful")
	}

	return p.sendResponse(CodeBadAuth, "Authentication failed")
}

// handleAuthLogin handles LOGIN authentication
func (p *Parser) handleAuthLogin() error {
	// Request username
	if err := p.sendResponse(CodeNeedAuth, "VXNlcm5hbWU6"); err != nil { // "Username:" base64
		return err
	}

	username, err := p.reader.ReadLine()
	if err != nil {
		return err
	}

	// Request password
	if err := p.sendResponse(CodeNeedAuth, "UGFzc3dvcmQ6"); err != nil { // "Password:" base64
		return err
	}

	password, err := p.reader.ReadLine()
	if err != nil {
		return err
	}

	// Validate credentials
	// In production, this would validate against a real auth system
	if username != "" && password != "" {
		p.session.Authenticated = true
		p.session.AuthUser = "authenticated@example.com"
		return p.sendResponse(CodeAuthSuccess, "Authentication successful")
	}

	return p.sendResponse(CodeBadAuth, "Authentication failed")
}

// handleMAIL handles the MAIL FROM command
func (p *Parser) handleMAIL(args string) error {
	if p.session.HelloDomain == "" {
		return p.sendResponse(CodeBadSequence, "Send HELO/EHLO first")
	}

	if p.config.RequireAuth && !p.session.Authenticated {
		return p.sendResponse(CodeBadSequence, "Authentication required")
	}

	if p.session.From != "" {
		return p.sendResponse(CodeBadSequence, "Sender already specified")
	}

	// Parse MAIL FROM:<address>
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		return p.sendResponse(CodeSyntaxError, "Syntax: MAIL FROM:<address>")
	}

	from := extractAddress(args[5:])
	if from == "" && args[5:] != "<>" { // Allow null sender
		return p.sendResponse(CodeSyntaxError, "Invalid sender address")
	}

	// Validate sender
	if err := p.handlers.ValidateFrom(p.session, from); err != nil {
		return p.sendResponse(CodeSyntaxError, err.Error())
	}

	p.session.From = from
	return p.sendResponse(CodeOK, "Sender OK")
}

// handleRCPT handles the RCPT TO command
func (p *Parser) handleRCPT(args string) error {
	if p.session.From == "" {
		return p.sendResponse(CodeBadSequence, "Send MAIL FROM first")
	}

	if len(p.session.Recipients) >= p.config.MaxRecipients {
		return p.sendResponse(CodeTempError, "Too many recipients")
	}

	// Parse RCPT TO:<address>
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		return p.sendResponse(CodeSyntaxError, "Syntax: RCPT TO:<address>")
	}

	to := extractAddress(args[3:])
	if to == "" {
		return p.sendResponse(CodeSyntaxError, "Invalid recipient address")
	}

	// Validate recipient
	if err := p.handlers.ValidateRecipient(p.session, to); err != nil {
		return p.sendResponse(CodeSyntaxError, err.Error())
	}

	p.session.Recipients = append(p.session.Recipients, to)
	return p.sendResponse(CodeOK, "Recipient OK")
}

// handleDATA handles the DATA command
func (p *Parser) handleDATA() error {
	if len(p.session.Recipients) == 0 {
		return p.sendResponse(CodeBadSequence, "No recipients specified")
	}

	if err := p.sendResponse(CodeStartData, "Start mail input; end with <CRLF>.<CRLF>"); err != nil {
		return err
	}

	// Set data timeout
	if err := p.conn.SetReadDeadline(time.Now().Add(p.config.DataTimeout)); err != nil {
		return err
	}

	// Read message data
	data, err := p.reader.ReadDotBytes()
	if err != nil {
		return fmt.Errorf("failed to read message data: %w", err)
	}

	// Check message size
	if int64(len(data)) > p.config.MaxMessageSize {
		return p.sendResponse(CodeMessageTooBig, "Message too large")
	}

	p.session.Data = data

	// Parse and handle the message
	envelope := Envelope{
		From:       p.session.From,
		Recipients: p.session.Recipients,
		Data:       data,
		MessageID:  uuid.New().String(),
		Received:   time.Now(),
	}

	// Parse headers
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err == nil {
		envelope.Headers = msg.Header
	}

	// Handle the message
	if err := p.handlers.HandleMessage(p.session, envelope); err != nil {
		return p.sendResponse(CodeTempError, "Failed to process message")
	}

	// Reset session for next message
	p.resetSession()

	return p.sendResponse(CodeOK, fmt.Sprintf("Message accepted for delivery: %s", envelope.MessageID))
}

// handleRSET handles the RSET command
func (p *Parser) handleRSET() error {
	p.resetSession()
	return p.sendResponse(CodeOK, "OK")
}

// handleNOOP handles the NOOP command
func (p *Parser) handleNOOP() error {
	return p.sendResponse(CodeOK, "OK")
}

// handleQUIT handles the QUIT command
func (p *Parser) handleQUIT() error {
	p.sendResponse(CodeClosing, "Bye")
	return io.EOF
}

// Helper methods

func (p *Parser) sendResponse(code int, message string) error {
	if err := p.conn.SetWriteDeadline(time.Now().Add(p.config.WriteTimeout)); err != nil {
		return err
	}

	line := fmt.Sprintf("%d %s", code, message)
	p.logger.Debug("SMTP response", zap.String("response", line))
	
	return p.writer.PrintfLine("%s", line)
}

func (p *Parser) sendMultilineResponse(code int, lines []string) error {
	if err := p.conn.SetWriteDeadline(time.Now().Add(p.config.WriteTimeout)); err != nil {
		return err
	}

	for i, line := range lines {
		var format string
		if i < len(lines)-1 {
			format = "%d-%s"
		} else {
			format = "%d %s"
		}
		
		response := fmt.Sprintf(format, code, line)
		p.logger.Debug("SMTP response", zap.String("response", response))
		
		if err := p.writer.PrintfLine("%s", response); err != nil {
			return err
		}
	}

	return nil
}

func (p *Parser) resetSession() {
	p.session.From = ""
	p.session.Recipients = []string{}
	p.session.Data = nil
}

// extractAddress extracts email address from SMTP command
func extractAddress(input string) string {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "<") || !strings.HasSuffix(input, ">") {
		return ""
	}
	return strings.TrimSpace(input[1 : len(input)-1])
}