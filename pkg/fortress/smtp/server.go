package smtp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/pat-fortress/pkg/fortress/legacy"
	"github.com/pat-fortress/pkg/fortress/ratelimit"
	"go.uber.org/zap"
)

// FortressSMTPServer provides a modern SMTP server with legacy MailHog compatibility
type FortressSMTPServer struct {
    config       *FortressSMTPConfig
    logger       *zap.Logger
    store        legacy.FortressMessageStore
    parser       *legacy.FortressMessageParser
    listener     net.Listener
    tlsConfig    *tls.Config
    shutdown     chan struct{}
    rateLimiter  *ratelimit.SimpleRateLimiter
    connMutex    sync.RWMutex
    activeConns  int
    onMessage    func(*legacy.Message)
}

// FortressSMTPConfig defines configuration for the fortress SMTP server
type FortressSMTPConfig struct {
	BindAddr         string
	Hostname         string
	MaxMessageSize   int64
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	MaxConnections   int
	EnableTLS        bool
	TLSCertFile      string
	TLSKeyFile       string
	EnableAuth       bool
	EnableSTARTTLS   bool
	RequireTLS       bool
	
	// Fortress security features
	EnableRateLimit  bool
	MaxPerIP         int
	EnableBlacklist  bool
	BlacklistPath    string
	EnableAuditLog   bool
	TenantID         string
}

// NewFortressSMTPServer creates a new fortress-enhanced SMTP server
func NewFortressSMTPServer(config *FortressSMTPConfig, store legacy.FortressMessageStore, logger *zap.Logger) *FortressSMTPServer {
	parser := legacy.NewFortressMessageParser(true, config.MaxMessageSize)

	server := &FortressSMTPServer{
		config:   config,
		logger:   logger,
		store:    store,
		parser:   parser,
		shutdown: make(chan struct{}),
	}

	// Simple connection counting (no fancy semaphores needed)
	if config.MaxConnections > 0 {
		logger.Info("SMTP connection limiting enabled",
			zap.Int("max_connections", config.MaxConnections))
	}

	// Initialize simple rate limiting if enabled
	if config.EnableRateLimit && config.MaxPerIP > 0 {
		server.rateLimiter = ratelimit.NewSimpleRateLimiter(config.MaxPerIP)
		logger.Info("SMTP rate limiting enabled",
			zap.Int("max_per_ip", config.MaxPerIP),
			zap.String("window", "1 minute"))
	}

	return server
}

// Listen starts the fortress SMTP server listening for connections
func (s *FortressSMTPServer) Listen() error {
	var err error
	s.listener, err = net.Listen("tcp", s.config.BindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.BindAddr, err)
	}

	s.logger.Info("Fortress SMTP server listening", 
		zap.String("address", s.config.BindAddr),
		zap.String("hostname", s.config.Hostname),
		zap.Bool("tls_enabled", s.config.EnableTLS),
	)

	// Setup TLS if enabled
	if s.config.EnableTLS && s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		
		s.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ServerName:   s.config.Hostname,
		}
	}

	// Connection handling loop
	for {
		select {
		case <-s.shutdown:
			s.logger.Info("Fortress SMTP server shutting down")
			return nil
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				s.logger.Error("Failed to accept connection", zap.Error(err))
				continue
			}

			// Check connection limits and rate limits
			if !s.acceptConnection(conn) {
				conn.Close()
				continue
			}

			// Handle connection in goroutine
			go s.handleConnectionWithLimits(conn)
		}
	}
}

// Shutdown gracefully shuts down the fortress SMTP server
func (s *FortressSMTPServer) Shutdown() error {
	close(s.shutdown)

	// Close rate limiter
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// acceptConnection checks if a connection should be accepted (simple limits)
func (s *FortressSMTPServer) acceptConnection(conn net.Conn) bool {
	remoteAddr := conn.RemoteAddr().String()

	// Check rate limiting first
	if s.rateLimiter != nil && !s.rateLimiter.Allow(remoteAddr) {
		s.logger.Warn("Connection rejected due to rate limiting",
			zap.String("remote_addr", remoteAddr))
		return false
	}

	// Simple connection limit check
	if s.config.MaxConnections > 0 {
		s.connMutex.RLock()
		current := s.activeConns
		s.connMutex.RUnlock()

		if current >= s.config.MaxConnections {
			s.logger.Warn("Connection rejected due to connection limit",
				zap.String("remote_addr", remoteAddr),
				zap.Int("active", current),
				zap.Int("max", s.config.MaxConnections))
			return false
		}
	}

	return true
}

// handleConnectionWithLimits handles a connection with simple cleanup
func (s *FortressSMTPServer) handleConnectionWithLimits(conn net.Conn) {
	// Simple connection tracking
	s.connMutex.Lock()
	s.activeConns++
	s.connMutex.Unlock()

	defer func() {
		conn.Close()
		s.connMutex.Lock()
		s.activeConns--
		s.connMutex.Unlock()
	}()

	s.handleConnection(conn)
}

// handleConnection handles an individual SMTP connection with fortress enhancements
func (s *FortressSMTPServer) handleConnection(conn net.Conn) {
	session := &FortressSMTPSession{
		server:     s,
		conn:       conn,
		reader:     bufio.NewReader(conn),
		remoteAddr: conn.RemoteAddr().String(),
		state:      StateConnect,
		logger:     s.logger.With(zap.String("remote_addr", conn.RemoteAddr().String())),
	}

	session.handle()
}

// GetActiveConnections returns the current number of active connections
func (s *FortressSMTPServer) GetActiveConnections() int {
	s.connMutex.RLock()
	defer s.connMutex.RUnlock()
	return s.activeConns
}

// FortressSMTPSession represents a fortress-enhanced SMTP session
type FortressSMTPSession struct {
	server     *FortressSMTPServer
	conn       net.Conn
	reader     *bufio.Reader
	remoteAddr string
	state      SMTPState
	helo       string
	from       string
	to         []string
	data       []string
	logger     *zap.Logger
	tls        bool
}

// SMTPState represents the current state of the SMTP session
type SMTPState int

const (
	StateConnect SMTPState = iota
	StateHelo
	StateMailFrom
	StateRcptTo
	StateData
	StateQuit
)

// handle processes the SMTP session with fortress security features
func (s *FortressSMTPSession) handle() {
	s.logger.Info("New SMTP connection established")
	
	// Set connection timeouts
	if s.server.config.ReadTimeout > 0 {
		s.conn.SetReadDeadline(time.Now().Add(s.server.config.ReadTimeout))
	}
	
	// Send fortress SMTP greeting
	s.writeLine("220 %s Fortress SMTP Server", s.server.config.Hostname)

	for {
		// Read command from client
		if s.server.config.ReadTimeout > 0 {
			s.conn.SetReadDeadline(time.Now().Add(s.server.config.ReadTimeout))
		}
		
		line, err := s.reader.ReadString('\n')
		if err != nil {
			s.logger.Debug("Client connection closed",
				zap.Error(err),
				zap.String("remote_addr", s.remoteAddr))
			return
		}

		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 0 {
			continue
		}

		cmd := strings.ToUpper(parts[0])
		var args string
		if len(parts) > 1 {
			args = parts[1]
		}

		s.logger.Debug("SMTP command received", 
			zap.String("command", cmd), 
			zap.String("args", args),
		)

		// Process command
		if !s.processCommand(cmd, args) {
			return
		}
	}
}

// processCommand processes individual SMTP commands with fortress validation
func (s *FortressSMTPSession) processCommand(cmd, args string) bool {
	switch cmd {
	case "HELO", "EHLO":
		return s.handleHelo(cmd, args)
	case "MAIL":
		return s.handleMail(args)
	case "RCPT":
		return s.handleRcpt(args)
	case "DATA":
		return s.handleData()
	case "QUIT":
		return s.handleQuit()
	case "RSET":
		return s.handleRset()
	case "NOOP":
		return s.handleNoop()
	case "STARTTLS":
		return s.handleStartTLS()
	default:
		s.writeLine("500 Command not recognized")
		return true
	}
}

// handleHelo processes HELO/EHLO commands
func (s *FortressSMTPSession) handleHelo(cmd, args string) bool {
	if args == "" {
		s.writeLine("501 HELO requires domain address")
		return true
	}

	s.helo = args
	s.state = StateHelo

	if cmd == "EHLO" {
		s.writeLine("250-%s Hello %s", s.server.config.Hostname, args)
		s.writeLine("250-SIZE %d", s.server.config.MaxMessageSize)
		s.writeLine("250-8BITMIME")
		s.writeLine("250-PIPELINING")
		if s.server.config.EnableSTARTTLS && s.server.tlsConfig != nil && !s.tls {
			s.writeLine("250-STARTTLS")
		}
		s.writeLine("250 OK")
	} else {
		s.writeLine("250 %s Hello %s", s.server.config.Hostname, args)
	}

	return true
}

// handleMail processes MAIL FROM commands
func (s *FortressSMTPSession) handleMail(args string) bool {
	if s.state != StateHelo {
		s.writeLine("503 Bad sequence of commands")
		return true
	}

	// Parse MAIL FROM command
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		s.writeLine("501 Syntax error in MAIL command")
		return true
	}

	fromAddr := strings.TrimSpace(args[5:])
	if strings.HasPrefix(fromAddr, "<") && strings.HasSuffix(fromAddr, ">") {
		fromAddr = fromAddr[1 : len(fromAddr)-1]
	}

	// Validate email address
	if fromAddr != "" {
		if _, err := mail.ParseAddress(fromAddr); err != nil {
			s.writeLine("553 Invalid sender address")
			return true
		}
	}

	s.from = fromAddr
	s.to = nil // Reset recipients
	s.state = StateMailFrom

	s.writeLine("250 OK")
	return true
}

// handleRcpt processes RCPT TO commands
func (s *FortressSMTPSession) handleRcpt(args string) bool {
	if s.state != StateMailFrom && s.state != StateRcptTo {
		s.writeLine("503 Bad sequence of commands")
		return true
	}

	// Parse RCPT TO command
	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		s.writeLine("501 Syntax error in RCPT command")
		return true
	}

	toAddr := strings.TrimSpace(args[3:])
	if strings.HasPrefix(toAddr, "<") && strings.HasSuffix(toAddr, ">") {
		toAddr = toAddr[1 : len(toAddr)-1]
	}

	// Validate email address
	if _, err := mail.ParseAddress(toAddr); err != nil {
		s.writeLine("553 Invalid recipient address")
		return true
	}

	s.to = append(s.to, toAddr)
	s.state = StateRcptTo

	s.writeLine("250 OK")
	return true
}

// handleData processes DATA command and message content
func (s *FortressSMTPSession) handleData() bool {
	if s.state != StateRcptTo {
		s.writeLine("503 Bad sequence of commands")
		return true
	}

	s.writeLine("354 End data with <CR><LF>.<CR><LF>")
	s.state = StateData

	// Read message data with incremental size tracking
	var dataLines []string
	var totalSize int64
	maxSize := s.server.config.MaxMessageSize

	for {
		if s.server.config.ReadTimeout > 0 {
			s.conn.SetReadDeadline(time.Now().Add(s.server.config.ReadTimeout))
		}

		line, err := s.reader.ReadString('\n')
		if err != nil {
			s.logger.Error("Error reading message data", zap.Error(err))
			return false
		}

		line = strings.TrimSuffix(line, "\r\n")
		line = strings.TrimSuffix(line, "\n")

		// Check for end of data
		if line == "." {
			break
		}

		// Handle dot-stuffing
		if strings.HasPrefix(line, ".") {
			line = line[1:]
		}

		// Check message size limit before adding line (O(1) performance)
		lineSize := int64(len(line) + 1) // +1 for newline when joined
		if totalSize+lineSize > maxSize {
			s.writeLine("552 Message size exceeds maximum allowed")
			// Drain remaining data until end marker
			for {
				drainLine, err := s.reader.ReadString('\n')
				if err != nil || strings.TrimSpace(drainLine) == "." {
					break
				}
			}
			return true
		}

		dataLines = append(dataLines, line)
		totalSize += lineSize
	}

	// Create fortress message
	raw := &legacy.SMTPMessage{
		From:       s.from,
		To:         s.to,
		Data:       strings.Join(dataLines, "\n"),
		Helo:       s.helo,
		RemoteAddr: s.remoteAddr,
		TLS:        s.tls,
	}

	// Parse message using fortress parser
	message, err := s.server.parser.ParseMessage(raw)
	if err != nil {
		s.logger.Error("Failed to parse message", zap.Error(err))
		s.writeLine("554 Transaction failed: message parsing error")
		return true
	}

	// Add fortress metadata
	message.TenantID = s.server.config.TenantID
	if message.Metadata == nil {
		message.Metadata = make(map[string]string)
	}
	message.Metadata["source_ip"] = s.remoteAddr
	message.Metadata["helo"] = s.helo
	message.Metadata["tls"] = fmt.Sprintf("%v", s.tls)

    // Store message
    messageID, err := s.server.store.Store(message)
    if err != nil {
        s.logger.Error("Failed to store message", zap.Error(err))
        s.writeLine("554 Transaction failed: storage error")
        return true
    }

	s.logger.Info("Message received and stored",
		zap.String("message_id", string(messageID)),
		zap.String("from", s.from),
		zap.Strings("to", s.to),
		zap.Int("size", len(raw.Data)),
	)

    s.writeLine("250 OK: message queued as %s", messageID)

    // Reset session for next message
    s.from = ""
    s.to = nil
    s.state = StateHelo

    // Notify listeners about new message
    if s.server.onMessage != nil {
        // best-effort notify; avoid blocking SMTP path
        go s.server.onMessage(message)
    }

    return true
}

// SetOnMessageCallback registers a callback to be invoked when a message is stored
func (s *FortressSMTPServer) SetOnMessageCallback(cb func(*legacy.Message)) {
    s.onMessage = cb
}

// handleQuit processes QUIT command
func (s *FortressSMTPSession) handleQuit() bool {
	s.writeLine("221 %s Service closing transmission channel", s.server.config.Hostname)
	return false
}

// handleRset processes RSET command
func (s *FortressSMTPSession) handleRset() bool {
	s.from = ""
	s.to = nil
	s.state = StateHelo
	s.writeLine("250 OK")
	return true
}

// handleNoop processes NOOP command
func (s *FortressSMTPSession) handleNoop() bool {
	s.writeLine("250 OK")
	return true
}

// handleStartTLS processes STARTTLS command
func (s *FortressSMTPSession) handleStartTLS() bool {
	if s.server.tlsConfig == nil {
		s.writeLine("502 STARTTLS not available")
		return true
	}

	if s.tls {
		s.writeLine("503 Already using TLS")
		return true
	}

	s.writeLine("220 Ready to start TLS")

	// Upgrade connection to TLS
	tlsConn := tls.Server(s.conn, s.server.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		s.logger.Error("TLS handshake failed", zap.Error(err))
		return false
	}

	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.tls = true

	// Reset session state after STARTTLS
	s.state = StateConnect
	s.helo = ""
	s.from = ""
	s.to = nil

	s.logger.Info("TLS connection established")
	return true
}

// writeLine writes a formatted response line to the client
func (s *FortressSMTPSession) writeLine(format string, args ...interface{}) {
	if s.server.config.WriteTimeout > 0 {
		s.conn.SetWriteDeadline(time.Now().Add(s.server.config.WriteTimeout))
	}
	
	line := fmt.Sprintf(format, args...)
	s.conn.Write([]byte(line + "\r\n"))
	
	s.logger.Debug("SMTP response sent", zap.String("response", line))
}

// DefaultFortressSMTPConfig returns a default fortress SMTP configuration
func DefaultFortressSMTPConfig() *FortressSMTPConfig {
	return &FortressSMTPConfig{
		BindAddr:         "0.0.0.0:1025",
		Hostname:         "fortress.local",
		MaxMessageSize:   10 * 1024 * 1024, // 10MB
		ReadTimeout:      60 * time.Second,
		WriteTimeout:     60 * time.Second,
		MaxConnections:   100,
		EnableTLS:        false,
		EnableSTARTTLS:   true,
		RequireTLS:       false,
		EnableAuth:       false,
		EnableRateLimit:  true,
		MaxPerIP:         10,
		EnableBlacklist:  false,
		EnableAuditLog:   true,
	}
}
