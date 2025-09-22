package legacy

import (
    "crypto/rand"
    "encoding/base64"
    "io"
    "log"
    "net/mail"
    "sync"
    "strings"
    "time"
)

// FortressCompatibilityLayer provides a modern replacement for legacy MailHog components
// while maintaining full backward compatibility with the original MailHog API and data structures.

// LogHandler provides fortress-compatible logging interface
var LogHandler func(message string, args ...interface{})

func logf(message string, args ...interface{}) {
	if LogHandler != nil {
		LogHandler(message, args...)
	} else {
		log.Printf(message, args...)
	}
}

// MessageID represents the fortress-managed ID of an SMTP message
type MessageID string

// NewMessageID generates a fortress-compatible message ID maintaining MailHog compatibility
func NewMessageID(hostname string) (MessageID, error) {
	size := 32
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return MessageID(""), err
	}
	rs := base64.URLEncoding.EncodeToString(rb)
	return MessageID(rs + "@" + hostname), nil
}

// Messages represents an array of Messages for fortress compatibility
type Messages []Message

// Message represents a parsed SMTP message with fortress enhancements
// Maintains full compatibility with original MailHog Message structure
type Message struct {
	ID      MessageID      `json:"ID"`
	From    *mail.Address  `json:"From"`
	To      []*mail.Address `json:"To"`
	Content *Content       `json:"Content"`
	Created time.Time      `json:"Created"`
	MIME    *MIMEBody      `json:"MIME"`
	Raw     *SMTPMessage   `json:"Raw"`
	
	// Fortress enhancements
	TenantID    string            `json:"tenant_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	SecurityLevel string          `json:"security_level,omitempty"`
}

// Content represents message content with fortress security enhancements
type Content struct {
	Headers map[string][]string `json:"Headers"`
	Body    string              `json:"Body"`
	Size    int                 `json:"Size"`
	MIME    string              `json:"MIME"`

	// Basic MIME info (useful for email testing)
	HasAttachments bool     `json:"has_attachments"`
	AttachmentCount int     `json:"attachment_count"`
	ContentType    string   `json:"content_type"`

	// Fortress security features
	Sanitized   bool `json:"sanitized"`
	ScannedAt   *time.Time `json:"scanned_at,omitempty"`
	SecurityTags []string `json:"security_tags,omitempty"`
}

// SMTPMessage represents the raw SMTP message data
type SMTPMessage struct {
	From string   `json:"From"`
	To   []string `json:"To"`
	Data string   `json:"Data"`
	Helo string   `json:"Helo"`
	
	// Fortress connection info
	RemoteAddr string `json:"remote_addr,omitempty"`
	TLS        bool   `json:"tls,omitempty"`
}

// MIMEBody represents MIME message structure
type MIMEBody struct {
	Parts []*Content `json:"Parts"`
}

// Path represents a message search/filtering path
type Path struct {
	Name  string `json:"Name"`
	Key   string `json:"Key"`
	Hash  string `json:"Hash"`
	Exact bool   `json:"Exact"`
}

// FortressMessageParser provides modern message parsing with legacy compatibility
type FortressMessageParser struct {
	enforceSecurityScanning bool
	maxMessageSize         int64
}

// NewFortressMessageParser creates a new fortress-enhanced message parser
func NewFortressMessageParser(enforceSecurityScanning bool, maxSize int64) *FortressMessageParser {
	return &FortressMessageParser{
		enforceSecurityScanning: enforceSecurityScanning,
		maxMessageSize:         maxSize,
	}
}

// ParseMessage parses an SMTP message using fortress-enhanced parsing
func (fmp *FortressMessageParser) ParseMessage(raw *SMTPMessage) (*Message, error) {
	msg := &Message{
		ID:      "",
		Created: time.Now(),
		Raw:     raw,
		Metadata: make(map[string]string),
	}
	
	// Generate fortress-compatible message ID
	msgID, err := NewMessageID("fortress.local")
	if err != nil {
		return nil, err
	}
	msg.ID = msgID
	
	// Parse email headers and content
	reader := strings.NewReader(raw.Data)
	mailMsg, err := mail.ReadMessage(reader)
	if err != nil {
		return nil, err
	}
	
	// Extract and parse headers
	contentType := mailMsg.Header.Get("Content-Type")
	msg.Content = &Content{
		Headers:     make(map[string][]string),
		MIME:        contentType,
		ContentType: contentType,
		Sanitized:   false,
	}
	
	// Copy all headers
	for key, values := range mailMsg.Header {
		msg.Content.Headers[key] = values
	}
	
	// Extract From address
	if fromHeader := mailMsg.Header.Get("From"); fromHeader != "" {
		if from, err := mail.ParseAddress(fromHeader); err == nil {
			msg.From = from
		}
	}
	
	// Extract To addresses
	if toHeader := mailMsg.Header.Get("To"); toHeader != "" {
		if toAddrs, err := mail.ParseAddressList(toHeader); err == nil {
			msg.To = toAddrs
		}
	}
	
	// Read message body
	body, err := io.ReadAll(mailMsg.Body)
	if err != nil {
		return nil, err
	}
	msg.Content.Body = string(body)
	msg.Content.Size = len(body)

	// Basic MIME detection (simple but useful for email testing)
	fmp.detectMIMEInfo(msg)

	// Apply fortress security enhancements if enabled
	if fmp.enforceSecurityScanning {
		fmp.applySecurity(msg)
	}

	return msg, nil
}

// detectMIMEInfo performs basic MIME detection (simple but practical)
func (fmp *FortressMessageParser) detectMIMEInfo(msg *Message) {
	contentType := strings.ToLower(msg.Content.ContentType)

	// Simple attachment detection
	if strings.Contains(contentType, "multipart/") {
		msg.Content.HasAttachments = true

		// Count attachments by counting Content-Disposition: attachment
		// (Simple heuristic - good enough for email testing)
		body := strings.ToLower(msg.Content.Body)
		count := strings.Count(body, "content-disposition:") + strings.Count(body, "content-disposition ")
		if count > 0 {
			msg.Content.AttachmentCount = count
		}
	}

	// Detect inline attachments or base64 content
	if strings.Contains(msg.Content.Body, "base64") || strings.Contains(msg.Content.Body, "attachment") {
		if !msg.Content.HasAttachments {
			msg.Content.HasAttachments = true
			msg.Content.AttachmentCount = 1 // Estimate
		}
	}
}

// applySecurity applies fortress security enhancements to the message
func (fmp *FortressMessageParser) applySecurity(msg *Message) {
	msg.SecurityLevel = "standard"
	msg.Content.ScannedAt = &[]time.Time{time.Now()}[0]
	
	// Basic security tags based on content analysis
	if strings.Contains(strings.ToLower(msg.Content.Body), "password") {
		msg.Content.SecurityTags = append(msg.Content.SecurityTags, "contains_credentials")
		msg.SecurityLevel = "high"
	}
	
	if strings.Contains(strings.ToLower(msg.Content.Body), "click here") {
		msg.Content.SecurityTags = append(msg.Content.SecurityTags, "potential_phishing")
		msg.SecurityLevel = "high"
	}
	
	// Mark as sanitized
	msg.Content.Sanitized = true
}

// FortressMessageStore provides modern storage interface with legacy compatibility
type FortressMessageStore interface {
	Store(m *Message) (MessageID, error)
	Count() int
	Search(kind, query string, start, limit int) (*Messages, error)
	List(start, limit int) (*Messages, error)
	DeleteOne(id MessageID) error
	DeleteAll() error
	Load(id MessageID) (*Message, error)
}

// InMemoryFortressStore implements a fortress-compatible in-memory message store
type InMemoryFortressStore struct {
    messages map[MessageID]*Message
    ordered  []MessageID
    mu       sync.RWMutex
}

// NewInMemoryFortressStore creates a new fortress-compatible in-memory store
func NewInMemoryFortressStore() *InMemoryFortressStore {
	return &InMemoryFortressStore{
		messages: make(map[MessageID]*Message),
		ordered:  make([]MessageID, 0),
	}
}

// Store saves a message in the fortress store
func (s *InMemoryFortressStore) Store(m *Message) (MessageID, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    if m.ID == "" {
        id, err := NewMessageID("fortress.local")
        if err != nil {
            return "", err
        }
        m.ID = id
    }
    
    s.messages[m.ID] = m
    s.ordered = append(s.ordered, m.ID)
    return m.ID, nil
}

// Count returns the total number of messages
func (s *InMemoryFortressStore) Count() int {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return len(s.messages)
}

// List returns messages with pagination
func (s *InMemoryFortressStore) List(start, limit int) (*Messages, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    messages := make(Messages, 0)

	// Clamp start to valid bounds to prevent index out of range panic
	if start < 0 {
		start = 0
	}
	if start > len(s.ordered) {
		start = len(s.ordered)
	}

	end := start + limit
	if end > len(s.ordered) {
		end = len(s.ordered)
	}

    for i := start; i < end; i++ {
        if msg, exists := s.messages[s.ordered[i]]; exists {
            messages = append(messages, *msg)
        }
    }

	return &messages, nil
}

// Load retrieves a message by ID
func (s *InMemoryFortressStore) Load(id MessageID) (*Message, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    if msg, exists := s.messages[id]; exists {
        return msg, nil
    }
    return nil, ErrMessageNotFound
}

// Search searches messages (basic implementation for compatibility)
func (s *InMemoryFortressStore) Search(kind, query string, start, limit int) (*Messages, error) {
    // Basic search implementation - can be enhanced with more sophisticated search
    s.mu.RLock()
    defer s.mu.RUnlock()
    messages := make(Messages, 0)
    found := 0
	
	for _, id := range s.ordered {
		msg, exists := s.messages[id]
		if !exists {
			continue
		}
		
		// Simple string matching - enhance as needed
		match := false
		switch kind {
		case "from":
			if msg.From != nil && strings.Contains(strings.ToLower(msg.From.String()), strings.ToLower(query)) {
				match = true
			}
		case "to":
			for _, to := range msg.To {
				if strings.Contains(strings.ToLower(to.String()), strings.ToLower(query)) {
					match = true
					break
				}
			}
		case "containing":
			if strings.Contains(strings.ToLower(msg.Content.Body), strings.ToLower(query)) {
				match = true
			}
		}
		
		if match {
			if found >= start && len(messages) < limit {
				messages = append(messages, *msg)
			}
			found++
		}
	}
	
	return &messages, nil
}

// DeleteOne removes a single message
func (s *InMemoryFortressStore) DeleteOne(id MessageID) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if _, exists := s.messages[id]; !exists {
        return ErrMessageNotFound
    }
    
    delete(s.messages, id)
    
    // Remove from ordered list
    for i, orderedID := range s.ordered {
        if orderedID == id {
            s.ordered = append(s.ordered[:i], s.ordered[i+1:]...)
            break
        }
    }
    
    return nil
}

// DeleteAll removes all messages
func (s *InMemoryFortressStore) DeleteAll() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.messages = make(map[MessageID]*Message)
    s.ordered = make([]MessageID, 0)
    return nil
}

// Common errors for fortress compatibility
var (
	ErrMessageNotFound = &FortressError{Code: "MESSAGE_NOT_FOUND", Message: "Message not found"}
)

// FortressError provides structured error handling
type FortressError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *FortressError) Error() string {
	return e.Message
}

// FortressConfigShim provides configuration compatibility with legacy MailHog
type FortressConfigShim struct {
	SMTPBindAddr   string
	HTTPBindAddr   string
	Hostname       string
	MongoURI       string
	MongoDb        string
	MongoColl      string
	StorageType    string
	CORSOrigin     string
	WebPath        string
	
	// Fortress enhancements
	EnableSecurity     bool
	MaxMessageSize     int64
	RetentionDays      int
	TenantID           string
}

// NewFortressConfigShim creates a configuration shim for legacy compatibility
func NewFortressConfigShim() *FortressConfigShim {
	return &FortressConfigShim{
		SMTPBindAddr:   "0.0.0.0:1025",
		HTTPBindAddr:   "0.0.0.0:8025",
		Hostname:       "fortress.local",
		StorageType:    "memory",
		WebPath:        "",
		EnableSecurity: true,
		MaxMessageSize: 10 * 1024 * 1024, // 10MB
		RetentionDays:  7,
	}
}
