package email

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Parser handles email parsing and extraction
type Parser struct {
	logger        *zap.Logger
	maxHeaderSize int64
	maxBodySize   int64
}

// ParsedEmail represents a fully parsed email
type ParsedEmail struct {
	ID              string
	MessageID       string
	ConversationID  string
	From            *mail.Address
	To              []*mail.Address
	CC              []*mail.Address
	BCC             []*mail.Address
	ReplyTo         []*mail.Address
	Subject         string
	Date            time.Time
	Headers         mail.Header
	TextBody        string
	HTMLBody        string
	Attachments     []*Attachment
	InlineImages    []*Attachment
	RawSize         int64
	ContentType     string
	Charset         string
	SPFResult       string
	DKIMResult      string
	DMARCResult     string
}

// Attachment represents an email attachment
type Attachment struct {
	ID          string
	Filename    string
	ContentType string
	Size        int64
	Data        []byte
	ContentID   string
	IsInline    bool
	Checksum    string
}

// NewParser creates a new email parser
func NewParser(logger *zap.Logger) *Parser {
	return &Parser{
		logger:        logger,
		maxHeaderSize: 1024 * 1024,    // 1MB
		maxBodySize:   50 * 1024 * 1024, // 50MB
	}
}

// Parse parses raw email data
func (p *Parser) Parse(rawEmail []byte) (*ParsedEmail, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(rawEmail))
	if err != nil {
		return nil, fmt.Errorf("failed to parse email: %w", err)
	}

	parsed := &ParsedEmail{
		ID:       uuid.New().String(),
		Headers:  msg.Header,
		RawSize:  int64(len(rawEmail)),
	}

	// Extract headers
	if err := p.extractHeaders(parsed, msg.Header); err != nil {
		return nil, fmt.Errorf("failed to extract headers: %w", err)
	}

	// Parse body
	if err := p.parseBody(parsed, msg); err != nil {
		return nil, fmt.Errorf("failed to parse body: %w", err)
	}

	// Extract authentication results
	p.extractAuthResults(parsed)

	// Generate conversation ID
	parsed.ConversationID = p.generateConversationID(parsed)

	return parsed, nil
}

// extractHeaders extracts common email headers
func (p *Parser) extractHeaders(email *ParsedEmail, headers mail.Header) error {
	// Message-ID
	email.MessageID = headers.Get("Message-ID")
	if email.MessageID == "" {
		email.MessageID = fmt.Sprintf("<%s@generated>", email.ID)
	}

	// From
	if from := headers.Get("From"); from != "" {
		addr, err := mail.ParseAddress(from)
		if err == nil {
			email.From = addr
		}
	}

	// To
	email.To = p.parseAddressList(headers.Get("To"))

	// CC
	email.CC = p.parseAddressList(headers.Get("Cc"))

	// BCC (rarely in headers, but check anyway)
	email.BCC = p.parseAddressList(headers.Get("Bcc"))

	// Reply-To
	email.ReplyTo = p.parseAddressList(headers.Get("Reply-To"))

	// Subject
	email.Subject = p.decodeHeader(headers.Get("Subject"))

	// Date
	if dateStr := headers.Get("Date"); dateStr != "" {
		if date, err := mail.ParseDate(dateStr); err == nil {
			email.Date = date
		}
	}
	if email.Date.IsZero() {
		email.Date = time.Now()
	}

	// Content-Type
	contentType := headers.Get("Content-Type")
	if contentType != "" {
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err == nil {
			email.ContentType = mediaType
			email.Charset = params["charset"]
		}
	}

	return nil
}

// parseBody parses the email body and attachments
func (p *Parser) parseBody(email *ParsedEmail, msg *mail.Message) error {
	contentType := email.ContentType
	if contentType == "" {
		contentType = "text/plain"
	}

	// Handle different content types
	switch {
	case strings.HasPrefix(contentType, "text/plain"):
		body, err := p.readBody(msg.Body)
		if err != nil {
			return err
		}
		email.TextBody = p.decodeBody(body, email.Charset)

	case strings.HasPrefix(contentType, "text/html"):
		body, err := p.readBody(msg.Body)
		if err != nil {
			return err
		}
		email.HTMLBody = p.decodeBody(body, email.Charset)

	case strings.HasPrefix(contentType, "multipart/"):
		return p.parseMultipart(email, msg)

	default:
		// Treat as attachment
		data, err := p.readBody(msg.Body)
		if err != nil {
			return err
		}
		
		attachment := &Attachment{
			ID:          uuid.New().String(),
			Filename:    "body.dat",
			ContentType: contentType,
			Size:        int64(len(data)),
			Data:        data,
			Checksum:    p.calculateChecksum(data),
		}
		email.Attachments = append(email.Attachments, attachment)
	}

	return nil
}

// parseMultipart handles multipart messages
func (p *Parser) parseMultipart(email *ParsedEmail, msg *mail.Message) error {
	mediaType, params, err := mime.ParseMediaType(email.ContentType)
	if err != nil {
		return fmt.Errorf("failed to parse media type: %w", err)
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		return fmt.Errorf("not a multipart message")
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read multipart: %w", err)
		}

		if err := p.processPart(email, part); err != nil {
			p.logger.Warn("Failed to process part", zap.Error(err))
		}
		part.Close()
	}

	return nil
}

// processPart processes a single MIME part
func (p *Parser) processPart(email *ParsedEmail, part *multipart.Part) error {
	contentType := part.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}

	mediaType, params, _ := mime.ParseMediaType(contentType)
	
	// Read part data
	data, err := p.readBody(part)
	if err != nil {
		return err
	}

	// Check if it's an attachment
	disposition := part.Header.Get("Content-Disposition")
	isAttachment := false
	filename := ""
	
	if disposition != "" {
		dispType, dispParams, _ := mime.ParseMediaType(disposition)
		isAttachment = dispType == "attachment"
		filename = dispParams["filename"]
	}

	// Also check for filename in Content-Type
	if filename == "" {
		filename = params["name"]
	}

	// Content-ID for inline images
	contentID := part.Header.Get("Content-ID")
	if contentID != "" {
		contentID = strings.Trim(contentID, "<>")
	}

	// Process based on type
	switch {
	case isAttachment || filename != "":
		attachment := &Attachment{
			ID:          uuid.New().String(),
			Filename:    p.sanitizeFilename(filename),
			ContentType: mediaType,
			Size:        int64(len(data)),
			Data:        data,
			ContentID:   contentID,
			IsInline:    contentID != "",
			Checksum:    p.calculateChecksum(data),
		}
		
		if attachment.IsInline {
			email.InlineImages = append(email.InlineImages, attachment)
		} else {
			email.Attachments = append(email.Attachments, attachment)
		}

	case strings.HasPrefix(mediaType, "text/plain"):
		email.TextBody += p.decodeBody(data, params["charset"])

	case strings.HasPrefix(mediaType, "text/html"):
		email.HTMLBody += p.decodeBody(data, params["charset"])

	case strings.HasPrefix(mediaType, "multipart/"):
		// Nested multipart
		subMsg := &mail.Message{
			Header: mail.Header(part.Header),
			Body:   io.NopCloser(bytes.NewReader(data)),
		}
		subEmail := &ParsedEmail{
			ContentType: contentType,
			Charset:     params["charset"],
		}
		if err := p.parseMultipart(subEmail, subMsg); err == nil {
			email.TextBody += subEmail.TextBody
			email.HTMLBody += subEmail.HTMLBody
			email.Attachments = append(email.Attachments, subEmail.Attachments...)
			email.InlineImages = append(email.InlineImages, subEmail.InlineImages...)
		}
	}

	return nil
}

// Helper methods

func (p *Parser) parseAddressList(header string) []*mail.Address {
	if header == "" {
		return nil
	}

	addrs, err := mail.ParseAddressList(header)
	if err != nil {
		// Try to extract at least email addresses
		var result []*mail.Address
		for _, part := range strings.Split(header, ",") {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "@") {
				result = append(result, &mail.Address{Address: part})
			}
		}
		return result
	}

	return addrs
}

func (p *Parser) decodeHeader(header string) string {
	dec := &mime.WordDecoder{}
	decoded, err := dec.DecodeHeader(header)
	if err != nil {
		return header
	}
	return decoded
}

func (p *Parser) decodeBody(data []byte, charset string) string {
	if charset == "" {
		charset = "utf-8"
	}

	// For common charsets, just return as string
	// In production, use proper charset conversion
	return string(data)
}

func (p *Parser) readBody(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, p.maxBodySize)
	return io.ReadAll(limited)
}

func (p *Parser) sanitizeFilename(filename string) string {
	if filename == "" {
		return "attachment"
	}

	// Remove path components
	filename = strings.TrimSpace(filename)
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, "..", "_")

	// Limit length
	if len(filename) > 255 {
		ext := ""
		if idx := strings.LastIndex(filename, "."); idx > 0 {
			ext = filename[idx:]
		}
		filename = filename[:255-len(ext)] + ext
	}

	return filename
}

func (p *Parser) calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (p *Parser) extractAuthResults(email *ParsedEmail) {
	// SPF
	if spf := email.Headers.Get("Received-SPF"); spf != "" {
		parts := strings.SplitN(spf, " ", 2)
		if len(parts) > 0 {
			email.SPFResult = strings.ToLower(parts[0])
		}
	}

	// DKIM
	if dkim := email.Headers.Get("Authentication-Results"); dkim != "" {
		if strings.Contains(dkim, "dkim=pass") {
			email.DKIMResult = "pass"
		} else if strings.Contains(dkim, "dkim=fail") {
			email.DKIMResult = "fail"
		}
	}

	// DMARC
	if dmarc := email.Headers.Get("Authentication-Results"); dmarc != "" {
		if strings.Contains(dmarc, "dmarc=pass") {
			email.DMARCResult = "pass"
		} else if strings.Contains(dmarc, "dmarc=fail") {
			email.DMARCResult = "fail"
		}
	}
}

func (p *Parser) generateConversationID(email *ParsedEmail) string {
	// Use In-Reply-To or References to group conversations
	if inReplyTo := email.Headers.Get("In-Reply-To"); inReplyTo != "" {
		hash := sha256.Sum256([]byte(inReplyTo))
		return base64.URLEncoding.EncodeToString(hash[:16])
	}

	if references := email.Headers.Get("References"); references != "" {
		// Use first reference
		parts := strings.Fields(references)
		if len(parts) > 0 {
			hash := sha256.Sum256([]byte(parts[0]))
			return base64.URLEncoding.EncodeToString(hash[:16])
		}
	}

	// Generate from subject and participants
	conv := email.Subject
	if email.From != nil {
		conv += email.From.Address
	}
	for _, to := range email.To {
		conv += to.Address
	}

	hash := sha256.Sum256([]byte(conv))
	return base64.URLEncoding.EncodeToString(hash[:16])
}