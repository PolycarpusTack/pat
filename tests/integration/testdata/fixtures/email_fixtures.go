package fixtures

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pat-fortress/pkg/fortress/interfaces"
)

// EmailFixtures provides comprehensive email test data
type EmailFixtures struct{}

// NewEmailFixtures creates a new email fixtures instance
func NewEmailFixtures() *EmailFixtures {
	return &EmailFixtures{}
}

// SimpleTextEmail creates a basic text email
func (f *EmailFixtures) SimpleTextEmail() *interfaces.Email {
	return &interfaces.Email{
		ID:        uuid.New().String(),
		MessageID: "<simple-" + uuid.New().String() + "@fortress.test>",
		From:      "sender@fortress.test",
		To:        []string{"recipient@fortress.test"},
		Subject:   "Simple Test Email",
		Body:      "This is a simple text email for integration testing.",
		Headers: map[string]string{
			"Content-Type":     "text/plain; charset=utf-8",
			"X-Fortress-Test":  "simple-text",
			"Message-ID":       "<simple-" + uuid.New().String() + "@fortress.test>",
			"Date":             time.Now().Format(time.RFC2822),
			"MIME-Version":     "1.0",
		},
		Metadata:   make(map[string]interface{}),
		ReceivedAt: time.Now(),
		Size:       int64(len("This is a simple text email for integration testing.")),
	}
}

// HTMLEmail creates an HTML email with attachments
func (f *EmailFixtures) HTMLEmail() *interfaces.Email {
	htmlBody := `
<!DOCTYPE html>
<html>
<head>
    <title>Integration Test Email</title>
</head>
<body>
    <h1>Fortress Integration Test</h1>
    <p>This is an <strong>HTML email</strong> for testing purposes.</p>
    <p>It contains:</p>
    <ul>
        <li>HTML formatting</li>
        <li>Multiple recipients</li>
        <li>Attachments</li>
        <li>Custom headers</li>
    </ul>
    <p>Best regards,<br>Fortress Test Suite</p>
</body>
</html>`

	textBody := `Fortress Integration Test

This is an HTML email for testing purposes.

It contains:
- HTML formatting
- Multiple recipients
- Attachments
- Custom headers

Best regards,
Fortress Test Suite`

	attachment := interfaces.Attachment{
		ID:       uuid.New().String(),
		Name:     "test-document.txt",
		Type:     "text/plain",
		Size:     27,
		Content:  []byte("This is a test attachment."),
		Checksum: "sha256-test",
	}

	return &interfaces.Email{
		ID:        uuid.New().String(),
		MessageID: "<html-" + uuid.New().String() + "@fortress.test>",
		From:      "html-sender@fortress.test",
		To:        []string{"recipient1@fortress.test", "recipient2@fortress.test"},
		CC:        []string{"cc@fortress.test"},
		BCC:       []string{"bcc@fortress.test"},
		Subject:   "HTML Integration Test Email",
		Body:      textBody,
		HTMLBody:  htmlBody,
		Attachments: []interfaces.Attachment{attachment},
		Headers: map[string]string{
			"Content-Type":       "multipart/mixed; boundary=fortress-test-boundary",
			"X-Fortress-Test":    "html-multipart",
			"X-Priority":         "3",
			"X-MSMail-Priority":  "Normal",
			"X-Test-Category":    "integration",
			"Message-ID":         "<html-" + uuid.New().String() + "@fortress.test>",
			"Date":               time.Now().Format(time.RFC2822),
			"MIME-Version":       "1.0",
		},
		Metadata: map[string]interface{}{
			"test_type":        "html_multipart",
			"attachment_count": 1,
			"has_html":         true,
		},
		ReceivedAt: time.Now(),
		Size:       int64(len(htmlBody) + len(textBody) + int(attachment.Size)),
	}
}

// LargeEmailWithAttachments creates an email with multiple large attachments
func (f *EmailFixtures) LargeEmailWithAttachments() *interfaces.Email {
	// Create large text content
	largeContent := make([]byte, 1024*1024) // 1MB
	for i := range largeContent {
		largeContent[i] = byte('A' + (i % 26))
	}

	// Create binary attachment (simulated PDF)
	binaryContent := make([]byte, 512*1024) // 512KB
	for i := range binaryContent {
		binaryContent[i] = byte(i % 256)
	}

	attachments := []interfaces.Attachment{
		{
			ID:       uuid.New().String(),
			Name:     "large-document.txt",
			Type:     "text/plain",
			Size:     int64(len(largeContent)),
			Content:  largeContent,
			Checksum: "sha256-large",
		},
		{
			ID:       uuid.New().String(),
			Name:     "binary-file.pdf",
			Type:     "application/pdf",
			Size:     int64(len(binaryContent)),
			Content:  binaryContent,
			Checksum: "sha256-binary",
		},
		{
			ID:       uuid.New().String(),
			Name:     "encoded-data.b64",
			Type:     "application/octet-stream",
			Size:     1024,
			Content:  []byte(base64.StdEncoding.EncodeToString([]byte("This is base64 encoded test data"))),
			Checksum: "sha256-encoded",
		},
	}

	return &interfaces.Email{
		ID:        uuid.New().String(),
		MessageID: "<large-" + uuid.New().String() + "@fortress.test>",
		From:      "bulk-sender@fortress.test",
		To:        []string{"recipient@fortress.test"},
		Subject:   "Large Email with Multiple Attachments",
		Body:      "This email contains large attachments for performance testing.",
		Attachments: attachments,
		Headers: map[string]string{
			"Content-Type":      "multipart/mixed; boundary=fortress-large-boundary",
			"X-Fortress-Test":   "large-attachments",
			"X-Priority":        "3",
			"X-Test-Size":       "large",
			"Message-ID":        "<large-" + uuid.New().String() + "@fortress.test>",
			"Date":              time.Now().Format(time.RFC2822),
			"MIME-Version":      "1.0",
		},
		Metadata: map[string]interface{}{
			"test_type":        "large_attachments",
			"attachment_count": len(attachments),
			"total_size":       int64(len(largeContent)) + int64(len(binaryContent)) + 1024,
		},
		ReceivedAt: time.Now(),
		Size:       int64(len(largeContent)) + int64(len(binaryContent)) + 1024 + 500, // +500 for headers/body
	}
}

// EmailWithSecurityHeaders creates an email with security-related headers
func (f *EmailFixtures) EmailWithSecurityHeaders() *interfaces.Email {
	return &interfaces.Email{
		ID:        uuid.New().String(),
		MessageID: "<security-" + uuid.New().String() + "@fortress.test>",
		From:      "security-test@fortress.test",
		To:        []string{"security-recipient@fortress.test"},
		Subject:   "Security Headers Test Email",
		Body:      "This email contains various security headers for testing.",
		Headers: map[string]string{
			"Content-Type":                     "text/plain; charset=utf-8",
			"X-Fortress-Test":                  "security-headers",
			"Authentication-Results":           "fortress.test; spf=pass smtp.mailfrom=security-test@fortress.test",
			"Received-SPF":                     "pass (fortress.test: domain of security-test@fortress.test designates 192.168.1.1 as permitted sender)",
			"DKIM-Signature":                   "v=1; a=rsa-sha256; c=relaxed/simple; d=fortress.test; s=default; t=1234567890; bh=test; h=from:to:subject:date; b=test",
			"ARC-Authentication-Results":       "i=1; fortress.test; spf=pass smtp.mailfrom=security-test@fortress.test",
			"X-Spam-Score":                     "0.1",
			"X-Spam-Status":                    "No, score=0.1 required=5.0",
			"X-Anti-Virus":                     "clean",
			"Message-ID":                       "<security-" + uuid.New().String() + "@fortress.test>",
			"Date":                             time.Now().Format(time.RFC2822),
			"MIME-Version":                     "1.0",
		},
		Metadata: map[string]interface{}{
			"test_type":      "security_headers",
			"spf_status":     "pass",
			"dkim_status":    "valid",
			"spam_score":     0.1,
			"virus_status":   "clean",
		},
		ReceivedAt: time.Now(),
		Size:       int64(len("This email contains various security headers for testing.")),
	}
}

// EmailWithUnicodeContent creates an email with international characters
func (f *EmailFixtures) EmailWithUnicodeContent() *interfaces.Email {
	unicodeBody := `
多言語テストメール / Multilingual Test Email / Тестовое письмо

English: This email contains various unicode characters for testing.
日本語: このメールはテスト用の様々なユニコード文字を含んでいます。
Русский: Это письмо содержит различные символы Unicode для тестирования.
العربية: يحتوي هذا البريد الإلكتروني على رموز يونيكود مختلفة للاختبار.
中文: 这封电子邮件包含各种用于测试的Unicode字符。
Español: Este correo electrónico contiene varios caracteres unicode para pruebas.
Français: Ce courriel contient divers caractères unicode pour les tests.
Deutsch: Diese E-Mail enthält verschiedene Unicode-Zeichen zum Testen.

Special characters: ☺ ★ ♥ ♦ ♣ ♠ • ◘ ○ ◙ ♂ ♀ ♪ ♫ ☼ ► ◄ ↕ ‼ ¶ § ▬ ↨ ↑ ↓ → ←

Mathematical symbols: ∑ ∏ ∫ ∆ ∇ ∂ ∞ ≤ ≥ ≠ ≈ ± × ÷

Currency symbols: $ € ¥ £ ¢ ₹ ₽ ₩ ₪ ₦
`

	return &interfaces.Email{
		ID:        uuid.New().String(),
		MessageID: "<unicode-" + uuid.New().String() + "@fortress.test>",
		From:      "unicode-sender@fortress.test",
		To:        []string{"unicode-recipient@fortress.test"},
		Subject:   "多言語テスト / Unicode Test / Тестовое письмо",
		Body:      unicodeBody,
		Headers: map[string]string{
			"Content-Type":       "text/plain; charset=utf-8",
			"Content-Transfer-Encoding": "8bit",
			"X-Fortress-Test":    "unicode-content",
			"X-Test-Languages":   "en,ja,ru,ar,zh,es,fr,de",
			"Message-ID":         "<unicode-" + uuid.New().String() + "@fortress.test>",
			"Date":               time.Now().Format(time.RFC2822),
			"MIME-Version":       "1.0",
		},
		Metadata: map[string]interface{}{
			"test_type":      "unicode_content",
			"languages":      []string{"en", "ja", "ru", "ar", "zh", "es", "fr", "de"},
			"has_special_chars": true,
			"encoding":       "utf-8",
		},
		ReceivedAt: time.Now(),
		Size:       int64(len([]byte(unicodeBody))), // byte length for UTF-8
	}
}

// MalformedEmail creates an email with various malformed aspects for testing
func (f *EmailFixtures) MalformedEmail() *interfaces.Email {
	return &interfaces.Email{
		ID:        uuid.New().String(),
		MessageID: "<malformed-" + uuid.New().String() + "@fortress.test>",
		From:      "malformed sender@fortress.test", // Space in email (malformed)
		To:        []string{"recipient@fortress.test", "invalid-email"}, // One valid, one invalid
		Subject:   "Malformed Test Email\nWith\nNewlines", // Newlines in subject
		Body:      "This email has various malformed aspects for testing error handling.",
		Headers: map[string]string{
			"Content-Type":    "", // Empty content type
			"X-Fortress-Test": "malformed",
			"Invalid-Header":  "header with\nnewlines and\ttabs",
			"Message-ID":      "<malformed-" + uuid.New().String() + "@fortress.test>",
			"Date":            "Invalid Date Format",
			// Missing MIME-Version intentionally
		},
		Metadata: map[string]interface{}{
			"test_type":        "malformed",
			"expected_errors":  true,
			"validation_flags": []string{"invalid_from", "invalid_to", "malformed_subject", "empty_content_type"},
		},
		ReceivedAt: time.Now(),
		Size:       256,
	}
}

// EmailBatch creates a batch of emails for bulk testing
func (f *EmailFixtures) EmailBatch(count int) []*interfaces.Email {
	emails := make([]*interfaces.Email, count)
	
	for i := 0; i < count; i++ {
		emails[i] = &interfaces.Email{
			ID:        uuid.New().String(),
			MessageID: fmt.Sprintf("<batch-%d-%s@fortress.test>", i, uuid.New().String()),
			From:      fmt.Sprintf("batch-sender-%d@fortress.test", i),
			To:        []string{fmt.Sprintf("batch-recipient-%d@fortress.test", i)},
			Subject:   fmt.Sprintf("Batch Email #%d", i+1),
			Body:      fmt.Sprintf("This is batch email number %d of %d for performance testing.", i+1, count),
			Headers: map[string]string{
				"Content-Type":    "text/plain; charset=utf-8",
				"X-Fortress-Test": "batch",
				"X-Batch-Index":   fmt.Sprintf("%d", i),
				"X-Batch-Total":   fmt.Sprintf("%d", count),
				"Message-ID":      fmt.Sprintf("<batch-%d-%s@fortress.test>", i, uuid.New().String()),
				"Date":            time.Now().Add(time.Duration(i) * time.Second).Format(time.RFC2822),
				"MIME-Version":    "1.0",
			},
			Metadata: map[string]interface{}{
				"test_type":   "batch",
				"batch_index": i,
				"batch_total": count,
			},
			ReceivedAt: time.Now().Add(time.Duration(i) * time.Second),
			Size:       int64(50 + len(fmt.Sprintf("This is batch email number %d of %d for performance testing.", i+1, count))),
		}
	}
	
	return emails
}

// EmailsWithDifferentSizes creates emails of various sizes for testing
func (f *EmailFixtures) EmailsWithDifferentSizes() []*interfaces.Email {
	sizes := []struct {
		name string
		size int
	}{
		{"tiny", 100},
		{"small", 1024},        // 1KB
		{"medium", 10240},      // 10KB  
		{"large", 102400},      // 100KB
		{"xlarge", 1048576},    // 1MB
	}

	emails := make([]*interfaces.Email, len(sizes))
	
	for i, size := range sizes {
		body := make([]byte, size.size)
		for j := range body {
			body[j] = byte('A' + (j % 26))
		}

		emails[i] = &interfaces.Email{
			ID:        uuid.New().String(),
			MessageID: fmt.Sprintf("<%s-%s@fortress.test>", size.name, uuid.New().String()),
			From:      fmt.Sprintf("%s-sender@fortress.test", size.name),
			To:        []string{fmt.Sprintf("%s-recipient@fortress.test", size.name)},
			Subject:   fmt.Sprintf("%s Email Test", size.name),
			Body:      string(body),
			Headers: map[string]string{
				"Content-Type":    "text/plain; charset=utf-8",
				"X-Fortress-Test": "size-variant",
				"X-Test-Size":     size.name,
				"Message-ID":      fmt.Sprintf("<%s-%s@fortress.test>", size.name, uuid.New().String()),
				"Date":            time.Now().Format(time.RFC2822),
				"MIME-Version":    "1.0",
			},
			Metadata: map[string]interface{}{
				"test_type":    "size_variant",
				"size_category": size.name,
				"target_size":  size.size,
			},
			ReceivedAt: time.Now(),
			Size:       int64(size.size),
		}
	}
	
	return emails
}

// AllTestEmails returns a comprehensive set of test emails
func (f *EmailFixtures) AllTestEmails() []*interfaces.Email {
	emails := []*interfaces.Email{
		f.SimpleTextEmail(),
		f.HTMLEmail(),
		f.LargeEmailWithAttachments(),
		f.EmailWithSecurityHeaders(),
		f.EmailWithUnicodeContent(),
		f.MalformedEmail(),
	}
	
	// Add size variants
	emails = append(emails, f.EmailsWithDifferentSizes()...)
	
	// Add a small batch
	emails = append(emails, f.EmailBatch(5)...)
	
	return emails
}