package keep

import (
	"context"
	"fmt"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"go.uber.org/zap"
)

// EmailStorage handles email storage operations
type EmailStorage struct {
	config     StorageConfig
	foundation interfaces.Foundation
	logger     *zap.Logger
}

// NewEmailStorage creates a new email storage instance
func NewEmailStorage(config StorageConfig, foundation interfaces.Foundation, logger *zap.Logger) (*EmailStorage, error) {
	return &EmailStorage{
		config:     config,
		foundation: foundation,
		logger:     logger.Named("storage"),
	}, nil
}

// StoreEmail stores an email in the database
func (s *EmailStorage) StoreEmail(ctx context.Context, email *interfaces.Email) error {
	query := `
		INSERT INTO emails (
			id, message_id, from_address, to_addresses, cc_addresses, bcc_addresses,
			subject, body, html_body, headers, attachments, metadata, 
			received_at, size, raw_content, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`

	// Convert arrays to JSON strings for storage
	toJSON, _ := s.convertToJSON(email.To)
	ccJSON, _ := s.convertToJSON(email.CC)
	bccJSON, _ := s.convertToJSON(email.BCC)
	headersJSON, _ := s.convertToJSON(email.Headers)
	attachmentsJSON, _ := s.convertToJSON(email.Attachments)
	metadataJSON, _ := s.convertToJSON(email.Metadata)

	err := s.foundation.Exec(ctx, query,
		email.ID,
		email.MessageID,
		email.From,
		toJSON,
		ccJSON,
		bccJSON,
		email.Subject,
		email.Body,
		email.HTMLBody,
		headersJSON,
		attachmentsJSON,
		metadataJSON,
		email.ReceivedAt,
		email.Size,
		email.Raw,
		time.Now(),
		time.Now(),
	)

	if err != nil {
		s.logger.Error("Failed to store email", zap.Error(err), zap.String("email_id", email.ID))
		return fmt.Errorf("failed to store email: %w", err)
	}

	s.logger.Debug("Email stored successfully", zap.String("email_id", email.ID))
	return nil
}

// RetrieveEmail retrieves an email by ID
func (s *EmailStorage) RetrieveEmail(ctx context.Context, id string) (*interfaces.Email, error) {
	query := `
		SELECT id, message_id, from_address, to_addresses, cc_addresses, bcc_addresses,
			   subject, body, html_body, headers, attachments, metadata, 
			   received_at, size, raw_content
		FROM emails 
		WHERE id = $1`

	result, err := s.foundation.QueryOne(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve email: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("email not found: %s", id)
	}

	email, err := s.scanEmailFromRow(result)
	if err != nil {
		return nil, fmt.Errorf("failed to scan email: %w", err)
	}

	return email, nil
}

// RetrieveEmails retrieves emails based on filter criteria
func (s *EmailStorage) RetrieveEmails(ctx context.Context, filter *interfaces.Filter) ([]*interfaces.Email, error) {
	query, args := s.buildFilterQuery(filter)

	queryResult, err := s.foundation.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve emails: %w", err)
	}

	emails := make([]*interfaces.Email, 0, len(queryResult.Rows))
	for _, row := range queryResult.Rows {
		email, err := s.scanEmailFromRow(row)
		if err != nil {
			s.logger.Warn("Failed to scan email from row", zap.Error(err))
			continue
		}
		emails = append(emails, email)
	}

	return emails, nil
}

// DeleteEmail deletes an email by ID
func (s *EmailStorage) DeleteEmail(ctx context.Context, id string) error {
	query := `DELETE FROM emails WHERE id = $1`

	err := s.foundation.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete email: %w", err)
	}

	s.logger.Debug("Email deleted successfully", zap.String("email_id", id))
	return nil
}

// UpdateEmail updates an email with new data
func (s *EmailStorage) UpdateEmail(ctx context.Context, id string, updates map[string]interface{}) error {
	// Build dynamic update query
	setParts := make([]string, 0, len(updates))
	args := make([]interface{}, 0, len(updates)+1)
	argIndex := 1

	for field, value := range updates {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", field, argIndex))
		args = append(args, value)
		argIndex++
	}

	if len(setParts) == 0 {
		return fmt.Errorf("no updates provided")
	}

	query := fmt.Sprintf(`
		UPDATE emails 
		SET %s, updated_at = $%d
		WHERE id = $%d`,
		join(setParts, ", "),
		argIndex,
		argIndex+1)

	args = append(args, time.Now(), id)

	err := s.foundation.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update email: %w", err)
	}

	return nil
}

// TagEmail adds tags to an email
func (s *EmailStorage) TagEmail(ctx context.Context, id string, tags []string) error {
	tagsJSON, _ := s.convertToJSON(tags)

	query := `
		UPDATE emails 
		SET metadata = jsonb_set(COALESCE(metadata::jsonb, '{}'::jsonb), '{tags}', $1::jsonb)
		WHERE id = $2`

	err := s.foundation.Exec(ctx, query, tagsJSON, id)
	if err != nil {
		return fmt.Errorf("failed to tag email: %w", err)
	}

	return nil
}

// GetStorageStats returns storage statistics
func (s *EmailStorage) GetStorageStats(ctx context.Context) (*interfaces.StorageStats, error) {
	query := `
		SELECT 
			COUNT(*) as email_count,
			COALESCE(SUM(size), 0) as total_size,
			MIN(received_at) as oldest_email,
			MAX(received_at) as newest_email
		FROM emails`

	result, err := s.foundation.QueryOne(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage stats: %w", err)
	}

	stats := &interfaces.StorageStats{}
	if result != nil {
		if emailCount, ok := result["email_count"].(int64); ok {
			stats.EmailCount = emailCount
		}
		if totalSize, ok := result["total_size"].(int64); ok {
			stats.TotalSize = totalSize
		}
		if oldest, ok := result["oldest_email"].(time.Time); ok {
			stats.OldestEmail = &oldest
		}
		if newest, ok := result["newest_email"].(time.Time); ok {
			stats.NewestEmail = &newest
		}
	}

	// Calculate attachment size (simplified - would need separate query for accuracy)
	attachmentQuery := `
		SELECT COALESCE(SUM(jsonb_array_length(attachments::jsonb)), 0)
		FROM emails 
		WHERE attachments IS NOT NULL AND attachments != '[]'`

	attachResult, err := s.foundation.QueryOne(ctx, attachmentQuery)
	if err == nil && attachResult != nil {
		// This is a simplified calculation - would need proper attachment size calculation
		stats.AttachmentSize = stats.TotalSize / 10 // Estimate 10% is attachments
	}

	// Calculate usage percent (would need storage capacity info)
	stats.UsagePercent = 0.0 // Placeholder

	return stats, nil
}

// CompressEmail compresses email content (placeholder implementation)
func (s *EmailStorage) CompressEmail(email *interfaces.Email) error {
	// Implement compression logic here
	s.logger.Debug("Compressing email", zap.String("email_id", email.ID))
	return nil
}

// DecompressEmail decompresses email content (placeholder implementation)
func (s *EmailStorage) DecompressEmail(email *interfaces.Email) error {
	// Implement decompression logic here
	s.logger.Debug("Decompressing email", zap.String("email_id", email.ID))
	return nil
}

// EncryptEmail encrypts email content (placeholder implementation)
func (s *EmailStorage) EncryptEmail(email *interfaces.Email) error {
	// Implement encryption logic here
	s.logger.Debug("Encrypting email", zap.String("email_id", email.ID))
	return nil
}

// DecryptEmail decrypts email content (placeholder implementation)
func (s *EmailStorage) DecryptEmail(email *interfaces.Email) error {
	// Implement decryption logic here
	s.logger.Debug("Decrypting email", zap.String("email_id", email.ID))
	return nil
}

// Health returns storage health status
func (s *EmailStorage) Health(ctx context.Context) *interfaces.HealthStatus {
	// Test database connectivity
	query := "SELECT 1"
	_, err := s.foundation.QueryOne(ctx, query)

	status := &interfaces.HealthStatus{
		Service:   "email-storage",
		Timestamp: time.Now(),
	}

	if err != nil {
		status.Status = interfaces.HealthStatusUnhealthy
		status.Message = fmt.Sprintf("Database connectivity failed: %v", err)
	} else {
		status.Status = interfaces.HealthStatusHealthy
		status.Message = "Storage operational"
	}

	return status
}

// Private helper methods

func (s *EmailStorage) buildFilterQuery(filter *interfaces.Filter) (string, []interface{}) {
	query := `
		SELECT id, message_id, from_address, to_addresses, cc_addresses, bcc_addresses,
			   subject, body, html_body, headers, attachments, metadata, 
			   received_at, size, raw_content
		FROM emails 
		WHERE 1=1`

	args := make([]interface{}, 0)
	argIndex := 1

	if filter == nil {
		query += " ORDER BY received_at DESC LIMIT 100"
		return query, args
	}

	// Add filter conditions
	if filter.From != "" {
		query += fmt.Sprintf(" AND from_address ILIKE $%d", argIndex)
		args = append(args, "%"+filter.From+"%")
		argIndex++
	}

	if filter.To != "" {
		query += fmt.Sprintf(" AND to_addresses::text ILIKE $%d", argIndex)
		args = append(args, "%"+filter.To+"%")
		argIndex++
	}

	if filter.Subject != "" {
		query += fmt.Sprintf(" AND subject ILIKE $%d", argIndex)
		args = append(args, "%"+filter.Subject+"%")
		argIndex++
	}

	if !filter.DateFrom.IsZero() {
		query += fmt.Sprintf(" AND received_at >= $%d", argIndex)
		args = append(args, filter.DateFrom)
		argIndex++
	}

	if !filter.DateTo.IsZero() {
		query += fmt.Sprintf(" AND received_at <= $%d", argIndex)
		args = append(args, filter.DateTo)
		argIndex++
	}

	if filter.MessageID != "" {
		query += fmt.Sprintf(" AND message_id = $%d", argIndex)
		args = append(args, filter.MessageID)
		argIndex++
	}

	if filter.HasHTML != nil {
		if *filter.HasHTML {
			query += " AND html_body IS NOT NULL AND html_body != ''"
		} else {
			query += " AND (html_body IS NULL OR html_body = '')"
		}
	}

	if filter.HasAttach != nil {
		if *filter.HasAttach {
			query += " AND attachments IS NOT NULL AND attachments != '[]'"
		} else {
			query += " AND (attachments IS NULL OR attachments = '[]')"
		}
	}

	// Add ordering
	query += " ORDER BY received_at DESC"

	// Add pagination
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++

		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, filter.Offset)
			argIndex++
		}
	} else {
		query += " LIMIT 100" // Default limit
	}

	return query, args
}

func (s *EmailStorage) scanEmailFromRow(row map[string]interface{}) (*interfaces.Email, error) {
	email := &interfaces.Email{}

	// Scan basic fields
	if id, ok := row["id"].(string); ok {
		email.ID = id
	}
	if messageID, ok := row["message_id"].(string); ok {
		email.MessageID = messageID
	}
	if from, ok := row["from_address"].(string); ok {
		email.From = from
	}
	if subject, ok := row["subject"].(string); ok {
		email.Subject = subject
	}
	if body, ok := row["body"].(string); ok {
		email.Body = body
	}
	if htmlBody, ok := row["html_body"].(string); ok {
		email.HTMLBody = htmlBody
	}
	if receivedAt, ok := row["received_at"].(time.Time); ok {
		email.ReceivedAt = receivedAt
	}
	if size, ok := row["size"].(int64); ok {
		email.Size = size
	}
	if raw, ok := row["raw_content"].([]byte); ok {
		email.Raw = raw
	}

	// Parse JSON fields
	if toJSON, ok := row["to_addresses"].(string); ok {
		s.parseJSONField(toJSON, &email.To)
	}
	if ccJSON, ok := row["cc_addresses"].(string); ok {
		s.parseJSONField(ccJSON, &email.CC)
	}
	if bccJSON, ok := row["bcc_addresses"].(string); ok {
		s.parseJSONField(bccJSON, &email.BCC)
	}
	if headersJSON, ok := row["headers"].(string); ok {
		s.parseJSONField(headersJSON, &email.Headers)
	}
	if attachmentsJSON, ok := row["attachments"].(string); ok {
		s.parseJSONField(attachmentsJSON, &email.Attachments)
	}
	if metadataJSON, ok := row["metadata"].(string); ok {
		s.parseJSONField(metadataJSON, &email.Metadata)
	}

	return email, nil
}

func (s *EmailStorage) convertToJSON(data interface{}) (string, error) {
	// Simple JSON conversion - use proper JSON library in production
	// This is a placeholder implementation
	return fmt.Sprintf("%v", data), nil
}

func (s *EmailStorage) parseJSONField(jsonStr string, target interface{}) error {
	// Simple JSON parsing - use proper JSON library in production
	// This is a placeholder implementation
	return nil
}

// Helper function for string joining
func join(parts []string, separator string) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += separator + parts[i]
	}
	return result
}