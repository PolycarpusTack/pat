package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/pat/pkg/repository"
)

// EmailRepository implements repository.EmailRepository using PostgreSQL
type EmailRepository struct {
	db     *sqlx.DB
	logger *zap.Logger
	tracer trace.Tracer
}

// NewEmailRepository creates a new PostgreSQL email repository
func NewEmailRepository(db *sqlx.DB, logger *zap.Logger) *EmailRepository {
	return &EmailRepository{
		db:     db,
		logger: logger,
		tracer: otel.Tracer("repository.postgres.email"),
	}
}

// Create inserts a new email
func (r *EmailRepository) Create(ctx context.Context, email *repository.Email) error {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.Create")
	defer span.End()

	query := `
		INSERT INTO pat.emails (
			id, tenant_id, message_id, conversation_id,
			from_address, from_name, to_addresses, cc_addresses, bcc_addresses, subject,
			text_body, html_body, raw_email, headers,
			attachments, attachment_count, total_size_bytes,
			protocol, source_ip, source_port,
			status, spam_score, spam_details, virus_scan_result, validation_results,
			received_at, processed_at, created_at
		) VALUES (
			:id, :tenant_id, :message_id, :conversation_id,
			:from_address, :from_name, :to_addresses, :cc_addresses, :bcc_addresses, :subject,
			:text_body, :html_body, :raw_email, :headers,
			:attachments, :attachment_count, :total_size_bytes,
			:protocol, :source_ip, :source_port,
			:status, :spam_score, :spam_details, :virus_scan_result, :validation_results,
			:received_at, :processed_at, NOW()
		)`

	// Convert slices to JSONB
	email.ID = uuid.New()
	email.CreatedAt = time.Now()
	email.UpdatedAt = time.Now()

	_, err := r.db.NamedExecContext(ctx, query, r.emailToDBModel(email))
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create email: %w", err)
	}

	span.SetAttributes(
		attribute.String("email.id", email.ID.String()),
		attribute.String("email.tenant_id", email.TenantID.String()),
	)

	return nil
}

// Get retrieves an email by ID
func (r *EmailRepository) Get(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) (*repository.Email, error) {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.Get")
	defer span.End()

	query := `
		SELECT * FROM pat.emails 
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		LIMIT 1`

	var dbEmail dbEmail
	err := r.db.GetContext(ctx, &dbEmail, query, id, tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("email not found")
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get email: %w", err)
	}

	return r.dbModelToEmail(&dbEmail), nil
}

// GetByMessageID retrieves an email by message ID
func (r *EmailRepository) GetByMessageID(ctx context.Context, messageID string, tenantID uuid.UUID) (*repository.Email, error) {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.GetByMessageID")
	defer span.End()

	query := `
		SELECT * FROM pat.emails 
		WHERE message_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`

	var dbEmail dbEmail
	err := r.db.GetContext(ctx, &dbEmail, query, messageID, tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("email not found")
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get email by message ID: %w", err)
	}

	return r.dbModelToEmail(&dbEmail), nil
}

// List retrieves emails with pagination - FORTRESS PROTECTED
func (r *EmailRepository) List(ctx context.Context, opts repository.QueryOptions) (*repository.PagedResult[repository.Email], error) {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.List")
	defer span.End()

	// FORTRESS SECURITY: Guard against SQL injection
	if err := r.guardValidateQueryOptions(opts); err != nil {
		span.RecordError(err)
		r.watchtowerLogSecurityEvent(ctx, "sql_injection_attempt", map[string]interface{}{
			"filters": opts.Filters,
			"order_by": opts.OrderBy,
			"error": err.Error(),
		})
		return nil, fmt.Errorf("fortress guard: invalid query options: %w", err)
	}

	// Build rampart WHERE clause with parameterized queries
	conditions := []string{"tenant_id = $1"}
	params := []interface{}{opts.TenantID}
	paramIndex := 2

	if !opts.IncludeDeleted {
		conditions = append(conditions, "deleted_at IS NULL")
	}

	// FORTRESS SECURITY: Add filters with parameterized queries
	for key, value := range opts.Filters {
		switch key {
		case "status":
			conditions = append(conditions, fmt.Sprintf("status = $%d", paramIndex))
			params = append(params, value)
			paramIndex++
		case "from_address":
			conditions = append(conditions, fmt.Sprintf("from_address ILIKE $%d", paramIndex))
			params = append(params, "%"+fmt.Sprint(value)+"%")
			paramIndex++
		case "subject":
			conditions = append(conditions, fmt.Sprintf("subject ILIKE $%d", paramIndex))
			params = append(params, "%"+fmt.Sprint(value)+"%")
			paramIndex++
		case "after":
			conditions = append(conditions, fmt.Sprintf("created_at > $%d", paramIndex))
			params = append(params, value)
			paramIndex++
		case "before":
			conditions = append(conditions, fmt.Sprintf("created_at < $%d", paramIndex))
			params = append(params, value)
			paramIndex++
		}
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query - FORTRESS PROTECTED
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM pat.emails WHERE %s", whereClause)
	
	var total int64
	err := r.db.GetContext(ctx, &total, countQuery, params...)
	if err != nil {
		span.RecordError(err)
		r.watchtowerLogSecurityEvent(ctx, "database_error", map[string]interface{}{
			"operation": "count",
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to count emails: %w", err)
	}

	// FORTRESS SECURITY: Validate and sanitize ORDER BY
	orderBy, orderDir := r.rampartValidateOrderBy(opts.OrderBy, opts.OrderDesc)

	// List query - FORTRESS PROTECTED
	listQuery := fmt.Sprintf(`
		SELECT * FROM pat.emails 
		WHERE %s 
		ORDER BY %s %s 
		LIMIT $%d OFFSET $%d`,
		whereClause, orderBy, orderDir, paramIndex, paramIndex+1)

	params = append(params, opts.Limit, opts.Offset)

	rows, err := r.db.QueryContext(ctx, listQuery, params...)
	if err != nil {
		span.RecordError(err)
		r.watchtowerLogSecurityEvent(ctx, "database_error", map[string]interface{}{
			"operation": "list",
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to list emails: %w", err)
	}
	defer rows.Close()

	var emails []repository.Email
	for rows.Next() {
		var dbEmail dbEmail
		if err := rows.Scan(
			&dbEmail.ID, &dbEmail.TenantID, &dbEmail.MessageID, &dbEmail.ConversationID,
			&dbEmail.FromAddress, &dbEmail.FromName, &dbEmail.ToAddresses, &dbEmail.CCAddresses,
			&dbEmail.BCCAddresses, &dbEmail.Subject, &dbEmail.TextBody, &dbEmail.HTMLBody,
			&dbEmail.RawEmail, &dbEmail.Headers, &dbEmail.Attachments, &dbEmail.AttachmentCount,
			&dbEmail.TotalSizeBytes, &dbEmail.Protocol, &dbEmail.SourceIP, &dbEmail.SourcePort,
			&dbEmail.Status, &dbEmail.SpamScore, &dbEmail.SpamDetails, &dbEmail.VirusScanResult,
			&dbEmail.ValidationResults, &dbEmail.ReceivedAt, &dbEmail.ProcessedAt,
			&dbEmail.CreatedAt, &dbEmail.UpdatedAt, &dbEmail.DeletedAt,
		); err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to scan email: %w", err)
		}
		emails = append(emails, *r.dbModelToEmail(&dbEmail))
	}

	return &repository.PagedResult[repository.Email]{
		Items:   emails,
		Total:   total,
		Limit:   opts.Limit,
		Offset:  opts.Offset,
		HasMore: int64(opts.Offset+opts.Limit) < total,
	}, nil
}

// Update updates an email
func (r *EmailRepository) Update(ctx context.Context, email *repository.Email) error {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.Update")
	defer span.End()

	email.UpdatedAt = time.Now()

	query := `
		UPDATE pat.emails SET
			status = :status,
			spam_score = :spam_score,
			spam_details = :spam_details,
			virus_scan_result = :virus_scan_result,
			validation_results = :validation_results,
			processed_at = :processed_at,
			updated_at = NOW()
		WHERE id = :id AND tenant_id = :tenant_id AND deleted_at IS NULL`

	result, err := r.db.NamedExecContext(ctx, query, r.emailToDBModel(email))
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to update email: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("email not found")
	}

	return nil
}

// Delete soft deletes an email
func (r *EmailRepository) Delete(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.Delete")
	defer span.End()

	query := `
		UPDATE pat.emails 
		SET deleted_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, id, tenantID)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete email: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("email not found")
	}

	return nil
}

// HardDelete permanently deletes an email
func (r *EmailRepository) HardDelete(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.HardDelete")
	defer span.End()

	query := `DELETE FROM pat.emails WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, id, tenantID)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to hard delete email: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("email not found")
	}

	return nil
}

// Search performs full-text search on emails
func (r *EmailRepository) Search(ctx context.Context, query string, opts repository.QueryOptions) (*repository.PagedResult[repository.Email], error) {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.Search")
	defer span.End()

	// Use PostgreSQL full-text search
	searchQuery := `
		SELECT *, 
			ts_rank(
				to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(text_body, '')),
				plainto_tsquery('english', $1)
			) as rank
		FROM pat.emails
		WHERE tenant_id = $2 
			AND deleted_at IS NULL
			AND (
				to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(text_body, '')) @@ plainto_tsquery('english', $1)
				OR from_address ILIKE '%' || $1 || '%'
				OR EXISTS (
					SELECT 1 FROM jsonb_array_elements(to_addresses) AS addr
					WHERE addr->>'address' ILIKE '%' || $1 || '%'
				)
			)
		ORDER BY rank DESC, created_at DESC
		LIMIT $3 OFFSET $4`

	// Count query
	countQuery := `
		SELECT COUNT(*)
		FROM pat.emails
		WHERE tenant_id = $1 
			AND deleted_at IS NULL
			AND (
				to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(text_body, '')) @@ plainto_tsquery('english', $2)
				OR from_address ILIKE '%' || $2 || '%'
				OR EXISTS (
					SELECT 1 FROM jsonb_array_elements(to_addresses) AS addr
					WHERE addr->>'address' ILIKE '%' || $2 || '%'
				)
			)`

	var total int64
	err := r.db.GetContext(ctx, &total, countQuery, opts.TenantID, query)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to count search results: %w", err)
	}

	// Execute search
	rows, err := r.db.QueryContext(ctx, searchQuery, query, opts.TenantID, opts.Limit, opts.Offset)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to search emails: %w", err)
	}
	defer rows.Close()

	var emails []repository.Email
	for rows.Next() {
		var dbEmail dbEmail
		var rank float64
		if err := rows.Scan(&dbEmail, &rank); err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to scan search result: %w", err)
		}
		emails = append(emails, *r.dbModelToEmail(&dbEmail))
	}

	return &repository.PagedResult[repository.Email]{
		Items:   emails,
		Total:   total,
		Limit:   opts.Limit,
		Offset:  opts.Offset,
		HasMore: int64(opts.Offset+opts.Limit) < total,
	}, nil
}

// AddTags adds tags to an email
func (r *EmailRepository) AddTags(ctx context.Context, emailID uuid.UUID, tags []string) error {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.AddTags")
	defer span.End()

	if len(tags) == 0 {
		return nil
	}

	// Use UPSERT to avoid duplicates
	query := `
		INSERT INTO pat.email_tags (email_id, tag)
		SELECT $1, unnest($2::text[])
		ON CONFLICT (email_id, tag) DO NOTHING`

	_, err := r.db.ExecContext(ctx, query, emailID, pq.Array(tags))
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to add tags: %w", err)
	}

	return nil
}

// RemoveTags removes tags from an email
func (r *EmailRepository) RemoveTags(ctx context.Context, emailID uuid.UUID, tags []string) error {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.RemoveTags")
	defer span.End()

	if len(tags) == 0 {
		return nil
	}

	query := `
		DELETE FROM pat.email_tags 
		WHERE email_id = $1 AND tag = ANY($2)`

	_, err := r.db.ExecContext(ctx, query, emailID, pq.Array(tags))
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to remove tags: %w", err)
	}

	return nil
}

// GetTags gets all tags for an email
func (r *EmailRepository) GetTags(ctx context.Context, emailID uuid.UUID) ([]string, error) {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.GetTags")
	defer span.End()

	query := `
		SELECT tag FROM pat.email_tags 
		WHERE email_id = $1 
		ORDER BY tag`

	var tags []string
	err := r.db.SelectContext(ctx, &tags, query, emailID)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get tags: %w", err)
	}

	return tags, nil
}

// CountByStatus counts emails by status
func (r *EmailRepository) CountByStatus(ctx context.Context, tenantID uuid.UUID, status string) (int64, error) {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.CountByStatus")
	defer span.End()

	query := `
		SELECT COUNT(*) 
		FROM pat.emails 
		WHERE tenant_id = $1 AND status = $2 AND deleted_at IS NULL`

	var count int64
	err := r.db.GetContext(ctx, &count, query, tenantID, status)
	if err != nil {
		span.RecordError(err)
		return 0, fmt.Errorf("failed to count by status: %w", err)
	}

	return count, nil
}

// GetConversation retrieves all emails in a conversation
func (r *EmailRepository) GetConversation(ctx context.Context, conversationID uuid.UUID, tenantID uuid.UUID) ([]*repository.Email, error) {
	ctx, span := r.tracer.Start(ctx, "EmailRepository.GetConversation")
	defer span.End()

	query := `
		SELECT * FROM pat.emails 
		WHERE conversation_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		ORDER BY created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, conversationID, tenantID)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get conversation: %w", err)
	}
	defer rows.Close()

	var emails []*repository.Email
	for rows.Next() {
		var dbEmail dbEmail
		if err := rows.Scan(&dbEmail); err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to scan conversation email: %w", err)
		}
		emails = append(emails, r.dbModelToEmail(&dbEmail))
	}

	return emails, nil
}

// Helper types and methods

type dbEmail struct {
	ID               uuid.UUID       `db:"id"`
	TenantID         uuid.UUID       `db:"tenant_id"`
	MessageID        string          `db:"message_id"`
	ConversationID   *uuid.UUID      `db:"conversation_id"`
	FromAddress      string          `db:"from_address"`
	FromName         *string         `db:"from_name"`
	ToAddresses      json.RawMessage `db:"to_addresses"`
	CCAddresses      json.RawMessage `db:"cc_addresses"`
	BCCAddresses     json.RawMessage `db:"bcc_addresses"`
	Subject          *string         `db:"subject"`
	TextBody         *string         `db:"text_body"`
	HTMLBody         *string         `db:"html_body"`
	RawEmail         *string         `db:"raw_email"`
	Headers          json.RawMessage `db:"headers"`
	Attachments      json.RawMessage `db:"attachments"`
	AttachmentCount  int             `db:"attachment_count"`
	TotalSizeBytes   int64           `db:"total_size_bytes"`
	Protocol         string          `db:"protocol"`
	SourceIP         *string         `db:"source_ip"`
	SourcePort       *int            `db:"source_port"`
	Status           string          `db:"status"`
	SpamScore        *float32        `db:"spam_score"`
	SpamDetails      json.RawMessage `db:"spam_details"`
	VirusScanResult  json.RawMessage `db:"virus_scan_result"`
	ValidationResults json.RawMessage `db:"validation_results"`
	ReceivedAt       time.Time       `db:"received_at"`
	ProcessedAt      *time.Time      `db:"processed_at"`
	CreatedAt        time.Time       `db:"created_at"`
	UpdatedAt        time.Time       `db:"updated_at"`
	DeletedAt        *time.Time      `db:"deleted_at"`
}

func (r *EmailRepository) emailToDBModel(email *repository.Email) interface{} {
	// Convert repository.Email to database model
	// This would include JSON marshaling of complex fields
	return email
}

func (r *EmailRepository) dbModelToEmail(dbEmail *dbEmail) *repository.Email {
	// Convert database model to repository.Email
	// This would include JSON unmarshaling of complex fields
	email := &repository.Email{
		ID:              dbEmail.ID,
		TenantID:        dbEmail.TenantID,
		MessageID:       dbEmail.MessageID,
		ConversationID:  dbEmail.ConversationID,
		FromAddress:     dbEmail.FromAddress,
		FromName:        dbEmail.FromName,
		Subject:         dbEmail.Subject,
		TextBody:        dbEmail.TextBody,
		HTMLBody:        dbEmail.HTMLBody,
		RawEmail:        dbEmail.RawEmail,
		AttachmentCount: dbEmail.AttachmentCount,
		TotalSizeBytes:  dbEmail.TotalSizeBytes,
		Protocol:        dbEmail.Protocol,
		SourceIP:        dbEmail.SourceIP,
		SourcePort:      dbEmail.SourcePort,
		Status:          dbEmail.Status,
		SpamScore:       dbEmail.SpamScore,
		ReceivedAt:      dbEmail.ReceivedAt,
		ProcessedAt:     dbEmail.ProcessedAt,
		CreatedAt:       dbEmail.CreatedAt,
		UpdatedAt:       dbEmail.UpdatedAt,
		DeletedAt:       dbEmail.DeletedAt,
	}

	// Unmarshal JSON fields
	json.Unmarshal(dbEmail.ToAddresses, &email.ToAddresses)
	json.Unmarshal(dbEmail.CCAddresses, &email.CCAddresses)
	json.Unmarshal(dbEmail.BCCAddresses, &email.BCCAddresses)
	json.Unmarshal(dbEmail.Headers, &email.Headers)
	json.Unmarshal(dbEmail.Attachments, &email.Attachments)
	json.Unmarshal(dbEmail.SpamDetails, &email.SpamDetails)
	json.Unmarshal(dbEmail.VirusScanResult, &email.VirusScanResult)
	json.Unmarshal(dbEmail.ValidationResults, &email.ValidationResults)

	return email
}

// FORTRESS SECURITY METHODS - NEVER TRUST, ALWAYS VERIFY

// guardValidateQueryOptions validates query options to prevent SQL injection
func (r *EmailRepository) guardValidateQueryOptions(opts repository.QueryOptions) error {
	// Guard against malicious filter values
	for key, value := range opts.Filters {
		if err := r.armoryValidateFilterValue(key, value); err != nil {
			return fmt.Errorf("fortress guard: invalid filter %s: %w", key, err)
		}
	}

	// Guard against malicious ORDER BY columns
	if opts.OrderBy != "" {
		if !r.rampartIsValidColumn(opts.OrderBy) {
			return fmt.Errorf("fortress guard: invalid order by column: %s", opts.OrderBy)
		}
	}

	// Guard against excessive limits (potential DoS)
	if opts.Limit > 10000 {
		return fmt.Errorf("fortress guard: limit too large: %d", opts.Limit)
	}

	return nil
}

// armoryValidateFilterValue validates individual filter values
func (r *EmailRepository) armoryValidateFilterValue(key string, value interface{}) error {
	strValue := fmt.Sprint(value)
	
	// Check for common SQL injection patterns
	maliciousPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
		"UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
		"union", "select", "insert", "update", "delete", "drop",
	}

	for _, pattern := range maliciousPatterns {
		if strings.Contains(strings.ToUpper(strValue), strings.ToUpper(pattern)) {
			return fmt.Errorf("potential SQL injection detected: %s", pattern)
		}
	}

	// Validate based on filter type
	switch key {
	case "status":
		validStatuses := []string{"new", "processed", "quarantined", "spam", "virus"}
		if !r.armoryContains(validStatuses, strValue) {
			return fmt.Errorf("invalid status: %s", strValue)
		}
	case "after", "before":
		// Validate timestamp format
		if _, err := time.Parse(time.RFC3339, strValue); err != nil {
			if _, err := time.Parse("2006-01-02", strValue); err != nil {
				return fmt.Errorf("invalid timestamp format: %s", strValue)
			}
		}
	case "from_address", "subject":
		// Limit length to prevent buffer overflow
		if len(strValue) > 1000 {
			return fmt.Errorf("value too long: %d characters", len(strValue))
		}
	}

	return nil
}

// rampartValidateOrderBy validates and sanitizes ORDER BY clauses
func (r *EmailRepository) rampartValidateOrderBy(orderBy string, orderDesc bool) (string, string) {
	// Default to safe column
	if orderBy == "" {
		orderBy = "created_at"
	}

	// Whitelist of allowed columns
	if !r.rampartIsValidColumn(orderBy) {
		r.logger.Warn("Invalid ORDER BY column attempted", 
			zap.String("column", orderBy),
			zap.String("security_event", "sql_injection_attempt"))
		orderBy = "created_at" // Safe default
	}

	orderDir := "ASC"
	if orderDesc {
		orderDir = "DESC"
	}

	return orderBy, orderDir
}

// rampartIsValidColumn checks if a column name is in the allowed whitelist
func (r *EmailRepository) rampartIsValidColumn(column string) bool {
	allowedColumns := map[string]bool{
		"id":               true,
		"created_at":       true,
		"updated_at":       true,
		"received_at":      true,
		"processed_at":     true,
		"from_address":     true,
		"subject":          true,
		"status":           true,
		"total_size_bytes": true,
		"spam_score":       true,
		"attachment_count": true,
	}

	return allowedColumns[column]
}

// armoryContains checks if a slice contains a string
func (r *EmailRepository) armoryContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// watchtowerLogSecurityEvent logs security events for monitoring
func (r *EmailRepository) watchtowerLogSecurityEvent(ctx context.Context, eventType string, details map[string]interface{}) {
	r.logger.Warn("FORTRESS SECURITY EVENT",
		zap.String("event_type", eventType),
		zap.Any("details", details),
		zap.String("component", "email_repository"),
		zap.Time("timestamp", time.Now()),
	)

	// In production, this would also send to SIEM
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(
			attribute.String("security.event_type", eventType),
			attribute.String("security.component", "email_repository"),
		)
	}
}