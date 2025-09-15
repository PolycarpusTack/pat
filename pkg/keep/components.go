package keep

import (
	"context"
	"fmt"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"go.uber.org/zap"
)

// EmailSearcher handles email search operations
type EmailSearcher struct {
	config     SearchConfig
	foundation interfaces.Foundation
	logger     *zap.Logger
}

// NewEmailSearcher creates a new email searcher
func NewEmailSearcher(config SearchConfig, foundation interfaces.Foundation, logger *zap.Logger) (*EmailSearcher, error) {
	return &EmailSearcher{
		config:     config,
		foundation: foundation,
		logger:     logger.Named("searcher"),
	}, nil
}

// SearchEmails performs advanced search on emails
func (s *EmailSearcher) SearchEmails(ctx context.Context, query *interfaces.SearchQuery) (*interfaces.SearchResults, error) {
	startTime := time.Now()
	
	// Build search query based on configuration
	sqlQuery, args := s.buildSearchQuery(query)
	
	// Execute search with timeout
	searchCtx, cancel := context.WithTimeout(ctx, s.config.SearchTimeout)
	defer cancel()
	
	result, err := s.foundation.Query(searchCtx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("search query failed: %w", err)
	}

	// Convert results
	emails := make([]*interfaces.Email, 0, len(result.Rows))
	for _, row := range result.Rows {
		email, err := s.scanEmailFromSearchResult(row)
		if err != nil {
			s.logger.Warn("Failed to scan search result", zap.Error(err))
			continue
		}
		emails = append(emails, email)
	}

	// Get total count for pagination
	totalCount, err := s.getSearchResultCount(ctx, query)
	if err != nil {
		s.logger.Warn("Failed to get search result count", zap.Error(err))
		totalCount = int64(len(emails))
	}

	searchResults := &interfaces.SearchResults{
		Emails: emails,
		Total:  totalCount,
		Took:   time.Since(startTime),
	}

	// Add highlights if requested
	if query.Highlight {
		s.addHighlights(searchResults, query)
	}

	// Add facets if requested
	if len(query.Facets) > 0 {
		s.addFacets(ctx, searchResults, query)
	}

	return searchResults, nil
}

// IndexEmail indexes an email for search
func (s *EmailSearcher) IndexEmail(ctx context.Context, email *interfaces.Email) error {
	// Create or update search index entry
	indexQuery := `
		INSERT INTO email_search_index (email_id, search_content, indexed_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (email_id) 
		DO UPDATE SET search_content = EXCLUDED.search_content, indexed_at = EXCLUDED.indexed_at`

	searchContent := s.buildSearchContent(email)
	
	err := s.foundation.Exec(ctx, indexQuery, email.ID, searchContent, time.Now())
	if err != nil {
		return fmt.Errorf("failed to index email: %w", err)
	}

	return nil
}

// UpdateIndex updates search index for an email
func (s *EmailSearcher) UpdateIndex(ctx context.Context, email *interfaces.Email) error {
	return s.IndexEmail(ctx, email) // Same operation for update
}

// RemoveFromIndex removes an email from search index
func (s *EmailSearcher) RemoveFromIndex(ctx context.Context, emailID string) error {
	query := `DELETE FROM email_search_index WHERE email_id = $1`
	
	err := s.foundation.Exec(ctx, query, emailID)
	if err != nil {
		return fmt.Errorf("failed to remove email from index: %w", err)
	}

	return nil
}

// Private helper methods for EmailSearcher

func (s *EmailSearcher) buildSearchQuery(query *interfaces.SearchQuery) (string, []interface{}) {
	baseQuery := `
		SELECT e.id, e.message_id, e.from_address, e.to_addresses, e.subject, 
			   e.body, e.html_body, e.received_at, e.size
		FROM emails e`

	if s.config.IndexingEnabled {
		baseQuery += ` LEFT JOIN email_search_index i ON e.id = i.email_id`
	}

	whereClause := " WHERE 1=1"
	args := make([]interface{}, 0)
	argIndex := 1

	// Add search conditions
	if query.Query != "" {
		if s.config.FullTextSearch && s.config.IndexingEnabled {
			whereClause += fmt.Sprintf(" AND i.search_content @@ plainto_tsquery($%d)", argIndex)
		} else {
			whereClause += fmt.Sprintf(" AND (e.subject ILIKE $%d OR e.body ILIKE $%d)", argIndex, argIndex)
		}
		
		searchTerm := query.Query
		if !s.config.FullTextSearch {
			searchTerm = "%" + query.Query + "%"
		}
		args = append(args, searchTerm)
		argIndex++
	}

	// Add filter conditions
	if query.Filters != nil {
		filterQuery, filterArgs := s.buildFilterConditions(query.Filters, argIndex)
		whereClause += filterQuery
		args = append(args, filterArgs...)
		argIndex += len(filterArgs)
	}

	// Add sorting
	orderClause := " ORDER BY e.received_at DESC"
	if query.SortBy != "" {
		direction := "DESC"
		if query.SortOrder == "asc" {
			direction = "ASC"
		}
		orderClause = fmt.Sprintf(" ORDER BY e.%s %s", query.SortBy, direction)
	}

	// Add pagination
	limitClause := ""
	if query.Pagination != nil {
		if query.Pagination.Limit > 0 {
			limitClause = fmt.Sprintf(" LIMIT $%d", argIndex)
			args = append(args, query.Pagination.Limit)
			argIndex++

			if query.Pagination.Offset > 0 {
				limitClause += fmt.Sprintf(" OFFSET $%d", argIndex)
				args = append(args, query.Pagination.Offset)
				argIndex++
			}
		}
	} else {
		limitClause = fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, s.config.MaxSearchResults)
		argIndex++
	}

	finalQuery := baseQuery + whereClause + orderClause + limitClause
	return finalQuery, args
}

func (s *EmailSearcher) buildFilterConditions(filter *interfaces.Filter, startArgIndex int) (string, []interface{}) {
	conditions := ""
	args := make([]interface{}, 0)
	argIndex := startArgIndex

	if filter.From != "" {
		conditions += fmt.Sprintf(" AND e.from_address ILIKE $%d", argIndex)
		args = append(args, "%"+filter.From+"%")
		argIndex++
	}

	if filter.To != "" {
		conditions += fmt.Sprintf(" AND e.to_addresses::text ILIKE $%d", argIndex)
		args = append(args, "%"+filter.To+"%")
		argIndex++
	}

	if !filter.DateFrom.IsZero() {
		conditions += fmt.Sprintf(" AND e.received_at >= $%d", argIndex)
		args = append(args, filter.DateFrom)
		argIndex++
	}

	if !filter.DateTo.IsZero() {
		conditions += fmt.Sprintf(" AND e.received_at <= $%d", argIndex)
		args = append(args, filter.DateTo)
		argIndex++
	}

	return conditions, args
}

func (s *EmailSearcher) getSearchResultCount(ctx context.Context, query *interfaces.SearchQuery) (int64, error) {
	countQuery := "SELECT COUNT(*) FROM emails e"
	
	if s.config.IndexingEnabled {
		countQuery += " LEFT JOIN email_search_index i ON e.id = i.email_id"
	}

	whereClause := " WHERE 1=1"
	args := make([]interface{}, 0)
	argIndex := 1

	if query.Query != "" {
		if s.config.FullTextSearch && s.config.IndexingEnabled {
			whereClause += fmt.Sprintf(" AND i.search_content @@ plainto_tsquery($%d)", argIndex)
		} else {
			whereClause += fmt.Sprintf(" AND (e.subject ILIKE $%d OR e.body ILIKE $%d)", argIndex, argIndex)
		}
		args = append(args, query.Query)
		argIndex++
	}

	if query.Filters != nil {
		filterQuery, filterArgs := s.buildFilterConditions(query.Filters, argIndex)
		whereClause += filterQuery
		args = append(args, filterArgs...)
	}

	finalCountQuery := countQuery + whereClause

	result, err := s.foundation.QueryOne(ctx, finalCountQuery, args...)
	if err != nil {
		return 0, err
	}

	if result != nil {
		if count, ok := result["count"].(int64); ok {
			return count, nil
		}
	}

	return 0, nil
}

func (s *EmailSearcher) buildSearchContent(email *interfaces.Email) string {
	content := fmt.Sprintf("%s %s %s %s", 
		email.From, 
		email.Subject, 
		email.Body,
		email.HTMLBody)
	
	// Add recipient information
	for _, to := range email.To {
		content += " " + to
	}
	
	// Add attachment names
	for _, att := range email.Attachments {
		content += " " + att.Name
	}

	return content
}

func (s *EmailSearcher) scanEmailFromSearchResult(row map[string]interface{}) (*interfaces.Email, error) {
	email := &interfaces.Email{}

	// Scan fields from search result
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

	return email, nil
}

func (s *EmailSearcher) addHighlights(results *interfaces.SearchResults, query *interfaces.SearchQuery) {
	// Implementation would add search term highlights to results
	results.Highlights = make(map[string][]string)
}

func (s *EmailSearcher) addFacets(ctx context.Context, results *interfaces.SearchResults, query *interfaces.SearchQuery) {
	// Implementation would add faceted search results
	results.Facets = make(map[string]interface{})
}

// EmailAnalyzer handles email analytics and statistics
type EmailAnalyzer struct {
	config     AnalyticsConfig
	foundation interfaces.Foundation
	logger     *zap.Logger
}

// NewEmailAnalyzer creates a new email analyzer
func NewEmailAnalyzer(config AnalyticsConfig, foundation interfaces.Foundation, logger *zap.Logger) (*EmailAnalyzer, error) {
	return &EmailAnalyzer{
		config:     config,
		foundation: foundation,
		logger:     logger.Named("analyzer"),
	}, nil
}

// AnalyzeEmail performs analytics on a single email
func (a *EmailAnalyzer) AnalyzeEmail(ctx context.Context, email *interfaces.Email) error {
	if !a.config.Enabled {
		return nil
	}

	// Store analytics data
	analyticsData := map[string]interface{}{
		"email_id":         email.ID,
		"from_domain":      extractDomain(email.From),
		"recipient_count":  len(email.To) + len(email.CC) + len(email.BCC),
		"has_html":         email.HTMLBody != "",
		"has_attachments":  len(email.Attachments) > 0,
		"attachment_count": len(email.Attachments),
		"size_bytes":       email.Size,
		"analyzed_at":      time.Now(),
	}

	// Insert analytics record
	query := `
		INSERT INTO email_analytics (
			email_id, from_domain, recipient_count, has_html, has_attachments,
			attachment_count, size_bytes, analyzed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	err := a.foundation.Exec(ctx, query,
		analyticsData["email_id"],
		analyticsData["from_domain"],
		analyticsData["recipient_count"],
		analyticsData["has_html"],
		analyticsData["has_attachments"],
		analyticsData["attachment_count"],
		analyticsData["size_bytes"],
		analyticsData["analyzed_at"],
	)

	if err != nil {
		return fmt.Errorf("failed to store analytics: %w", err)
	}

	return nil
}

// GetEmailStats returns email statistics based on filter
func (a *EmailAnalyzer) GetEmailStats(ctx context.Context, filter *interfaces.Filter) (*interfaces.EmailStats, error) {
	stats := &interfaces.EmailStats{}

	// Get basic counts
	countQuery := "SELECT COUNT(*) as total FROM emails"
	whereClause, args := a.buildAnalyticsFilter(filter)
	
	result, err := a.foundation.QueryOne(ctx, countQuery+whereClause, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get email count: %w", err)
	}

	if result != nil {
		if total, ok := result["total"].(int64); ok {
			stats.Total = total
		}
	}

	// Get size distribution
	stats.SizeDistrib, _ = a.getSizeDistribution(ctx, filter)
	
	// Get domain distribution
	stats.DomainDistrib, _ = a.getDomainDistribution(ctx, filter)
	
	// Get time distribution
	stats.TimeDistrib, _ = a.getTimeDistribution(ctx, filter)

	return stats, nil
}

// Private helper methods for EmailAnalyzer

func (a *EmailAnalyzer) buildAnalyticsFilter(filter *interfaces.Filter) (string, []interface{}) {
	if filter == nil {
		return "", []interface{}{}
	}

	whereClause := " WHERE 1=1"
	args := make([]interface{}, 0)
	argIndex := 1

	if filter.From != "" {
		whereClause += fmt.Sprintf(" AND from_address ILIKE $%d", argIndex)
		args = append(args, "%"+filter.From+"%")
		argIndex++
	}

	if !filter.DateFrom.IsZero() {
		whereClause += fmt.Sprintf(" AND received_at >= $%d", argIndex)
		args = append(args, filter.DateFrom)
		argIndex++
	}

	if !filter.DateTo.IsZero() {
		whereClause += fmt.Sprintf(" AND received_at <= $%d", argIndex)
		args = append(args, filter.DateTo)
		argIndex++
	}

	return whereClause, args
}

func (a *EmailAnalyzer) getSizeDistribution(ctx context.Context, filter *interfaces.Filter) (map[string]int64, error) {
	query := `
		SELECT 
			CASE 
				WHEN size < 1024 THEN 'small'
				WHEN size < 1048576 THEN 'medium' 
				ELSE 'large' 
			END as size_category,
			COUNT(*) as count
		FROM emails`
	
	whereClause, args := a.buildAnalyticsFilter(filter)
	query += whereClause + " GROUP BY size_category"

	result, err := a.foundation.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	distribution := make(map[string]int64)
	for _, row := range result.Rows {
		if category, ok := row["size_category"].(string); ok {
			if count, ok := row["count"].(int64); ok {
				distribution[category] = count
			}
		}
	}

	return distribution, nil
}

func (a *EmailAnalyzer) getDomainDistribution(ctx context.Context, filter *interfaces.Filter) (map[string]int64, error) {
	query := `
		SELECT 
			SPLIT_PART(from_address, '@', 2) as domain,
			COUNT(*) as count
		FROM emails`
	
	whereClause, args := a.buildAnalyticsFilter(filter)
	query += whereClause + " GROUP BY domain ORDER BY count DESC LIMIT 10"

	result, err := a.foundation.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	distribution := make(map[string]int64)
	for _, row := range result.Rows {
		if domain, ok := row["domain"].(string); ok {
			if count, ok := row["count"].(int64); ok {
				distribution[domain] = count
			}
		}
	}

	return distribution, nil
}

func (a *EmailAnalyzer) getTimeDistribution(ctx context.Context, filter *interfaces.Filter) (map[string]int64, error) {
	query := `
		SELECT 
			DATE_TRUNC('hour', received_at) as hour,
			COUNT(*) as count
		FROM emails`
	
	whereClause, args := a.buildAnalyticsFilter(filter)
	query += whereClause + " GROUP BY hour ORDER BY hour DESC LIMIT 24"

	result, err := a.foundation.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	distribution := make(map[string]int64)
	for _, row := range result.Rows {
		if hour, ok := row["hour"].(time.Time); ok {
			if count, ok := row["count"].(int64); ok {
				hourStr := hour.Format("2006-01-02 15:00")
				distribution[hourStr] = count
			}
		}
	}

	return distribution, nil
}

// EmailValidator handles email validation
type EmailValidator struct {
	config ValidationConfig
	logger *zap.Logger
}

// NewEmailValidator creates a new email validator
func NewEmailValidator(config ValidationConfig, logger *zap.Logger) (*EmailValidator, error) {
	return &EmailValidator{
		config: config,
		logger: logger.Named("validator"),
	}, nil
}

// ValidateEmail validates an email message
func (v *EmailValidator) ValidateEmail(ctx context.Context, email *interfaces.Email) error {
	if !v.config.ValidateStructure {
		return nil
	}

	// Validate required fields
	if email.ID == "" {
		return fmt.Errorf("email ID is required")
	}

	if email.From == "" {
		return fmt.Errorf("from address is required")
	}

	if len(email.To) == 0 {
		return fmt.Errorf("at least one recipient is required")
	}

	// Validate headers if enabled
	if v.config.ValidateHeaders {
		if err := v.validateHeaders(email); err != nil {
			return fmt.Errorf("header validation failed: %w", err)
		}
	}

	// Validate encoding if enabled
	if v.config.ValidateEncoding {
		if err := v.validateEncoding(email); err != nil {
			return fmt.Errorf("encoding validation failed: %w", err)
		}
	}

	return nil
}

func (v *EmailValidator) validateHeaders(email *interfaces.Email) error {
	// Basic header validation
	if email.Headers == nil {
		return fmt.Errorf("headers are missing")
	}

	// Check for required headers
	requiredHeaders := []string{"Date", "From", "To"}
	for _, header := range requiredHeaders {
		if _, exists := email.Headers[header]; !exists {
			return fmt.Errorf("required header missing: %s", header)
		}
	}

	return nil
}

func (v *EmailValidator) validateEncoding(email *interfaces.Email) error {
	// Basic encoding validation
	// This would typically check for valid UTF-8, proper MIME encoding, etc.
	return nil
}