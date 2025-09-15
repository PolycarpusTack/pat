package utils

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FortressTestUtils provides common testing utilities for fortress components
type FortressTestUtils struct {
	t *testing.T
}

// NewFortressTestUtils creates a new fortress test utilities instance
func NewFortressTestUtils(t *testing.T) *FortressTestUtils {
	return &FortressTestUtils{t: t}
}

// CreateTestEmail creates a test email for fortress testing
func (f *FortressTestUtils) CreateTestEmail(options ...EmailOption) *interfaces.Email {
	email := &interfaces.Email{
		ID:        uuid.New().String(),
		MessageID: fmt.Sprintf("<test-%s@fortress.test>", uuid.New().String()),
		From:      "sender@fortress.test",
		To:        []string{"recipient@fortress.test"},
		Subject:   "Test Email for Fortress",
		Body:      "This is a test email body for fortress testing",
		Headers: map[string]string{
			"X-Fortress-Test": "true",
			"Content-Type":    "text/plain",
		},
		Metadata:   make(map[string]interface{}),
		ReceivedAt: time.Now(),
		Size:       256,
	}

	// Apply options
	for _, option := range options {
		option(email)
	}

	return email
}

// EmailOption allows customizing test emails
type EmailOption func(*interfaces.Email)

// WithSubject sets the email subject
func WithSubject(subject string) EmailOption {
	return func(e *interfaces.Email) {
		e.Subject = subject
	}
}

// WithFrom sets the email sender
func WithFrom(from string) EmailOption {
	return func(e *interfaces.Email) {
		e.From = from
	}
}

// WithTo sets the email recipients
func WithTo(to []string) EmailOption {
	return func(e *interfaces.Email) {
		e.To = to
	}
}

// WithHTMLBody adds HTML body
func WithHTMLBody(html string) EmailOption {
	return func(e *interfaces.Email) {
		e.HTMLBody = html
	}
}

// WithAttachment adds an attachment
func WithAttachment(name, contentType string, content []byte) EmailOption {
	return func(e *interfaces.Email) {
		attachment := interfaces.Attachment{
			ID:       uuid.New().String(),
			Name:     name,
			Type:     contentType,
			Size:     int64(len(content)),
			Content:  content,
			Checksum: fmt.Sprintf("sha256-%x", content),
		}
		e.Attachments = append(e.Attachments, attachment)
	}
}

// WithHeaders adds custom headers
func WithHeaders(headers map[string]string) EmailOption {
	return func(e *interfaces.Email) {
		for k, v := range headers {
			e.Headers[k] = v
		}
	}
}

// WithMetadata adds metadata
func WithMetadata(metadata map[string]interface{}) EmailOption {
	return func(e *interfaces.Email) {
		for k, v := range metadata {
			e.Metadata[k] = v
		}
	}
}

// CreateTestFilter creates a test email filter
func (f *FortressTestUtils) CreateTestFilter(options ...FilterOption) *interfaces.Filter {
	filter := &interfaces.Filter{
		Limit:  10,
		Offset: 0,
	}

	// Apply options
	for _, option := range options {
		option(filter)
	}

	return filter
}

// FilterOption allows customizing test filters
type FilterOption func(*interfaces.Filter)

// WithFilterFrom sets the from filter
func WithFilterFrom(from string) FilterOption {
	return func(f *interfaces.Filter) {
		f.From = from
	}
}

// WithFilterSubject sets the subject filter
func WithFilterSubject(subject string) FilterOption {
	return func(f *interfaces.Filter) {
		f.Subject = subject
	}
}

// WithFilterDateRange sets the date range filter
func WithFilterDateRange(from, to time.Time) FilterOption {
	return func(f *interfaces.Filter) {
		f.DateFrom = from
		f.DateTo = to
	}
}

// WithFilterLimit sets the limit
func WithFilterLimit(limit int) FilterOption {
	return func(f *interfaces.Filter) {
		f.Limit = limit
	}
}

// CreateTestSearchQuery creates a test search query
func (f *FortressTestUtils) CreateTestSearchQuery(query string, options ...SearchQueryOption) *interfaces.SearchQuery {
	searchQuery := &interfaces.SearchQuery{
		Query:     query,
		SortBy:    "receivedAt",
		SortOrder: "desc",
		Fuzzy:     false,
		Highlight: true,
		Pagination: &interfaces.PaginationParams{
			Page:     1,
			PageSize: 20,
			Offset:   0,
			Limit:    20,
		},
	}

	// Apply options
	for _, option := range options {
		option(searchQuery)
	}

	return searchQuery
}

// SearchQueryOption allows customizing test search queries
type SearchQueryOption func(*interfaces.SearchQuery)

// WithSearchFields sets the search fields
func WithSearchFields(fields []string) SearchQueryOption {
	return func(sq *interfaces.SearchQuery) {
		sq.Fields = fields
	}
}

// WithSearchFuzzy enables fuzzy search
func WithSearchFuzzy(fuzzy bool) SearchQueryOption {
	return func(sq *interfaces.SearchQuery) {
		sq.Fuzzy = fuzzy
	}
}

// WithSearchSort sets the sort parameters
func WithSearchSort(sortBy, sortOrder string) SearchQueryOption {
	return func(sq *interfaces.SearchQuery) {
		sq.SortBy = sortBy
		sq.SortOrder = sortOrder
	}
}

// CreateTestHealthStatus creates a test health status
func (f *FortressTestUtils) CreateTestHealthStatus(service string, status interfaces.HealthStatusType, message string) *interfaces.HealthStatus {
	return &interfaces.HealthStatus{
		Service:   service,
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"test": true,
		},
		Duration: time.Millisecond * 50,
	}
}

// AssertEmailEquals compares two emails for testing
func (f *FortressTestUtils) AssertEmailEquals(expected, actual *interfaces.Email) {
	assert.Equal(f.t, expected.ID, actual.ID, "Email IDs should match")
	assert.Equal(f.t, expected.MessageID, actual.MessageID, "Message IDs should match")
	assert.Equal(f.t, expected.From, actual.From, "From addresses should match")
	assert.Equal(f.t, expected.To, actual.To, "To addresses should match")
	assert.Equal(f.t, expected.Subject, actual.Subject, "Subjects should match")
	assert.Equal(f.t, expected.Body, actual.Body, "Bodies should match")
}

// AssertHealthStatusValid validates a health status
func (f *FortressTestUtils) AssertHealthStatusValid(status *interfaces.HealthStatus, expectedService string) {
	require.NotNil(f.t, status, "Health status should not be nil")
	assert.Equal(f.t, expectedService, status.Service, "Service name should match")
	assert.NotZero(f.t, status.Timestamp, "Timestamp should be set")
	assert.True(f.t, status.Duration >= 0, "Duration should be non-negative")
	assert.Contains(f.t, []interfaces.HealthStatusType{
		interfaces.HealthStatusHealthy,
		interfaces.HealthStatusDegraded,
		interfaces.HealthStatusUnhealthy,
		interfaces.HealthStatusUnknown,
	}, status.Status, "Status should be valid")
}

// CreateTestContext creates a test context with timeout
func (f *FortressTestUtils) CreateTestContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// CreateTestContextWithValues creates a test context with values
func (f *FortressTestUtils) CreateTestContextWithValues(values map[string]interface{}) context.Context {
	ctx := context.Background()
	for key, value := range values {
		ctx = context.WithValue(ctx, key, value)
	}
	return ctx
}

// WaitForCondition waits for a condition to be met or times out
func (f *FortressTestUtils) WaitForCondition(condition func() bool, timeout time.Duration, message string) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(time.Millisecond * 10)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if condition() {
				return
			}
			if time.Now().After(deadline) {
				f.t.Fatalf("Condition not met within timeout: %s", message)
			}
		}
	}
}

// AssertNoError is a convenience method for no error assertion
func (f *FortressTestUtils) AssertNoError(err error, msgAndArgs ...interface{}) {
	require.NoError(f.t, err, msgAndArgs...)
}

// AssertError is a convenience method for error assertion
func (f *FortressTestUtils) AssertError(err error, msgAndArgs ...interface{}) {
	require.Error(f.t, err, msgAndArgs...)
}

// AssertEqual is a convenience method for equality assertion
func (f *FortressTestUtils) AssertEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	assert.Equal(f.t, expected, actual, msgAndArgs...)
}

// AssertNotNil is a convenience method for not nil assertion
func (f *FortressTestUtils) AssertNotNil(object interface{}, msgAndArgs ...interface{}) {
	assert.NotNil(f.t, object, msgAndArgs...)
}

// AssertTrue is a convenience method for true assertion
func (f *FortressTestUtils) AssertTrue(value bool, msgAndArgs ...interface{}) {
	assert.True(f.t, value, msgAndArgs...)
}

// AssertFalse is a convenience method for false assertion
func (f *FortressTestUtils) AssertFalse(value bool, msgAndArgs ...interface{}) {
	assert.False(f.t, value, msgAndArgs...)
}

// FortressTestEmailBatch creates a batch of test emails for performance testing
func (f *FortressTestUtils) FortressTestEmailBatch(count int) []*interfaces.Email {
	emails := make([]*interfaces.Email, count)
	for i := 0; i < count; i++ {
		emails[i] = f.CreateTestEmail(
			WithSubject(fmt.Sprintf("Batch Email %d", i+1)),
			WithFrom(fmt.Sprintf("sender%d@fortress.test", i+1)),
			WithTo([]string{fmt.Sprintf("recipient%d@fortress.test", i+1)}),
		)
	}
	return emails
}

// FortressTestConcurrentExecution runs test functions concurrently
func (f *FortressTestUtils) FortressTestConcurrentExecution(workers int, testFunc func(workerID int)) {
	done := make(chan bool, workers)
	
	for i := 0; i < workers; i++ {
		go func(workerID int) {
			defer func() { done <- true }()
			testFunc(workerID)
		}(i)
	}
	
	for i := 0; i < workers; i++ {
		<-done
	}
}