package interfaces

import (
	"context"
	"time"
)

// Common types used across fortress services

// Email represents an email message within the fortress
type Email struct {
	ID          string                 `json:"id"`
	MessageID   string                 `json:"messageId"`
	From        string                 `json:"from"`
	To          []string               `json:"to"`
	CC          []string               `json:"cc,omitempty"`
	BCC         []string               `json:"bcc,omitempty"`
	Subject     string                 `json:"subject"`
	Body        string                 `json:"body"`
	HTMLBody    string                 `json:"htmlBody,omitempty"`
	Headers     map[string]string      `json:"headers"`
	Attachments []Attachment           `json:"attachments,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	ReceivedAt  time.Time              `json:"receivedAt"`
	Size        int64                  `json:"size"`
	Raw         []byte                 `json:"raw,omitempty"`
}

// Attachment represents an email attachment
type Attachment struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Content  []byte `json:"content,omitempty"`
	Checksum string `json:"checksum"`
}

// Filter represents search/filter criteria for emails
type Filter struct {
	From        string    `json:"from,omitempty"`
	To          string    `json:"to,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	DateFrom    time.Time `json:"dateFrom,omitempty"`
	DateTo      time.Time `json:"dateTo,omitempty"`
	HasHTML     *bool     `json:"hasHtml,omitempty"`
	HasAttach   *bool     `json:"hasAttachments,omitempty"`
	MessageID   string    `json:"messageId,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Limit       int       `json:"limit,omitempty"`
	Offset      int       `json:"offset,omitempty"`
}

// SearchQuery represents advanced search parameters
type SearchQuery struct {
	Query      string            `json:"query"`
	Fields     []string          `json:"fields,omitempty"`
	Filters    *Filter           `json:"filters,omitempty"`
	SortBy     string            `json:"sortBy,omitempty"`
	SortOrder  string            `json:"sortOrder,omitempty"`
	Fuzzy      bool              `json:"fuzzy,omitempty"`
	Highlight  bool              `json:"highlight,omitempty"`
	Facets     []string          `json:"facets,omitempty"`
	Pagination *PaginationParams `json:"pagination,omitempty"`
}

// SearchResults contains search results and metadata
type SearchResults struct {
	Emails      []*Email               `json:"emails"`
	Total       int64                  `json:"total"`
	Took        time.Duration          `json:"took"`
	Facets      map[string]interface{} `json:"facets,omitempty"`
	Highlights  map[string][]string    `json:"highlights,omitempty"`
	Suggestions []string               `json:"suggestions,omitempty"`
}

// PaginationParams for result pagination
type PaginationParams struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
	Offset   int `json:"offset"`
	Limit    int `json:"limit"`
}

// HealthStatus represents the health status of a service
type HealthStatus struct {
	Service   string                 `json:"service"`
	Status    HealthStatusType       `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Duration  time.Duration          `json:"duration"`
}

// HealthStatusType represents health status types
type HealthStatusType string

const (
	HealthStatusHealthy   HealthStatusType = "healthy"
	HealthStatusDegraded  HealthStatusType = "degraded"
	HealthStatusUnhealthy HealthStatusType = "unhealthy"
	HealthStatusUnknown   HealthStatusType = "unknown"
)

// LogLevel represents logging levels
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

// PluginConfig represents plugin configuration
type PluginConfig struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Type        PluginType             `json:"type"`
	Config      map[string]interface{} `json:"config"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Timeout     time.Duration          `json:"timeout"`
	RetryPolicy *RetryPolicy           `json:"retryPolicy,omitempty"`
}

// PluginType represents types of plugins
type PluginType string

const (
	PluginTypeFilter      PluginType = "filter"
	PluginTypeValidator   PluginType = "validator"
	PluginTypeTransformer PluginType = "transformer"
	PluginTypeNotifier    PluginType = "notifier"
	PluginTypeAnalyzer    PluginType = "analyzer"
)

// PluginResult represents plugin execution results
type PluginResult struct {
	Success   bool                   `json:"success"`
	Message   string                 `json:"message,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Error     error                  `json:"error,omitempty"`
	Duration  time.Duration          `json:"duration"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Modified  bool                   `json:"modified"`
	Actions   []PluginAction         `json:"actions,omitempty"`
}

// PluginAction represents actions to be taken based on plugin results
type PluginAction struct {
	Type   string                 `json:"type"`
	Target string                 `json:"target"`
	Data   map[string]interface{} `json:"data"`
}

// PluginInfo contains plugin metadata
type PluginInfo struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Type        PluginType             `json:"type"`
	Description string                 `json:"description"`
	Author      string                 `json:"author"`
	Status      PluginStatus           `json:"status"`
	LastRun     *time.Time             `json:"lastRun,omitempty"`
	Stats       map[string]interface{} `json:"stats,omitempty"`
}

// PluginStatus represents plugin execution status
type PluginStatus string

const (
	PluginStatusLoaded   PluginStatus = "loaded"
	PluginStatusActive   PluginStatus = "active"
	PluginStatusInactive PluginStatus = "inactive"
	PluginStatusError    PluginStatus = "error"
)

// RetryPolicy defines retry behavior for plugin execution
type RetryPolicy struct {
	MaxRetries int           `json:"maxRetries"`
	Delay      time.Duration `json:"delay"`
	Backoff    string        `json:"backoff"` // linear, exponential
	MaxDelay   time.Duration `json:"maxDelay"`
}

// Transaction represents a database transaction
type Transaction interface {
	Commit() error
	Rollback() error
	Query(query string, args ...interface{}) (*QueryResult, error)
	Exec(query string, args ...interface{}) error
}

// QueryResult represents database query results
type QueryResult struct {
	Rows     []map[string]interface{} `json:"rows"`
	Count    int64                    `json:"count"`
	Duration time.Duration            `json:"duration"`
	Error    error                    `json:"error,omitempty"`
}

// HandlerFunc represents HTTP handler function type
type HandlerFunc func(context.Context, *Request) (*Response, error)

// Request represents HTTP request
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Query   map[string]string `json:"query"`
	Body    []byte            `json:"body"`
	UserID  string            `json:"userId,omitempty"`
	Roles   []string          `json:"roles,omitempty"`
}

// Response represents HTTP response
type Response struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
}

// GraphQLResult represents GraphQL query results
type GraphQLResult struct {
	Data   interface{} `json:"data"`
	Errors []string    `json:"errors,omitempty"`
}

// Event represents fortress internal events
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	UserID    string                 `json:"userId,omitempty"`
	TraceID   string                 `json:"traceId,omitempty"`
}

// EventHandler represents event handler function type
type EventHandler func(context.Context, *Event) error