package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Common types
type QueryOptions struct {
	Limit      int
	Offset     int
	OrderBy    string
	OrderDesc  bool
	TenantID   uuid.UUID
	Filters    map[string]interface{}
	IncludeDeleted bool
}

type PagedResult[T any] struct {
	Items      []T
	Total      int64
	Limit      int
	Offset     int
	HasMore    bool
}

// Email represents an email entity
type Email struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	TenantID       uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	MessageID      string                 `json:"message_id" db:"message_id"`
	ConversationID *uuid.UUID             `json:"conversation_id,omitempty" db:"conversation_id"`
	
	// Email metadata
	FromAddress    string                 `json:"from_address" db:"from_address"`
	FromName       *string                `json:"from_name,omitempty" db:"from_name"`
	ToAddresses    []EmailAddress         `json:"to_addresses" db:"to_addresses"`
	CCAddresses    []EmailAddress         `json:"cc_addresses,omitempty" db:"cc_addresses"`
	BCCAddresses   []EmailAddress         `json:"bcc_addresses,omitempty" db:"bcc_addresses"`
	Subject        *string                `json:"subject,omitempty" db:"subject"`
	
	// Content
	TextBody       *string                `json:"text_body,omitempty" db:"text_body"`
	HTMLBody       *string                `json:"html_body,omitempty" db:"html_body"`
	RawEmail       *string                `json:"raw_email,omitempty" db:"raw_email"`
	Headers        map[string]string      `json:"headers" db:"headers"`
	
	// Attachments
	Attachments    []Attachment           `json:"attachments" db:"attachments"`
	AttachmentCount int                   `json:"attachment_count" db:"attachment_count"`
	TotalSizeBytes int64                 `json:"total_size_bytes" db:"total_size_bytes"`
	
	// Protocol info
	Protocol       string                 `json:"protocol" db:"protocol"`
	SourceIP       *string                `json:"source_ip,omitempty" db:"source_ip"`
	SourcePort     *int                   `json:"source_port,omitempty" db:"source_port"`
	
	// Processing info
	Status         string                 `json:"status" db:"status"`
	SpamScore      *float32               `json:"spam_score,omitempty" db:"spam_score"`
	SpamDetails    map[string]interface{} `json:"spam_details,omitempty" db:"spam_details"`
	VirusScanResult map[string]interface{} `json:"virus_scan_result,omitempty" db:"virus_scan_result"`
	ValidationResults map[string]interface{} `json:"validation_results,omitempty" db:"validation_results"`
	
	// Timestamps
	ReceivedAt     time.Time              `json:"received_at" db:"received_at"`
	ProcessedAt    *time.Time             `json:"processed_at,omitempty" db:"processed_at"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt      *time.Time             `json:"deleted_at,omitempty" db:"deleted_at"`
}

type EmailAddress struct {
	Address string  `json:"address"`
	Name    *string `json:"name,omitempty"`
}

type Attachment struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	S3Key       string `json:"s3_key"`
	Checksum    string `json:"checksum"`
}

// Workflow represents a workflow entity
type Workflow struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	TenantID     uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Name         string                 `json:"name" db:"name"`
	Description  *string                `json:"description,omitempty" db:"description"`
	TriggerRules map[string]interface{} `json:"trigger_rules" db:"trigger_rules"`
	Steps        []WorkflowStep         `json:"steps" db:"steps"`
	Settings     map[string]interface{} `json:"settings" db:"settings"`
	IsActive     bool                   `json:"is_active" db:"is_active"`
	CreatedBy    *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt    *time.Time             `json:"deleted_at,omitempty" db:"deleted_at"`
}

type WorkflowStep struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Name       string                 `json:"name"`
	Config     map[string]interface{} `json:"config"`
	Conditions map[string]interface{} `json:"conditions,omitempty"`
}

// Plugin represents a plugin entity
type Plugin struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	TenantID     *uuid.UUID             `json:"tenant_id,omitempty" db:"tenant_id"`
	Name         string                 `json:"name" db:"name"`
	Version      string                 `json:"version" db:"version"`
	Description  *string                `json:"description,omitempty" db:"description"`
	Author       *string                `json:"author,omitempty" db:"author"`
	RepositoryURL *string               `json:"repository_url,omitempty" db:"repository_url"`
	Manifest     map[string]interface{} `json:"manifest" db:"manifest"`
	Config       map[string]interface{} `json:"config" db:"config"`
	Status       string                 `json:"status" db:"status"`
	IsGlobal     bool                   `json:"is_global" db:"is_global"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt    *time.Time             `json:"deleted_at,omitempty" db:"deleted_at"`
}

// Repository interfaces

// EmailRepository defines the interface for email data access
type EmailRepository interface {
	// Create inserts a new email
	Create(ctx context.Context, email *Email) error
	
	// Get retrieves an email by ID
	Get(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) (*Email, error)
	
	// GetByMessageID retrieves an email by message ID
	GetByMessageID(ctx context.Context, messageID string, tenantID uuid.UUID) (*Email, error)
	
	// List retrieves emails with pagination
	List(ctx context.Context, opts QueryOptions) (*PagedResult[Email], error)
	
	// Update updates an email
	Update(ctx context.Context, email *Email) error
	
	// Delete soft deletes an email
	Delete(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error
	
	// HardDelete permanently deletes an email
	HardDelete(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error
	
	// Search performs full-text search on emails
	Search(ctx context.Context, query string, opts QueryOptions) (*PagedResult[Email], error)
	
	// AddTags adds tags to an email
	AddTags(ctx context.Context, emailID uuid.UUID, tags []string) error
	
	// RemoveTags removes tags from an email
	RemoveTags(ctx context.Context, emailID uuid.UUID, tags []string) error
	
	// GetTags gets all tags for an email
	GetTags(ctx context.Context, emailID uuid.UUID) ([]string, error)
	
	// CountByStatus counts emails by status
	CountByStatus(ctx context.Context, tenantID uuid.UUID, status string) (int64, error)
	
	// GetConversation retrieves all emails in a conversation
	GetConversation(ctx context.Context, conversationID uuid.UUID, tenantID uuid.UUID) ([]*Email, error)
}

// WorkflowRepository defines the interface for workflow data access
type WorkflowRepository interface {
	// Create inserts a new workflow
	Create(ctx context.Context, workflow *Workflow) error
	
	// Get retrieves a workflow by ID
	Get(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) (*Workflow, error)
	
	// List retrieves workflows with pagination
	List(ctx context.Context, opts QueryOptions) (*PagedResult[Workflow], error)
	
	// Update updates a workflow
	Update(ctx context.Context, workflow *Workflow) error
	
	// Delete soft deletes a workflow
	Delete(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error
	
	// GetActive retrieves all active workflows for a tenant
	GetActive(ctx context.Context, tenantID uuid.UUID) ([]*Workflow, error)
	
	// GetByTrigger retrieves workflows that match a trigger
	GetByTrigger(ctx context.Context, tenantID uuid.UUID, triggerType string) ([]*Workflow, error)
}

// PluginRepository defines the interface for plugin data access
type PluginRepository interface {
	// Create inserts a new plugin
	Create(ctx context.Context, plugin *Plugin) error
	
	// Get retrieves a plugin by ID
	Get(ctx context.Context, id uuid.UUID) (*Plugin, error)
	
	// GetByNameVersion retrieves a plugin by name and version
	GetByNameVersion(ctx context.Context, name, version string, tenantID *uuid.UUID) (*Plugin, error)
	
	// List retrieves plugins with pagination
	List(ctx context.Context, opts QueryOptions) (*PagedResult[Plugin], error)
	
	// Update updates a plugin
	Update(ctx context.Context, plugin *Plugin) error
	
	// Delete soft deletes a plugin
	Delete(ctx context.Context, id uuid.UUID) error
	
	// GetActive retrieves all active plugins for a tenant
	GetActive(ctx context.Context, tenantID *uuid.UUID) ([]*Plugin, error)
	
	// UpdateStatus updates a plugin's status
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
}

// CacheRepository defines the interface for cache operations
type CacheRepository interface {
	// Get retrieves a value by key
	Get(ctx context.Context, key string) ([]byte, error)
	
	// Set stores a value with expiration
	Set(ctx context.Context, key string, value []byte, expiration time.Duration) error
	
	// Delete removes a value
	Delete(ctx context.Context, key string) error
	
	// Exists checks if a key exists
	Exists(ctx context.Context, key string) (bool, error)
	
	// GetMulti retrieves multiple values
	GetMulti(ctx context.Context, keys []string) (map[string][]byte, error)
	
	// SetMulti stores multiple values
	SetMulti(ctx context.Context, items map[string][]byte, expiration time.Duration) error
	
	// DeleteMulti removes multiple values
	DeleteMulti(ctx context.Context, keys []string) error
	
	// Increment increments a counter
	Increment(ctx context.Context, key string, delta int64) (int64, error)
	
	// TTL gets the time-to-live for a key
	TTL(ctx context.Context, key string) (time.Duration, error)
	
	// Scan scans keys matching a pattern
	Scan(ctx context.Context, pattern string, count int) ([]string, error)
}