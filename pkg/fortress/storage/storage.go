package storage

import (
	"context"
	"time"

	"github.com/pat-fortress/pkg/fortress/legacy"
)

// StorageBackend defines the interface for message storage backends
// Keep it simple - just wrap the existing legacy interface
type StorageBackend interface {
	legacy.FortressMessageStore
	Close() error
}

// SearchQuery defines parameters for message searching
type SearchQuery struct {
	// Search criteria
	Kind  string // "from", "to", "subject", "body", "containing"
	Query string // search term

	// Filters
	From      string
	To        string
	Subject   string
	TenantID  string
	DateFrom  *time.Time
	DateTo    *time.Time

	// Pagination
	Offset int
	Limit  int

	// Sorting
	SortBy    string // "created", "size", "from", "to", "subject"
	SortOrder string // "asc", "desc"
}

// StorageConfig defines common configuration for storage backends
type StorageConfig struct {
	Type         string        // "memory", "postgresql", "mongodb"
	DSN          string        // Database connection string
	MaxOpenConns int           // Maximum open connections
	MaxIdleConns int           // Maximum idle connections
	MaxLifetime  time.Duration // Connection lifetime

	// Storage-specific options
	TablePrefix    string // For SQL backends
	Database       string // Database name
	RetentionDays  int    // Message retention period
	EnableFullText bool   // Enable full-text search
}

// NewStorageBackend creates a new storage backend based on configuration
func NewStorageBackend(config *StorageConfig) (StorageBackend, error) {
	// For email testing, just use the existing memory store with a close method
	return &SimpleStorageWrapper{
		store: legacy.NewInMemoryFortressStore(),
	}, nil
}

// SimpleStorageWrapper wraps legacy store with close method
type SimpleStorageWrapper struct {
	store legacy.FortressMessageStore
}

func (w *SimpleStorageWrapper) Store(m *legacy.Message) (legacy.MessageID, error) {
	return w.store.Store(m)
}

func (w *SimpleStorageWrapper) Count() int {
	return w.store.Count()
}

func (w *SimpleStorageWrapper) Search(kind, query string, start, limit int) (*legacy.Messages, error) {
	return w.store.Search(kind, query, start, limit)
}

func (w *SimpleStorageWrapper) List(start, limit int) (*legacy.Messages, error) {
	return w.store.List(start, limit)
}

func (w *SimpleStorageWrapper) DeleteOne(id legacy.MessageID) error {
	return w.store.DeleteOne(id)
}

func (w *SimpleStorageWrapper) DeleteAll() error {
	return w.store.DeleteAll()
}

func (w *SimpleStorageWrapper) Load(id legacy.MessageID) (*legacy.Message, error) {
	return w.store.Load(id)
}

func (w *SimpleStorageWrapper) Close() error {
	// Memory store doesn't need cleanup
	return nil
}