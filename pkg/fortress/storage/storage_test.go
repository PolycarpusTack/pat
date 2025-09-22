package storage

import (
    "net/mail"
    "testing"
    "time"

    "github.com/pat-fortress/pkg/fortress/legacy"
)

func TestNewStorageBackend(t *testing.T) {
	config := &StorageConfig{
		Type:         "memory",
		DSN:          "",
		MaxOpenConns: 25,
		MaxIdleConns: 5,
		MaxLifetime:  5 * time.Minute,
		TablePrefix:  "fortress",
		Database:     "fortress",
		RetentionDays: 7,
		EnableFullText: true,
	}

	backend, err := NewStorageBackend(config)
	if err != nil {
		t.Fatalf("Expected no error creating storage backend, got: %v", err)
	}

	if backend == nil {
		t.Fatal("Expected storage backend to be created, got nil")
	}

	// Test that it implements the interface
	var _ StorageBackend = backend
}

func TestSimpleStorageWrapper(t *testing.T) {
	config := &StorageConfig{
		Type:         "memory",
		RetentionDays: 7,
	}

	backend, err := NewStorageBackend(config)
	if err != nil {
		t.Fatalf("Failed to create storage backend: %v", err)
	}

	// Test initial state
	count := backend.Count()
	if count != 0 {
		t.Errorf("Expected initial count to be 0, got %d", count)
	}

	// Create a test message
    testMessage := &legacy.Message{
        ID:   "test-id-1",
        From: &mail.Address{Address: "sender@test.com"},
        To:   []*mail.Address{{Address: "recipient@test.com"}},
        Content: &legacy.Content{
            Headers: map[string][]string{
                "Subject": {"Test Subject"},
                "From":    {"sender@test.com"},
                "To":      {"recipient@test.com"},
            },
            Body: "Test message body",
            Size: 100,
        },
        Created: time.Now(),
        Raw: &legacy.SMTPMessage{
            From: "sender@test.com",
            To:   []string{"recipient@test.com"},
            Data: "Test raw data",
        },
    }

	// Test Store
	id, err := backend.Store(testMessage)
	if err != nil {
		t.Fatalf("Failed to store message: %v", err)
	}

	if string(id) != "test-id-1" {
		t.Errorf("Expected stored ID to be test-id-1, got %s", string(id))
	}

	// Test Count after storing
	count = backend.Count()
	if count != 1 {
		t.Errorf("Expected count to be 1 after storing, got %d", count)
	}

	// Test Load
	loadedMessage, err := backend.Load(id)
	if err != nil {
		t.Fatalf("Failed to load message: %v", err)
	}

	if loadedMessage.ID != testMessage.ID {
		t.Errorf("Expected loaded message ID to be %s, got %s", testMessage.ID, loadedMessage.ID)
	}

	if loadedMessage.Content.Body != testMessage.Content.Body {
		t.Errorf("Expected loaded message body to be %s, got %s", testMessage.Content.Body, loadedMessage.Content.Body)
	}

	// Test List
	messages, err := backend.List(0, 10)
	if err != nil {
		t.Fatalf("Failed to list messages: %v", err)
	}

	if len(*messages) != 1 {
		t.Errorf("Expected 1 message in list, got %d", len(*messages))
	}

	// Test Search
	searchResults, err := backend.Search("from", "sender@test.com", 0, 10)
	if err != nil {
		t.Fatalf("Failed to search messages: %v", err)
	}

	if len(*searchResults) != 1 {
		t.Errorf("Expected 1 message in search results, got %d", len(*searchResults))
	}

	// Test DeleteOne
	err = backend.DeleteOne(id)
	if err != nil {
		t.Fatalf("Failed to delete message: %v", err)
	}

	count = backend.Count()
	if count != 0 {
		t.Errorf("Expected count to be 0 after deletion, got %d", count)
	}

	// Test DeleteAll
	// Store multiple messages
    for i := 0; i < 3; i++ {
        msg := &legacy.Message{
            ID:      legacy.MessageID("test-id-" + string(rune('2'+i))),
            From:    &mail.Address{Address: "sender@test.com"},
            Content: &legacy.Content{Body: "Test body", Size: 50},
            Created: time.Now(),
        }
        _, err := backend.Store(msg)
        if err != nil {
            t.Fatalf("Failed to store test message %d: %v", i, err)
        }
    }

	count = backend.Count()
	if count != 3 {
		t.Errorf("Expected count to be 3 after storing 3 messages, got %d", count)
	}

	err = backend.DeleteAll()
	if err != nil {
		t.Fatalf("Failed to delete all messages: %v", err)
	}

	count = backend.Count()
	if count != 0 {
		t.Errorf("Expected count to be 0 after delete all, got %d", count)
	}

	// Test Close
	err = backend.Close()
	if err != nil {
		t.Fatalf("Failed to close storage backend: %v", err)
	}
}

func TestSearchQuery(t *testing.T) {
	query := &SearchQuery{
		Kind:      "from",
		Query:     "test@example.com",
		From:      "sender@test.com",
		To:        "recipient@test.com",
		Subject:   "Test Subject",
		TenantID:  "tenant-1",
		Offset:    0,
		Limit:     50,
		SortBy:    "created",
		SortOrder: "desc",
	}

	if query.Kind != "from" {
		t.Errorf("Expected Kind to be 'from', got %s", query.Kind)
	}

	if query.Query != "test@example.com" {
		t.Errorf("Expected Query to be 'test@example.com', got %s", query.Query)
	}

	if query.Limit != 50 {
		t.Errorf("Expected Limit to be 50, got %d", query.Limit)
	}

	if query.SortBy != "created" {
		t.Errorf("Expected SortBy to be 'created', got %s", query.SortBy)
	}
}

func TestStorageConfig(t *testing.T) {
	config := &StorageConfig{
		Type:         "memory",
		DSN:          "postgres://user:pass@localhost/db",
		MaxOpenConns: 25,
		MaxIdleConns: 5,
		MaxLifetime:  5 * time.Minute,
		TablePrefix:  "fortress",
		Database:     "fortress_test",
		RetentionDays: 14,
		EnableFullText: true,
	}

	if config.Type != "memory" {
		t.Errorf("Expected Type to be 'memory', got %s", config.Type)
	}

	if config.MaxOpenConns != 25 {
		t.Errorf("Expected MaxOpenConns to be 25, got %d", config.MaxOpenConns)
	}

	if config.RetentionDays != 14 {
		t.Errorf("Expected RetentionDays to be 14, got %d", config.RetentionDays)
	}

	if !config.EnableFullText {
		t.Error("Expected EnableFullText to be true")
	}
}
