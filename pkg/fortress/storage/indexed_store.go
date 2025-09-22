package storage

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pat-fortress/pkg/fortress/legacy"
)

// IndexedFortressStore provides an enhanced in-memory store with search indexing
type IndexedFortressStore struct {
	// Core storage
	messages map[legacy.MessageID]*legacy.Message
	ordered  []legacy.MessageID
	mu       sync.RWMutex

	// Search indexes for performance
	fromIndex    map[string][]legacy.MessageID // Index by sender email
	toIndex      map[string][]legacy.MessageID // Index by recipient email
	subjectIndex map[string][]legacy.MessageID // Index by subject keywords
	bodyIndex    map[string][]legacy.MessageID // Index by body keywords
	dateIndex    map[string][]legacy.MessageID // Index by date (YYYY-MM-DD)
	tenantIndex  map[string][]legacy.MessageID // Index by tenant ID

	// Full-text search index (simple keyword-based)
	keywordIndex map[string][]legacy.MessageID

	// Configuration
	config           *StorageConfig
	maxSearchResults int
	indexingEnabled  bool
}

// NewIndexedFortressStore creates a new indexed fortress store
func NewIndexedFortressStore(config *StorageConfig) *IndexedFortressStore {
	if config == nil {
		config = &StorageConfig{
			EnableFullText: true,
		}
	}

	return &IndexedFortressStore{
		messages:         make(map[legacy.MessageID]*legacy.Message),
		ordered:          make([]legacy.MessageID, 0),
		fromIndex:        make(map[string][]legacy.MessageID),
		toIndex:          make(map[string][]legacy.MessageID),
		subjectIndex:     make(map[string][]legacy.MessageID),
		bodyIndex:        make(map[string][]legacy.MessageID),
		dateIndex:        make(map[string][]legacy.MessageID),
		tenantIndex:      make(map[string][]legacy.MessageID),
		keywordIndex:     make(map[string][]legacy.MessageID),
		config:           config,
		maxSearchResults: 1000,
		indexingEnabled:  config.EnableFullText,
	}
}

// Store saves a message and updates search indexes
func (s *IndexedFortressStore) Store(m *legacy.Message) (legacy.MessageID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate ID if not set
	if m.ID == "" {
		id, err := legacy.NewMessageID("fortress.local")
		if err != nil {
			return "", err
		}
		m.ID = id
	}

	// Store the message
	s.messages[m.ID] = m
	s.ordered = append(s.ordered, m.ID)

	// Update indexes if enabled
	if s.indexingEnabled {
		s.updateIndexes(m)
	}

	return m.ID, nil
}

// updateIndexes updates all search indexes for a message
func (s *IndexedFortressStore) updateIndexes(m *legacy.Message) {
	// Index by sender
	if m.From != nil && m.From.Address != "" {
		email := strings.ToLower(m.From.Address)
		s.fromIndex[email] = append(s.fromIndex[email], m.ID)
	}

	// Index by recipients
	for _, to := range m.To {
		if to.Address != "" {
			email := strings.ToLower(to.Address)
			s.toIndex[email] = append(s.toIndex[email], m.ID)
		}
	}

	// Index by tenant ID
	if m.TenantID != "" {
		s.tenantIndex[m.TenantID] = append(s.tenantIndex[m.TenantID], m.ID)
	}

	// Index by date
	dateKey := m.Created.Format("2006-01-02")
	s.dateIndex[dateKey] = append(s.dateIndex[dateKey], m.ID)

	// Index subject and body content
	if m.Content != nil {
		// Index subject keywords
		if subject := getHeader(m, "Subject"); subject != "" {
			keywords := extractKeywords(subject)
			for _, keyword := range keywords {
				s.subjectIndex[keyword] = append(s.subjectIndex[keyword], m.ID)
				s.keywordIndex[keyword] = append(s.keywordIndex[keyword], m.ID)
			}
		}

		// Index body keywords
		if m.Content.Body != "" {
			keywords := extractKeywords(m.Content.Body)
			for _, keyword := range keywords {
				s.bodyIndex[keyword] = append(s.bodyIndex[keyword], m.ID)
				s.keywordIndex[keyword] = append(s.keywordIndex[keyword], m.ID)
			}
		}
	}
}

// Search performs optimized search using indexes
func (s *IndexedFortressStore) Search(kind, query string, start, limit int) (*legacy.Messages, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matchingIDs []legacy.MessageID

	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return s.List(start, limit)
	}

	// Use appropriate index based on search kind
	switch kind {
	case "from":
		matchingIDs = s.searchInIndex(s.fromIndex, query)
	case "to":
		matchingIDs = s.searchInIndex(s.toIndex, query)
	case "subject":
		matchingIDs = s.searchInIndex(s.subjectIndex, query)
	case "body":
		matchingIDs = s.searchInIndex(s.bodyIndex, query)
	case "containing", "":
		// Full-text search across all keywords
		matchingIDs = s.searchInIndex(s.keywordIndex, query)
	default:
		// Fallback to unindexed search
		return s.fallbackSearch(kind, query, start, limit)
	}

	// Convert IDs to messages
	return s.convertIDsToMessages(matchingIDs, start, limit)
}

// searchInIndex searches for a query in a specific index
func (s *IndexedFortressStore) searchInIndex(index map[string][]legacy.MessageID, query string) []legacy.MessageID {
	var allMatches []legacy.MessageID
	matchSet := make(map[legacy.MessageID]bool)

	// Exact match
	if ids, exists := index[query]; exists {
		for _, id := range ids {
			if !matchSet[id] {
				allMatches = append(allMatches, id)
				matchSet[id] = true
			}
		}
	}

	// Partial matches (contains)
	for keyword, ids := range index {
		if strings.Contains(keyword, query) && keyword != query {
			for _, id := range ids {
				if !matchSet[id] {
					allMatches = append(allMatches, id)
					matchSet[id] = true
				}
			}
		}
	}

	// Sort by most recent first
	sort.Slice(allMatches, func(i, j int) bool {
		msgI := s.messages[allMatches[i]]
		msgJ := s.messages[allMatches[j]]
		return msgI.Created.After(msgJ.Created)
	})

	return allMatches
}

// convertIDsToMessages converts message IDs to a Messages slice
func (s *IndexedFortressStore) convertIDsToMessages(ids []legacy.MessageID, start, limit int) (*legacy.Messages, error) {
	total := len(ids)

	if start >= total {
		return &legacy.Messages{}, nil
	}

	end := start + limit
	if end > total {
		end = total
	}

	messages := make(legacy.Messages, 0, end-start)
	for i := start; i < end; i++ {
		if msg, exists := s.messages[ids[i]]; exists {
			messages = append(messages, msg)
		}
	}

	return &messages, nil
}

// fallbackSearch performs unindexed search for unsupported kinds
func (s *IndexedFortressStore) fallbackSearch(kind, query string, start, limit int) (*legacy.Messages, error) {
	messages := make(legacy.Messages, 0)
	count := 0

	// Iterate through messages in reverse chronological order
	for i := len(s.ordered) - 1; i >= 0; i-- {
		id := s.ordered[i]
		msg := s.messages[id]

		if s.messageMatches(msg, kind, query) {
			if count >= start && len(messages) < limit {
				messages = append(messages, msg)
			}
			count++
		}
	}

	return &messages, nil
}

// messageMatches checks if a message matches the search criteria
func (s *IndexedFortressStore) messageMatches(msg *legacy.Message, kind, query string) bool {
	query = strings.ToLower(query)

	switch kind {
	case "from":
		return msg.From != nil && strings.Contains(strings.ToLower(msg.From.Address), query)
	case "to":
		for _, to := range msg.To {
			if strings.Contains(strings.ToLower(to.Address), query) {
				return true
			}
		}
		return false
	case "subject":
		subject := getHeader(msg, "Subject")
		return strings.Contains(strings.ToLower(subject), query)
	case "body":
		return msg.Content != nil && strings.Contains(strings.ToLower(msg.Content.Body), query)
	default:
		// Search in all fields
		if msg.From != nil && strings.Contains(strings.ToLower(msg.From.Address), query) {
			return true
		}
		for _, to := range msg.To {
			if strings.Contains(strings.ToLower(to.Address), query) {
				return true
			}
		}
		if msg.Content != nil {
			subject := getHeader(msg, "Subject")
			if strings.Contains(strings.ToLower(subject), query) {
				return true
			}
			if strings.Contains(strings.ToLower(msg.Content.Body), query) {
				return true
			}
		}
		return false
	}
}

// List returns messages in reverse chronological order
func (s *IndexedFortressStore) List(start, limit int) (*legacy.Messages, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.ordered)
	if start >= total {
		return &legacy.Messages{}, nil
	}

	end := start + limit
	if end > total {
		end = total
	}

	messages := make(legacy.Messages, 0, end-start)

	// Return in reverse order (most recent first)
	for i := total - 1 - start; i >= total-end; i-- {
		id := s.ordered[i]
		if msg, exists := s.messages[id]; exists {
			messages = append(messages, msg)
		}
	}

	return &messages, nil
}

// Count returns the total number of messages
func (s *IndexedFortressStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.messages)
}

// Load retrieves a specific message by ID
func (s *IndexedFortressStore) Load(id legacy.MessageID) (*legacy.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if msg, exists := s.messages[id]; exists {
		return msg, nil
	}
	return nil, legacy.ErrMessageNotFound
}

// DeleteOne removes a message and updates indexes
func (s *IndexedFortressStore) DeleteOne(id legacy.MessageID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	msg, exists := s.messages[id]
	if !exists {
		return legacy.ErrMessageNotFound
	}

	// Remove from indexes
	if s.indexingEnabled {
		s.removeFromIndexes(msg)
	}

	// Remove from storage
	delete(s.messages, id)

	// Remove from ordered list
	for i, orderedID := range s.ordered {
		if orderedID == id {
			s.ordered = append(s.ordered[:i], s.ordered[i+1:]...)
			break
		}
	}

	return nil
}

// removeFromIndexes removes a message from all search indexes
func (s *IndexedFortressStore) removeFromIndexes(msg *legacy.Message) {
	// Helper function to remove ID from slice
	removeID := func(slice []legacy.MessageID, id legacy.MessageID) []legacy.MessageID {
		for i, msgID := range slice {
			if msgID == id {
				return append(slice[:i], slice[i+1:]...)
			}
		}
		return slice
	}

	// Remove from sender index
	if msg.From != nil {
		email := strings.ToLower(msg.From.Address)
		if ids, exists := s.fromIndex[email]; exists {
			s.fromIndex[email] = removeID(ids, msg.ID)
			if len(s.fromIndex[email]) == 0 {
				delete(s.fromIndex, email)
			}
		}
	}

	// Remove from recipient indexes
	for _, to := range msg.To {
		email := strings.ToLower(to.Address)
		if ids, exists := s.toIndex[email]; exists {
			s.toIndex[email] = removeID(ids, msg.ID)
			if len(s.toIndex[email]) == 0 {
				delete(s.toIndex, email)
			}
		}
	}

	// Remove from other indexes (subject, body, keywords, date, tenant)
	if msg.Content != nil {
		subject := getHeader(msg, "Subject")
		keywords := extractKeywords(subject + " " + msg.Content.Body)
		for _, keyword := range keywords {
			// Remove from subject index
			if ids, exists := s.subjectIndex[keyword]; exists {
				s.subjectIndex[keyword] = removeID(ids, msg.ID)
				if len(s.subjectIndex[keyword]) == 0 {
					delete(s.subjectIndex, keyword)
				}
			}

			// Remove from body index
			if ids, exists := s.bodyIndex[keyword]; exists {
				s.bodyIndex[keyword] = removeID(ids, msg.ID)
				if len(s.bodyIndex[keyword]) == 0 {
					delete(s.bodyIndex, keyword)
				}
			}

			// Remove from keyword index
			if ids, exists := s.keywordIndex[keyword]; exists {
				s.keywordIndex[keyword] = removeID(ids, msg.ID)
				if len(s.keywordIndex[keyword]) == 0 {
					delete(s.keywordIndex, keyword)
				}
			}
		}
	}

	// Remove from date index
	dateKey := msg.Created.Format("2006-01-02")
	if ids, exists := s.dateIndex[dateKey]; exists {
		s.dateIndex[dateKey] = removeID(ids, msg.ID)
		if len(s.dateIndex[dateKey]) == 0 {
			delete(s.dateIndex, dateKey)
		}
	}

	// Remove from tenant index
	if msg.TenantID != "" {
		if ids, exists := s.tenantIndex[msg.TenantID]; exists {
			s.tenantIndex[msg.TenantID] = removeID(ids, msg.ID)
			if len(s.tenantIndex[msg.TenantID]) == 0 {
				delete(s.tenantIndex, msg.TenantID)
			}
		}
	}
}

// DeleteAll removes all messages and clears indexes
func (s *IndexedFortressStore) DeleteAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear storage
	s.messages = make(map[legacy.MessageID]*legacy.Message)
	s.ordered = make([]legacy.MessageID, 0)

	// Clear indexes
	s.fromIndex = make(map[string][]legacy.MessageID)
	s.toIndex = make(map[string][]legacy.MessageID)
	s.subjectIndex = make(map[string][]legacy.MessageID)
	s.bodyIndex = make(map[string][]legacy.MessageID)
	s.dateIndex = make(map[string][]legacy.MessageID)
	s.tenantIndex = make(map[string][]legacy.MessageID)
	s.keywordIndex = make(map[string][]legacy.MessageID)

	return nil
}

// Close implements the storage backend interface
func (s *IndexedFortressStore) Close() error {
	// Memory store doesn't need cleanup
	return nil
}

// GetIndexStats returns statistics about search indexes
func (s *IndexedFortressStore) GetIndexStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"total_messages":     len(s.messages),
		"from_index_size":    len(s.fromIndex),
		"to_index_size":      len(s.toIndex),
		"subject_index_size": len(s.subjectIndex),
		"body_index_size":    len(s.bodyIndex),
		"keyword_index_size": len(s.keywordIndex),
		"date_index_size":    len(s.dateIndex),
		"tenant_index_size":  len(s.tenantIndex),
		"indexing_enabled":   s.indexingEnabled,
	}
}

// Helper functions

// extractKeywords extracts searchable keywords from text
func extractKeywords(text string) []string {
	if text == "" {
		return nil
	}

	// Simple tokenization (split on common delimiters)
	text = strings.ToLower(text)
	words := strings.FieldsFunc(text, func(c rune) bool {
		return !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '@' || c == '.' || c == '-')
	})

	// Filter out short words and common stop words
	keywords := make([]string, 0, len(words))
	stopWords := map[string]bool{
		"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
		"be": true, "by": true, "for": true, "from": true, "has": true, "he": true,
		"in": true, "is": true, "it": true, "its": true, "of": true, "on": true,
		"that": true, "the": true, "to": true, "was": true, "will": true, "with": true,
	}

	for _, word := range words {
		if len(word) >= 3 && !stopWords[word] {
			keywords = append(keywords, word)
		}
	}

	return keywords
}

// getHeader extracts a header value from a message
func getHeader(msg *legacy.Message, key string) string {
	if msg.Content == nil || msg.Content.Headers == nil {
		return ""
	}
	if headers, ok := msg.Content.Headers[key]; ok && len(headers) > 0 {
		return headers[0]
	}
	return ""
}