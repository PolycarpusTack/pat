package mocks

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/stretchr/testify/mock"
)

// MockKeep is a mock implementation of the Keep interface
type MockKeep struct {
	mock.Mock
	emails    map[string]*interfaces.Email
	stats     *interfaces.EmailStats
	mu        sync.RWMutex
	started   bool
}

// NewMockKeep creates a new mock Keep service
func NewMockKeep() *MockKeep {
	return &MockKeep{
		emails: make(map[string]*interfaces.Email),
		stats: &interfaces.EmailStats{
			TotalEmails:       0,
			TotalSize:         0,
			EmailsToday:       0,
			EmailsThisWeek:    0,
			EmailsThisMonth:   0,
			AverageSize:       0,
			LastEmailAt:       nil,
			ProcessingStats:   make(map[string]interface{}),
		},
	}
}

func (m *MockKeep) ProcessEmail(ctx context.Context, email *interfaces.Email) error {
	args := m.Called(ctx, email)
	if args.Error(0) == nil {
		m.mu.Lock()
		m.emails[email.ID] = email
		m.stats.TotalEmails++
		m.stats.TotalSize += email.Size
		now := time.Now()
		m.stats.LastEmailAt = &now
		m.mu.Unlock()
	}
	return args.Error(0)
}

func (m *MockKeep) StoreEmail(ctx context.Context, email *interfaces.Email) error {
	args := m.Called(ctx, email)
	if args.Error(0) == nil {
		m.mu.Lock()
		m.emails[email.ID] = email
		m.mu.Unlock()
	}
	return args.Error(0)
}

func (m *MockKeep) RetrieveEmail(ctx context.Context, id string) (*interfaces.Email, error) {
	args := m.Called(ctx, id)
	m.mu.RLock()
	email, exists := m.emails[id]
	m.mu.RUnlock()
	if !exists && args.Error(1) == nil {
		return nil, fmt.Errorf("email not found")
	}
	return args.Get(0).(*interfaces.Email), args.Error(1)
}

func (m *MockKeep) RetrieveEmails(ctx context.Context, filter *interfaces.Filter) ([]*interfaces.Email, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*interfaces.Email), args.Error(1)
}

func (m *MockKeep) SearchEmails(ctx context.Context, query *interfaces.SearchQuery) (*interfaces.SearchResults, error) {
	args := m.Called(ctx, query)
	return args.Get(0).(*interfaces.SearchResults), args.Error(1)
}

func (m *MockKeep) DeleteEmail(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	if args.Error(0) == nil {
		m.mu.Lock()
		delete(m.emails, id)
		m.stats.TotalEmails--
		m.mu.Unlock()
	}
	return args.Error(0)
}

func (m *MockKeep) UpdateEmail(ctx context.Context, id string, updates map[string]interface{}) error {
	args := m.Called(ctx, id, updates)
	return args.Error(0)
}

func (m *MockKeep) TagEmail(ctx context.Context, id string, tags []string) error {
	args := m.Called(ctx, id, tags)
	return args.Error(0)
}

func (m *MockKeep) ReleaseEmail(ctx context.Context, id string, to string) error {
	args := m.Called(ctx, id, to)
	return args.Error(0)
}

func (m *MockKeep) GetEmailStats(ctx context.Context, filter *interfaces.Filter) (*interfaces.EmailStats, error) {
	args := m.Called(ctx, filter)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats, args.Error(1)
}

func (m *MockKeep) GetStorageStats(ctx context.Context) (*interfaces.StorageStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.StorageStats), args.Error(1)
}

func (m *MockKeep) Start(ctx context.Context) error {
	args := m.Called(ctx)
	m.started = true
	return args.Error(0)
}

func (m *MockKeep) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	m.started = false
	return args.Error(0)
}

func (m *MockKeep) Health(ctx context.Context) *interfaces.HealthStatus {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.HealthStatus)
}

// MockWatchtower is a mock implementation of the Watchtower interface
type MockWatchtower struct {
	mock.Mock
	metrics     map[string]float64
	logs        []string
	healthChecks map[string]interfaces.HealthCheckFunc
	mu          sync.RWMutex
	monitoring  bool
}

// NewMockWatchtower creates a new mock Watchtower service
func NewMockWatchtower() *MockWatchtower {
	return &MockWatchtower{
		metrics:     make(map[string]float64),
		logs:        make([]string, 0),
		healthChecks: make(map[string]interfaces.HealthCheckFunc),
	}
}

func (m *MockWatchtower) RecordMetric(name string, value float64, labels map[string]string) {
	m.Called(name, value, labels)
	m.mu.Lock()
	m.metrics[name] = value
	m.mu.Unlock()
}

func (m *MockWatchtower) IncrementCounter(name string, labels map[string]string) {
	m.Called(name, labels)
	m.mu.Lock()
	m.metrics[name] = m.metrics[name] + 1
	m.mu.Unlock()
}

func (m *MockWatchtower) RecordHistogram(name string, value float64, labels map[string]string) {
	m.Called(name, value, labels)
}

func (m *MockWatchtower) SetGauge(name string, value float64, labels map[string]string) {
	m.Called(name, value, labels)
	m.mu.Lock()
	m.metrics[name] = value
	m.mu.Unlock()
}

func (m *MockWatchtower) LogEvent(level interfaces.LogLevel, message string, fields map[string]interface{}) {
	m.Called(level, message, fields)
	m.mu.Lock()
	m.logs = append(m.logs, fmt.Sprintf("[%s] %s", level, message))
	m.mu.Unlock()
}

func (m *MockWatchtower) LogEmail(email *interfaces.Email, action string, metadata map[string]interface{}) {
	m.Called(email, action, metadata)
}

func (m *MockWatchtower) LogError(err error, context map[string]interface{}) {
	m.Called(err, context)
	m.mu.Lock()
	m.logs = append(m.logs, fmt.Sprintf("[ERROR] %s", err.Error()))
	m.mu.Unlock()
}

func (m *MockWatchtower) StartTrace(ctx context.Context, operation string) (context.Context, interfaces.TraceSpan) {
	args := m.Called(ctx, operation)
	return args.Get(0).(context.Context), args.Get(1).(interfaces.TraceSpan)
}

func (m *MockWatchtower) RecordSpan(span interfaces.TraceSpan, status string, attributes map[string]interface{}) {
	m.Called(span, status, attributes)
}

func (m *MockWatchtower) HealthCheck(ctx context.Context) *interfaces.HealthStatus {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.HealthStatus)
}

func (m *MockWatchtower) RegisterHealthCheck(name string, check interfaces.HealthCheckFunc) {
	m.Called(name, check)
	m.mu.Lock()
	m.healthChecks[name] = check
	m.mu.Unlock()
}

func (m *MockWatchtower) GetSystemStats(ctx context.Context) (*interfaces.SystemStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.SystemStats), args.Error(1)
}

func (m *MockWatchtower) TriggerAlert(level interfaces.AlertLevel, message string, details map[string]interface{}) {
	m.Called(level, message, details)
}

func (m *MockWatchtower) RegisterAlertHandler(handler interfaces.AlertHandler) {
	m.Called(handler)
}

func (m *MockWatchtower) StartMonitoring(ctx context.Context) error {
	args := m.Called(ctx)
	m.monitoring = true
	return args.Error(0)
}

func (m *MockWatchtower) StopMonitoring(ctx context.Context) error {
	args := m.Called(ctx)
	m.monitoring = false
	return args.Error(0)
}

// MockFoundation is a mock implementation of the Foundation interface
type MockFoundation struct {
	mock.Mock
	connected    bool
	transactions map[string]*MockTransaction
	cache        map[string]interface{}
	files        map[string][]byte
	mu           sync.RWMutex
}

// NewMockFoundation creates a new mock Foundation service
func NewMockFoundation() *MockFoundation {
	return &MockFoundation{
		transactions: make(map[string]*MockTransaction),
		cache:        make(map[string]interface{}),
		files:        make(map[string][]byte),
	}
}

func (m *MockFoundation) Connect(ctx context.Context, config *interfaces.DatabaseConfig) error {
	args := m.Called(ctx, config)
	if args.Error(0) == nil {
		m.connected = true
	}
	return args.Error(0)
}

func (m *MockFoundation) Disconnect(ctx context.Context) error {
	args := m.Called(ctx)
	if args.Error(0) == nil {
		m.connected = false
	}
	return args.Error(0)
}

func (m *MockFoundation) Migrate(ctx context.Context, version string) error {
	args := m.Called(ctx, version)
	return args.Error(0)
}

func (m *MockFoundation) Query(ctx context.Context, query string, args ...interface{}) (*interfaces.QueryResult, error) {
	mockArgs := m.Called(ctx, query, args)
	return mockArgs.Get(0).(*interfaces.QueryResult), mockArgs.Error(1)
}

func (m *MockFoundation) QueryOne(ctx context.Context, query string, args ...interface{}) (map[string]interface{}, error) {
	mockArgs := m.Called(ctx, query, args)
	return mockArgs.Get(0).(map[string]interface{}), mockArgs.Error(1)
}

func (m *MockFoundation) Exec(ctx context.Context, query string, args ...interface{}) error {
	mockArgs := m.Called(ctx, query, args)
	return mockArgs.Error(0)
}

func (m *MockFoundation) BeginTransaction(ctx context.Context) (interfaces.Transaction, error) {
	args := m.Called(ctx)
	if args.Error(1) == nil {
		tx := &MockTransaction{id: fmt.Sprintf("tx-%d", time.Now().UnixNano())}
		m.mu.Lock()
		m.transactions[tx.id] = tx
		m.mu.Unlock()
		return tx, nil
	}
	return args.Get(0).(interfaces.Transaction), args.Error(1)
}

func (m *MockFoundation) Transaction(ctx context.Context, fn func(tx interfaces.Transaction) error) error {
	args := m.Called(ctx, fn)
	return args.Error(0)
}

func (m *MockFoundation) CacheGet(ctx context.Context, key string) (interface{}, error) {
	args := m.Called(ctx, key)
	m.mu.RLock()
	value, exists := m.cache[key]
	m.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("cache key not found")
	}
	return value, args.Error(1)
}

func (m *MockFoundation) CacheSet(ctx context.Context, key string, value interface{}, ttl *time.Duration) error {
	args := m.Called(ctx, key, value, ttl)
	if args.Error(0) == nil {
		m.mu.Lock()
		m.cache[key] = value
		m.mu.Unlock()
	}
	return args.Error(0)
}

func (m *MockFoundation) CacheDelete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	if args.Error(0) == nil {
		m.mu.Lock()
		delete(m.cache, key)
		m.mu.Unlock()
	}
	return args.Error(0)
}

func (m *MockFoundation) CacheClear(ctx context.Context, pattern string) error {
	args := m.Called(ctx, pattern)
	return args.Error(0)
}

func (m *MockFoundation) StoreFile(ctx context.Context, path string, data []byte) error {
	args := m.Called(ctx, path, data)
	if args.Error(0) == nil {
		m.mu.Lock()
		m.files[path] = data
		m.mu.Unlock()
	}
	return args.Error(0)
}

func (m *MockFoundation) RetrieveFile(ctx context.Context, path string) ([]byte, error) {
	args := m.Called(ctx, path)
	m.mu.RLock()
	data, exists := m.files[path]
	m.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("file not found")
	}
	return data, args.Error(1)
}

func (m *MockFoundation) DeleteFile(ctx context.Context, path string) error {
	args := m.Called(ctx, path)
	if args.Error(0) == nil {
		m.mu.Lock()
		delete(m.files, path)
		m.mu.Unlock()
	}
	return args.Error(0)
}

func (m *MockFoundation) ListFiles(ctx context.Context, pattern string) ([]string, error) {
	args := m.Called(ctx, pattern)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockFoundation) CreateBackup(ctx context.Context, config *interfaces.BackupConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockFoundation) RestoreBackup(ctx context.Context, backupID string) error {
	args := m.Called(ctx, backupID)
	return args.Error(0)
}

func (m *MockFoundation) ListBackups(ctx context.Context) ([]*interfaces.BackupInfo, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*interfaces.BackupInfo), args.Error(1)
}

func (m *MockFoundation) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockFoundation) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockFoundation) Health(ctx context.Context) *interfaces.HealthStatus {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.HealthStatus)
}

// MockTransaction is a mock implementation of the Transaction interface
type MockTransaction struct {
	mock.Mock
	id        string
	committed bool
	rolledback bool
}

func (m *MockTransaction) Commit() error {
	args := m.Called()
	if args.Error(0) == nil {
		m.committed = true
	}
	return args.Error(0)
}

func (m *MockTransaction) Rollback() error {
	args := m.Called()
	if args.Error(0) == nil {
		m.rolledback = true
	}
	return args.Error(0)
}

func (m *MockTransaction) Query(query string, args ...interface{}) (*interfaces.QueryResult, error) {
	mockArgs := m.Called(query, args)
	return mockArgs.Get(0).(*interfaces.QueryResult), mockArgs.Error(1)
}

func (m *MockTransaction) Exec(query string, args ...interface{}) error {
	mockArgs := m.Called(query, args)
	return mockArgs.Error(0)
}

// MockEventBus is a mock implementation of the EventBus interface
type MockEventBus struct {
	mock.Mock
	subscribers map[string][]interfaces.EventHandler
	events      []*interfaces.Event
	mu          sync.RWMutex
	started     bool
}

// NewMockEventBus creates a new mock EventBus service
func NewMockEventBus() *MockEventBus {
	return &MockEventBus{
		subscribers: make(map[string][]interfaces.EventHandler),
		events:      make([]*interfaces.Event, 0),
	}
}

func (m *MockEventBus) Publish(ctx context.Context, event *interfaces.Event) error {
	args := m.Called(ctx, event)
	if args.Error(0) == nil {
		m.mu.Lock()
		m.events = append(m.events, event)
		m.mu.Unlock()
	}
	return args.Error(0)
}

func (m *MockEventBus) PublishAsync(ctx context.Context, event *interfaces.Event) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockEventBus) Subscribe(eventType string, handler interfaces.EventHandler) error {
	args := m.Called(eventType, handler)
	if args.Error(0) == nil {
		m.mu.Lock()
		m.subscribers[eventType] = append(m.subscribers[eventType], handler)
		m.mu.Unlock()
	}
	return args.Error(0)
}

func (m *MockEventBus) Unsubscribe(eventType string, handler interfaces.EventHandler) error {
	args := m.Called(eventType, handler)
	return args.Error(0)
}

func (m *MockEventBus) ListSubscriptions(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockEventBus) GetEventHistory(ctx context.Context, filter *interfaces.EventFilter) ([]*interfaces.Event, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]*interfaces.Event), args.Error(1)
}

func (m *MockEventBus) Start(ctx context.Context) error {
	args := m.Called(ctx)
	m.started = true
	return args.Error(0)
}

func (m *MockEventBus) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	m.started = false
	return args.Error(0)
}

func (m *MockEventBus) Health(ctx context.Context) *interfaces.HealthStatus {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.HealthStatus)
}

// Helper methods for test assertions

// GetRecordedMetric returns a recorded metric value
func (m *MockWatchtower) GetRecordedMetric(name string) (float64, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, exists := m.metrics[name]
	return value, exists
}

// GetLogCount returns the number of logged messages
func (m *MockWatchtower) GetLogCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.logs)
}

// GetEmailCount returns the number of stored emails
func (m *MockKeep) GetEmailCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.emails)
}

// GetCacheSize returns the number of cached items
func (m *MockFoundation) GetCacheSize() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}

// GetEventCount returns the number of published events
func (m *MockEventBus) GetEventCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.events)
}