package interfaces

import (
	"context"
	"net"
)

// Keep - The fortress email processing engine
// Responsible for core email processing, storage, and retrieval operations
type Keep interface {
	// Email processing methods
	ProcessEmail(ctx context.Context, email *Email) error
	StoreEmail(ctx context.Context, email *Email) error
	RetrieveEmail(ctx context.Context, id string) (*Email, error)
	RetrieveEmails(ctx context.Context, filter *Filter) ([]*Email, error)
	SearchEmails(ctx context.Context, query *SearchQuery) (*SearchResults, error)
	
	// Email management operations
	DeleteEmail(ctx context.Context, id string) error
	UpdateEmail(ctx context.Context, id string, updates map[string]interface{}) error
	TagEmail(ctx context.Context, id string, tags []string) error
	ReleaseEmail(ctx context.Context, id string, to string) error
	
	// Statistics and analytics
	GetEmailStats(ctx context.Context, filter *Filter) (*EmailStats, error)
	GetStorageStats(ctx context.Context) (*StorageStats, error)
	
	// Lifecycle methods
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) *HealthStatus
}

// Watchtower - The fortress monitoring and observability system
// Responsible for metrics collection, logging, tracing, and health monitoring
type Watchtower interface {
	// Metrics operations
	RecordMetric(name string, value float64, labels map[string]string)
	IncrementCounter(name string, labels map[string]string)
	RecordHistogram(name string, value float64, labels map[string]string)
	SetGauge(name string, value float64, labels map[string]string)
	
	// Logging operations
	LogEvent(level LogLevel, message string, fields map[string]interface{})
	LogEmail(email *Email, action string, metadata map[string]interface{})
	LogError(err error, context map[string]interface{})
	
	// Tracing operations
	StartTrace(ctx context.Context, operation string) (context.Context, TraceSpan)
	RecordSpan(span TraceSpan, status string, attributes map[string]interface{})
	
	// Health and status monitoring
	HealthCheck(ctx context.Context) *HealthStatus
	RegisterHealthCheck(name string, check HealthCheckFunc)
	GetSystemStats(ctx context.Context) (*SystemStats, error)
	
	// Alert management
	TriggerAlert(level AlertLevel, message string, details map[string]interface{})
	RegisterAlertHandler(handler AlertHandler)
	
	// Lifecycle methods
	StartMonitoring(ctx context.Context) error
	StopMonitoring(ctx context.Context) error
}

// Guard - The fortress authentication and authorization system
// Responsible for user authentication, authorization, and session management
type Guard interface {
	// Authentication methods
	Authenticate(ctx context.Context, credentials *Credentials) (*AuthResult, error)
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
	RevokeToken(ctx context.Context, token string) error
	
	// Authorization methods
	Authorize(ctx context.Context, userID string, resource string, action string) error
	CheckPermission(ctx context.Context, userID string, permission string) bool
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
	
	// Session management
	CreateSession(ctx context.Context, userID string, metadata map[string]interface{}) (*Session, error)
	ValidateSession(ctx context.Context, sessionID string) (*Session, error)
	DestroySession(ctx context.Context, sessionID string) error
	
	// User management
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, userID string, updates *UserUpdates) error
	GetUser(ctx context.Context, userID string) (*User, error)
	
	// Lifecycle methods
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) *HealthStatus
}

// Rampart - The fortress security and rate limiting system
// Responsible for security policies, rate limiting, and threat protection
type Rampart interface {
	// Rate limiting
	CheckRateLimit(ctx context.Context, key string, limit *RateLimit) (*RateLimitResult, error)
	ResetRateLimit(ctx context.Context, key string) error
	GetRateLimitStatus(ctx context.Context, key string) (*RateLimitStatus, error)
	
	// Security validation
	ValidateRequest(ctx context.Context, req *Request) (*SecurityResult, error)
	ScanEmail(ctx context.Context, email *Email) (*ScanResult, error)
	CheckBlacklist(ctx context.Context, value string, listType BlacklistType) (bool, error)
	
	// Threat detection
	DetectAnomalies(ctx context.Context, data map[string]interface{}) (*AnomalyResult, error)
	ReportThreat(ctx context.Context, threat *ThreatReport) error
	
	// Security policies
	ApplySecurityPolicy(ctx context.Context, policy *SecurityPolicy, target interface{}) error
	ValidateCompliance(ctx context.Context, req *ComplianceRequest) (*ComplianceResult, error)
	
	// Lifecycle methods
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) *HealthStatus
}

// Armory - The fortress plugin system and tools
// Responsible for plugin management, execution, and tool orchestration
type Armory interface {
	// Plugin lifecycle management
	LoadPlugin(ctx context.Context, config *PluginConfig) error
	UnloadPlugin(ctx context.Context, pluginID string) error
	ReloadPlugin(ctx context.Context, pluginID string) error
	
	// Plugin execution
	ExecutePlugin(ctx context.Context, pluginID string, email *Email) (*PluginResult, error)
	ExecutePluginChain(ctx context.Context, chainID string, email *Email) ([]*PluginResult, error)
	
	// Plugin management
	ListPlugins(ctx context.Context) ([]*PluginInfo, error)
	GetPlugin(ctx context.Context, pluginID string) (*PluginInfo, error)
	EnablePlugin(ctx context.Context, pluginID string) error
	DisablePlugin(ctx context.Context, pluginID string) error
	
	// Plugin configuration
	UpdatePluginConfig(ctx context.Context, pluginID string, config map[string]interface{}) error
	GetPluginConfig(ctx context.Context, pluginID string) (map[string]interface{}, error)
	
	// Tool management
	RegisterTool(ctx context.Context, tool *Tool) error
	ExecuteTool(ctx context.Context, toolID string, params map[string]interface{}) (*ToolResult, error)
	ListTools(ctx context.Context) ([]*ToolInfo, error)
	
	// Lifecycle methods
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) *HealthStatus
}

// Gates - The fortress API endpoints and interfaces
// Responsible for HTTP/SMTP servers, API routing, and external communication
type Gates interface {
	// HTTP server management
	RegisterRoute(method, path string, handler HandlerFunc)
	RegisterMiddleware(middleware MiddlewareFunc)
	StartHTTPServer(ctx context.Context, config *HTTPServerConfig) error
	StopHTTPServer(ctx context.Context) error
	
	// SMTP server management
	StartSMTPServer(ctx context.Context, config *SMTPServerConfig) error
	StopSMTPServer(ctx context.Context) error
	HandleSMTPConnection(ctx context.Context, conn net.Conn) error
	
	// GraphQL operations
	RegisterGraphQLSchema(schema string) error
	HandleGraphQL(ctx context.Context, query string, variables map[string]interface{}) (*GraphQLResult, error)
	
	// WebSocket operations
	RegisterWebSocketHandler(path string, handler WebSocketHandler)
	BroadcastMessage(ctx context.Context, message *WebSocketMessage) error
	
	// API versioning and documentation
	RegisterAPIVersion(version string, routes map[string]HandlerFunc)
	GenerateOpenAPISpec() ([]byte, error)
	
	// Lifecycle methods
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) *HealthStatus
}

// Foundation - The fortress database and storage systems
// Responsible for data persistence, caching, and storage management
type Foundation interface {
	// Database operations
	Connect(ctx context.Context, config *DatabaseConfig) error
	Disconnect(ctx context.Context) error
	Migrate(ctx context.Context, version string) error
	
	// Query operations
	Query(ctx context.Context, query string, args ...interface{}) (*QueryResult, error)
	QueryOne(ctx context.Context, query string, args ...interface{}) (map[string]interface{}, error)
	Exec(ctx context.Context, query string, args ...interface{}) error
	
	// Transaction management
	BeginTransaction(ctx context.Context) (Transaction, error)
	Transaction(ctx context.Context, fn func(tx Transaction) error) error
	
	// Cache operations
	CacheGet(ctx context.Context, key string) (interface{}, error)
	CacheSet(ctx context.Context, key string, value interface{}, ttl *time.Duration) error
	CacheDelete(ctx context.Context, key string) error
	CacheClear(ctx context.Context, pattern string) error
	
	// Storage operations
	StoreFile(ctx context.Context, path string, data []byte) error
	RetrieveFile(ctx context.Context, path string) ([]byte, error)
	DeleteFile(ctx context.Context, path string) error
	ListFiles(ctx context.Context, pattern string) ([]string, error)
	
	// Backup and recovery
	CreateBackup(ctx context.Context, config *BackupConfig) error
	RestoreBackup(ctx context.Context, backupID string) error
	ListBackups(ctx context.Context) ([]*BackupInfo, error)
	
	// Lifecycle methods
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) *HealthStatus
}

// EventBus - Internal event communication system
type EventBus interface {
	// Event publishing
	Publish(ctx context.Context, event *Event) error
	PublishAsync(ctx context.Context, event *Event) error
	
	// Event subscription
	Subscribe(eventType string, handler EventHandler) error
	Unsubscribe(eventType string, handler EventHandler) error
	
	// Event management
	ListSubscriptions(ctx context.Context) ([]string, error)
	GetEventHistory(ctx context.Context, filter *EventFilter) ([]*Event, error)
	
	// Lifecycle methods
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) *HealthStatus
}