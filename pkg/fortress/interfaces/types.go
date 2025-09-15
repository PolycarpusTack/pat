package interfaces

import (
	"context"
	"time"
)

// Additional types for fortress services

// TraceSpan represents a tracing span
type TraceSpan interface {
	End()
	SetTag(key string, value interface{})
	SetError(err error)
	GetTraceID() string
	GetSpanID() string
}

// HealthCheckFunc represents a health check function
type HealthCheckFunc func(ctx context.Context) *HealthStatus

// AlertLevel represents alert severity levels
type AlertLevel string

const (
	AlertLevelInfo     AlertLevel = "info"
	AlertLevelWarning  AlertLevel = "warning"
	AlertLevelCritical AlertLevel = "critical"
	AlertLevelFatal    AlertLevel = "fatal"
)

// AlertHandler represents alert handler function
type AlertHandler func(level AlertLevel, message string, details map[string]interface{})

// SystemStats represents system-wide statistics
type SystemStats struct {
	CPU              float64           `json:"cpu"`
	Memory           *MemoryStats      `json:"memory"`
	Disk             *DiskStats        `json:"disk"`
	Network          *NetworkStats     `json:"network"`
	Goroutines       int               `json:"goroutines"`
	EmailsProcessed  int64             `json:"emailsProcessed"`
	ActiveSessions   int               `json:"activeSessions"`
	Uptime           time.Duration     `json:"uptime"`
	Version          string            `json:"version"`
	LastHealthCheck  time.Time         `json:"lastHealthCheck"`
	Services         map[string]string `json:"services"`
}

// MemoryStats represents memory usage statistics
type MemoryStats struct {
	Allocated     uint64  `json:"allocated"`
	TotalAlloc    uint64  `json:"totalAlloc"`
	Sys           uint64  `json:"sys"`
	NumGC         uint32  `json:"numGC"`
	HeapAlloc     uint64  `json:"heapAlloc"`
	HeapSys       uint64  `json:"heapSys"`
	HeapInuse     uint64  `json:"heapInuse"`
	StackInuse    uint64  `json:"stackInuse"`
	UsagePercent  float64 `json:"usagePercent"`
}

// DiskStats represents disk usage statistics
type DiskStats struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Available   uint64  `json:"available"`
	UsagePercent float64 `json:"usagePercent"`
}

// NetworkStats represents network statistics
type NetworkStats struct {
	BytesReceived uint64 `json:"bytesReceived"`
	BytesSent     uint64 `json:"bytesSent"`
	PacketsReceived uint64 `json:"packetsReceived"`
	PacketsSent   uint64 `json:"packetsSent"`
	Connections   int    `json:"connections"`
}

// EmailStats represents email statistics
type EmailStats struct {
	Total         int64              `json:"total"`
	Processed     int64              `json:"processed"`
	Failed        int64              `json:"failed"`
	Spam          int64              `json:"spam"`
	SizeDistrib   map[string]int64   `json:"sizeDistribution"`
	DomainDistrib map[string]int64   `json:"domainDistribution"`
	TimeDistrib   map[string]int64   `json:"timeDistribution"`
	Attachments   int64              `json:"attachments"`
	HTML          int64              `json:"html"`
	Text          int64              `json:"text"`
}

// StorageStats represents storage usage statistics
type StorageStats struct {
	EmailCount    int64   `json:"emailCount"`
	TotalSize     int64   `json:"totalSize"`
	AttachmentSize int64  `json:"attachmentSize"`
	UsagePercent  float64 `json:"usagePercent"`
	OldestEmail   *time.Time `json:"oldestEmail"`
	NewestEmail   *time.Time `json:"newestEmail"`
}

// Credentials represents user authentication credentials
type Credentials struct {
	Username    string            `json:"username"`
	Password    string            `json:"password"`
	Email       string            `json:"email,omitempty"`
	Provider    string            `json:"provider,omitempty"`
	Token       string            `json:"token,omitempty"`
	TwoFactor   string            `json:"twoFactor,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AuthResult represents authentication result
type AuthResult struct {
	Success      bool              `json:"success"`
	User         *User             `json:"user,omitempty"`
	TokenPair    *TokenPair        `json:"tokenPair,omitempty"`
	Permissions  []string          `json:"permissions,omitempty"`
	Roles        []string          `json:"roles,omitempty"`
	Message      string            `json:"message,omitempty"`
	RequiresMFA  bool              `json:"requiresMfa"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	UserID      string            `json:"userId"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	Roles       []string          `json:"roles"`
	Permissions []string          `json:"permissions"`
	IssuedAt    time.Time         `json:"issuedAt"`
	ExpiresAt   time.Time         `json:"expiresAt"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	TokenType    string    `json:"tokenType"`
}

// Session represents user session information
type Session struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"userId"`
	CreatedAt time.Time              `json:"createdAt"`
	ExpiresAt time.Time              `json:"expiresAt"`
	IPAddress string                 `json:"ipAddress"`
	UserAgent string                 `json:"userAgent"`
	Metadata  map[string]interface{} `json:"metadata"`
	Active    bool                   `json:"active"`
}

// User represents a user in the system
type User struct {
	ID          string                 `json:"id"`
	Username    string                 `json:"username"`
	Email       string                 `json:"email"`
	DisplayName string                 `json:"displayName"`
	Roles       []string               `json:"roles"`
	Permissions []string               `json:"permissions"`
	Active      bool                   `json:"active"`
	CreatedAt   time.Time              `json:"createdAt"`
	UpdatedAt   time.Time              `json:"updatedAt"`
	LastLogin   *time.Time             `json:"lastLogin"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// UserUpdates represents user update fields
type UserUpdates struct {
	Username    *string               `json:"username,omitempty"`
	Email       *string               `json:"email,omitempty"`
	DisplayName *string               `json:"displayName,omitempty"`
	Roles       []string              `json:"roles,omitempty"`
	Permissions []string              `json:"permissions,omitempty"`
	Active      *bool                 `json:"active,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RateLimit represents rate limiting configuration
type RateLimit struct {
	Requests int           `json:"requests"`
	Window   time.Duration `json:"window"`
	Burst    int           `json:"burst,omitempty"`
}

// RateLimitResult represents rate limiting check result
type RateLimitResult struct {
	Allowed   bool          `json:"allowed"`
	Remaining int           `json:"remaining"`
	ResetTime time.Time     `json:"resetTime"`
	RetryAfter time.Duration `json:"retryAfter,omitempty"`
}

// RateLimitStatus represents current rate limit status
type RateLimitStatus struct {
	Key        string        `json:"key"`
	Requests   int           `json:"requests"`
	Limit      int           `json:"limit"`
	Window     time.Duration `json:"window"`
	ResetTime  time.Time     `json:"resetTime"`
	Remaining  int           `json:"remaining"`
}

// SecurityResult represents security validation result
type SecurityResult struct {
	Valid    bool                   `json:"valid"`
	Blocked  bool                   `json:"blocked"`
	Score    float64                `json:"score"`
	Reasons  []string               `json:"reasons"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ScanResult represents email security scan result
type ScanResult struct {
	Safe        bool                   `json:"safe"`
	Threats     []ThreatInfo           `json:"threats"`
	Score       float64                `json:"score"`
	Quarantine  bool                   `json:"quarantine"`
	Actions     []SecurityAction       `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatInfo represents detected threat information
type ThreatInfo struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
	Source      string  `json:"source"`
}

// SecurityAction represents security action to take
type SecurityAction struct {
	Type   string                 `json:"type"`
	Target string                 `json:"target"`
	Data   map[string]interface{} `json:"data"`
}

// BlacklistType represents blacklist types
type BlacklistType string

const (
	BlacklistTypeIP     BlacklistType = "ip"
	BlacklistTypeEmail  BlacklistType = "email"
	BlacklistTypeDomain BlacklistType = "domain"
	BlacklistTypeKeyword BlacklistType = "keyword"
)

// AnomalyResult represents anomaly detection result
type AnomalyResult struct {
	Detected   bool                   `json:"detected"`
	Score      float64                `json:"score"`
	Anomalies  []AnomalyInfo          `json:"anomalies"`
	Baseline   map[string]float64     `json:"baseline"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// AnomalyInfo represents detected anomaly information
type AnomalyInfo struct {
	Type        string  `json:"type"`
	Field       string  `json:"field"`
	Expected    float64 `json:"expected"`
	Actual      float64 `json:"actual"`
	Deviation   float64 `json:"deviation"`
	Confidence  float64 `json:"confidence"`
}

// ThreatReport represents a threat report
type ThreatReport struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Timestamp   time.Time              `json:"timestamp"`
	ReporterID  string                 `json:"reporterId"`
}

// SecurityPolicy represents security policy configuration
type SecurityPolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Rules       []SecurityRule         `json:"rules"`
	Actions     []SecurityAction       `json:"actions"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecurityRule represents individual security rule
type SecurityRule struct {
	Field     string      `json:"field"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	Condition string      `json:"condition,omitempty"`
}

// ComplianceRequest represents compliance validation request
type ComplianceRequest struct {
	Standard string                 `json:"standard"` // GDPR, PCI-DSS, etc.
	Data     map[string]interface{} `json:"data"`
	Context  map[string]string      `json:"context"`
}

// ComplianceResult represents compliance validation result
type ComplianceResult struct {
	Compliant bool                   `json:"compliant"`
	Standard  string                 `json:"standard"`
	Violations []ComplianceViolation `json:"violations"`
	Score     float64                `json:"score"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ComplianceViolation represents compliance violation
type ComplianceViolation struct {
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Field       string `json:"field"`
	Value       string `json:"value"`
}

// Tool represents a fortress tool
type Tool struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Parameters  []ToolParameter        `json:"parameters"`
	Handler     ToolHandler            `json:"-"`
	Timeout     time.Duration          `json:"timeout"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ToolParameter represents tool parameter definition
type ToolParameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default"`
	Description string      `json:"description"`
	Validation  string      `json:"validation,omitempty"`
}

// ToolHandler represents tool handler function
type ToolHandler func(ctx context.Context, params map[string]interface{}) (*ToolResult, error)

// ToolResult represents tool execution result
type ToolResult struct {
	Success  bool                   `json:"success"`
	Data     map[string]interface{} `json:"data"`
	Message  string                 `json:"message,omitempty"`
	Error    error                  `json:"error,omitempty"`
	Duration time.Duration          `json:"duration"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ToolInfo represents tool information
type ToolInfo struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Status      string                 `json:"status"`
	LastRun     *time.Time             `json:"lastRun"`
	RunCount    int64                  `json:"runCount"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// HTTPServerConfig represents HTTP server configuration
type HTTPServerConfig struct {
	Port         int                    `json:"port"`
	Host         string                 `json:"host"`
	TLS          *TLSConfig             `json:"tls,omitempty"`
	CORS         *CORSConfig            `json:"cors,omitempty"`
	Timeout      time.Duration          `json:"timeout"`
	MaxBodySize  int64                  `json:"maxBodySize"`
	Middleware   []string               `json:"middleware"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// SMTPServerConfig represents SMTP server configuration
type SMTPServerConfig struct {
	Port         int                    `json:"port"`
	Host         string                 `json:"host"`
	TLS          *TLSConfig             `json:"tls,omitempty"`
	Auth         *SMTPAuthConfig        `json:"auth,omitempty"`
	MaxMsgSize   int64                  `json:"maxMsgSize"`
	MaxRecipients int                   `json:"maxRecipients"`
	Timeout      time.Duration          `json:"timeout"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
	MinVersion string `json:"minVersion"`
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowedOrigins"`
	AllowedMethods   []string `json:"allowedMethods"`
	AllowedHeaders   []string `json:"allowedHeaders"`
	ExposedHeaders   []string `json:"exposedHeaders"`
	AllowCredentials bool     `json:"allowCredentials"`
	MaxAge           int      `json:"maxAge"`
}

// SMTPAuthConfig represents SMTP authentication configuration
type SMTPAuthConfig struct {
	Enabled   bool              `json:"enabled"`
	Mechanisms []string         `json:"mechanisms"`
	Users     map[string]string `json:"users"`
}

// MiddlewareFunc represents HTTP middleware function
type MiddlewareFunc func(next HandlerFunc) HandlerFunc

// WebSocketHandler represents WebSocket handler function
type WebSocketHandler func(ctx context.Context, conn WebSocketConn) error

// WebSocketConn represents WebSocket connection interface
type WebSocketConn interface {
	ReadMessage() ([]byte, error)
	WriteMessage(data []byte) error
	Close() error
	RemoteAddr() string
}

// WebSocketMessage represents WebSocket message
type WebSocketMessage struct {
	Type    string      `json:"type"`
	Data    interface{} `json:"data"`
	UserID  string      `json:"userId,omitempty"`
	RoomID  string      `json:"roomId,omitempty"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Driver       string            `json:"driver"`
	DSN          string            `json:"dsn"`
	MaxConns     int               `json:"maxConns"`
	MaxIdleConns int               `json:"maxIdleConns"`
	MaxLifetime  time.Duration     `json:"maxLifetime"`
	Migrations   string            `json:"migrations"`
	Options      map[string]string `json:"options"`
}

// BackupConfig represents backup configuration
type BackupConfig struct {
	Type        string            `json:"type"`
	Destination string            `json:"destination"`
	Schedule    string            `json:"schedule"`
	Retention   time.Duration     `json:"retention"`
	Compression bool              `json:"compression"`
	Encryption  bool              `json:"encryption"`
	Options     map[string]string `json:"options"`
}

// BackupInfo represents backup information
type BackupInfo struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Size        int64     `json:"size"`
	CreatedAt   time.Time `json:"createdAt"`
	Destination string    `json:"destination"`
	Status      string    `json:"status"`
	Checksum    string    `json:"checksum"`
}

// EventFilter represents event filtering criteria
type EventFilter struct {
	Types     []string  `json:"types"`
	Sources   []string  `json:"sources"`
	DateFrom  time.Time `json:"dateFrom"`
	DateTo    time.Time `json:"dateTo"`
	UserID    string    `json:"userId,omitempty"`
	TraceID   string    `json:"traceId,omitempty"`
	Limit     int       `json:"limit"`
	Offset    int       `json:"offset"`
}