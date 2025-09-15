# Pat - Email Testing Platform Solution Design

## Executive Summary

**Pat** is a modern email testing platform built upon MailHog's foundation, enhanced with customer service testing capabilities. It serves as both a standalone application and an Alexandria plugin, providing CS teams with comprehensive email integration testing tools.

**Version**: 1.0.0  
**Document Date**: 2025-06-11  
**Status**: Solution Design

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Design](#2-architecture-design)
3. [Core Components](#3-core-components)
4. [Customer Service Enhancements](#4-customer-service-enhancements)
5. [Data Models](#5-data-models)
6. [API Specifications](#6-api-specifications)
7. [User Interface Design](#7-user-interface-design)
8. [Deployment Architecture](#8-deployment-architecture)
9. [Standalone vs Plugin Architecture](#9-standalone-vs-plugin-architecture)
10. [Security & Compliance](#10-security--compliance)
11. [Performance Requirements](#11-performance-requirements)
12. [Implementation Roadmap](#12-implementation-roadmap)

---

## 1. System Overview

### 1.1 Vision

Pat transforms email testing from a developer-centric tool into a comprehensive platform for Customer Service teams to validate email workflows, test warning systems, and ensure communication quality.

### 1.2 Key Objectives

- **Maintain MailHog compatibility** while adding CS-specific features
- **Dual deployment** as standalone tool or Alexandria plugin
- **Enhanced testing capabilities** for CS workflows
- **Modern architecture** with current security standards
- **Intuitive interface** for non-technical CS staff

### 1.3 Core Capabilities

```mermaid
graph TB
    subgraph "Email Capture"
        SMTP[SMTP Server<br/>Port 1025]
        Parser[Email Parser]
        Storage[(Storage Layer)]
    end
    
    subgraph "CS Testing Features"
        Validator[Email Validator]
        Templates[Template Tester]
        Workflows[Workflow Engine]
        Reports[Report Generator]
    end
    
    subgraph "User Interfaces"
        WebUI[Web Dashboard]
        API[REST/GraphQL API]
        Plugin[Alexandria Plugin]
    end
    
    SMTP --> Parser --> Storage
    Storage --> Validator
    Storage --> Templates
    Storage --> Workflows
    Validator --> Reports
    Templates --> Reports
    Workflows --> Reports
    Reports --> WebUI
    Reports --> API
    API --> Plugin
```

---

## 2. Architecture Design

### 2.1 High-Level Architecture

```yaml
Presentation Layer:
  - Modern Web UI (React/TypeScript)
  - REST API v3
  - GraphQL API
  - WebSocket for real-time updates
  - Alexandria Plugin Interface

Application Layer:
  - Email Capture Service
  - Validation Engine
  - Template Testing Service
  - Workflow Orchestrator
  - Report Generator
  - Authentication Service

Data Layer:
  - PostgreSQL (primary storage)
  - Redis (caching & real-time)
  - S3-compatible (email archives)
  - Elasticsearch (search)

Infrastructure Layer:
  - Docker containers
  - Kubernetes orchestration
  - Load balancers
  - Message queues
```

### 2.2 Technology Stack

```yaml
Backend:
  Language: Go 1.21+
  Framework: Fiber v2 (high performance)
  Database: 
    - PostgreSQL 15+ (main data)
    - Redis 7+ (cache/pubsub)
  Search: Elasticsearch 8+
  Queue: NATS (lightweight, Go-native)
  
Frontend:
  Framework: React 18 + TypeScript
  State: Zustand (simple, powerful)
  UI: Tailwind CSS + Radix UI
  Build: Vite
  Testing: Vitest + Playwright
  
DevOps:
  Container: Docker
  Orchestration: Kubernetes
  CI/CD: GitHub Actions
  Monitoring: Prometheus + Grafana
  Logging: Loki
```

---

## 3. Core Components

### 3.1 SMTP Server (Enhanced)

```go
// Enhanced SMTP server with CS features
type PatSMTPServer struct {
    *smtp.Server
    
    // CS enhancements
    WorkspaceRouter  *WorkspaceRouter    // Route emails to workspaces
    HeaderExtractor  *HeaderExtractor    // Extract CS metadata
    PriorityDetector *PriorityDetector   // Detect urgent emails
    RateLimiter      *RateLimiter        // Prevent email bombs
}

// Workspace-aware email routing
type WorkspaceRouter struct {
    Rules []RoutingRule
}

type RoutingRule struct {
    Pattern    string  // Email pattern
    Workspace  string  // Target workspace
    Priority   int     // Rule priority
}

// Extract CS-relevant headers
type HeaderExtractor struct {
    ExtractTicketID    bool
    ExtractPriority    bool
    ExtractCustomerID  bool
    CustomHeaders      []string
}
```

### 3.2 Storage Layer

```go
// Multi-backend storage with CS metadata
type StorageService struct {
    primary   StorageBackend  // PostgreSQL
    cache     CacheBackend    // Redis
    archive   ArchiveBackend  // S3
    search    SearchBackend   // Elasticsearch
}

// Enhanced message model
type Message struct {
    // Original MailHog fields
    ID        string
    From      EmailAddress
    To        []EmailAddress
    Subject   string
    Body      string
    Headers   map[string][]string
    Created   time.Time
    
    // CS enhancements
    Workspace    string
    Category     string      // alert, notification, customer
    Priority     Priority    // urgent, high, normal, low
    TicketID     string      // Extracted ticket reference
    CustomerID   string      // Extracted customer reference
    ValidatedAt  *time.Time
    ValidationResults []ValidationResult
    Tags         []string
    Metadata     map[string]interface{}
}
```

### 3.3 Validation Engine

```go
// Comprehensive email validation
type ValidationEngine struct {
    validators map[string]Validator
    rules      map[string][]ValidationRule
}

// Validator interface
type Validator interface {
    Name() string
    Validate(msg *Message) ValidationResult
}

// Built-in validators
var BuiltInValidators = []Validator{
    &HeaderValidator{},      // Required headers
    &SPFValidator{},        // SPF compliance
    &DKIMValidator{},       // DKIM signatures
    &ContentValidator{},    // Content rules
    &TemplateValidator{},   // Template compliance
    &AccessibilityValidator{}, // A11y checks
}

// Validation rule
type ValidationRule struct {
    Field      string
    Operator   string  // equals, contains, regex
    Value      interface{}
    Severity   string  // error, warning, info
    Message    string
}

// Validation result
type ValidationResult struct {
    Validator  string
    Passed     bool
    Errors     []ValidationError
    Warnings   []ValidationWarning
    Metadata   map[string]interface{}
    Duration   time.Duration
}
```

### 3.4 Template Testing Service

```go
// Template testing engine
type TemplateTestService struct {
    parser      *TemplateParser
    renderer    *TemplateRenderer
    validator   *TemplateValidator
    previewer   *TemplatePreview
}

// Template test case
type TemplateTest struct {
    ID          string
    Name        string
    Template    string
    TestData    []TestDataSet
    Validators  []string
    CreatedBy   string
    Created     time.Time
}

// Test data set
type TestDataSet struct {
    Name        string
    Variables   map[string]interface{}
    Expected    ExpectedResult
}

// Template preview generator
type TemplatePreview struct {
    Desktop     *EmailPreview
    Mobile      *EmailPreview
    PlainText   string
    Warnings    []string
}
```

### 3.5 Workflow Engine

```go
// Email workflow testing
type WorkflowEngine struct {
    executor    *WorkflowExecutor
    scheduler   *WorkflowScheduler
    monitor     *WorkflowMonitor
}

// Workflow definition
type Workflow struct {
    ID          string
    Name        string
    Trigger     WorkflowTrigger
    Steps       []WorkflowStep
    Validators  []string
    Timeout     time.Duration
}

// Workflow step
type WorkflowStep struct {
    Type        string  // wait, send, validate, webhook
    Config      map[string]interface{}
    OnSuccess   string  // next step ID
    OnFailure   string  // error step ID
}

// Workflow execution
type WorkflowExecution struct {
    WorkflowID  string
    Status      string
    StartedAt   time.Time
    CompletedAt *time.Time
    Steps       []StepExecution
    Results     []ValidationResult
}
```

---

## 4. Customer Service Enhancements

### 4.1 CS-Specific Features

#### Alert Email Testing
```go
type AlertTestSuite struct {
    // Test different severity levels
    SeverityTests map[string]AlertTest
    
    // Escalation chain validation
    EscalationTests []EscalationTest
    
    // De-duplication testing
    DeduplicationTests []DedupeTest
}

type AlertTest struct {
    Name         string
    TriggerEvent Event
    Expected     AlertExpectation
}

type AlertExpectation struct {
    Recipients   []string
    Subject      string
    Priority     string
    Headers      map[string]string
    BodyContains []string
}
```

#### Response Time Tracking
```go
type ResponseTracker struct {
    // Track email delivery times
    DeliveryMetrics map[string]MetricSet
    
    // Alert on delays
    DelayThresholds map[string]time.Duration
    
    // Performance reports
    ReportGenerator *PerformanceReporter
}

type MetricSet struct {
    Count       int64
    TotalTime   time.Duration
    MinTime     time.Duration
    MaxTime     time.Duration
    P50         time.Duration
    P95         time.Duration
    P99         time.Duration
}
```

#### Compliance Checking
```go
type ComplianceChecker struct {
    // Email compliance rules
    Rules map[string]ComplianceRule
    
    // Automated checking
    AutoCheck bool
    
    // Compliance reports
    Reporter *ComplianceReporter
}

type ComplianceRule struct {
    Name        string
    Type        string  // can-spam, gdpr, accessibility
    Validators  []Validator
    Required    bool
}
```

### 4.2 Test Scenario Management

```yaml
Test Scenarios:
  - Customer Notification Flow
  - Alert Escalation Chain
  - Template Personalization
  - Multi-language Support
  - Bounce Handling
  - Unsubscribe Process

Scenario Components:
  - Setup: Initial conditions
  - Execution: Steps to perform
  - Validation: Expected outcomes
  - Reporting: Results format
```

---

## 5. Data Models

### 5.1 Core Entities

```sql
-- Workspaces for team isolation
CREATE TABLE workspaces (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    settings JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Enhanced messages table
CREATE TABLE messages (
    id UUID PRIMARY KEY,
    workspace_id UUID REFERENCES workspaces(id),
    message_id VARCHAR(255) UNIQUE, -- Original email ID
    from_address VARCHAR(255),
    to_addresses TEXT[],
    subject TEXT,
    body_plain TEXT,
    body_html TEXT,
    headers JSONB,
    attachments JSONB,
    
    -- CS fields
    category VARCHAR(50),
    priority VARCHAR(20),
    ticket_id VARCHAR(100),
    customer_id VARCHAR(100),
    tags TEXT[],
    metadata JSONB,
    
    -- Validation
    validated_at TIMESTAMP,
    validation_results JSONB,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Test scenarios
CREATE TABLE test_scenarios (
    id UUID PRIMARY KEY,
    workspace_id UUID REFERENCES workspaces(id),
    name VARCHAR(255),
    description TEXT,
    configuration JSONB,
    created_by UUID,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Test executions
CREATE TABLE test_executions (
    id UUID PRIMARY KEY,
    scenario_id UUID REFERENCES test_scenarios(id),
    status VARCHAR(50),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    results JSONB,
    report_url VARCHAR(500)
);

-- Validation rules
CREATE TABLE validation_rules (
    id UUID PRIMARY KEY,
    workspace_id UUID REFERENCES workspaces(id),
    name VARCHAR(255),
    type VARCHAR(50),
    configuration JSONB,
    active BOOLEAN DEFAULT true
);
```

### 5.2 Indexes for Performance

```sql
-- Message searching
CREATE INDEX idx_messages_workspace ON messages(workspace_id);
CREATE INDEX idx_messages_created ON messages(created_at DESC);
CREATE INDEX idx_messages_category ON messages(category);
CREATE INDEX idx_messages_ticket ON messages(ticket_id) WHERE ticket_id IS NOT NULL;
CREATE INDEX idx_messages_customer ON messages(customer_id) WHERE customer_id IS NOT NULL;

-- Full-text search
CREATE INDEX idx_messages_subject_fts ON messages USING gin(to_tsvector('english', subject));
CREATE INDEX idx_messages_body_fts ON messages USING gin(to_tsvector('english', body_plain));
```

---

## 6. API Specifications

### 6.1 REST API v3

```yaml
openapi: 3.0.0
info:
  title: Pat Email Testing API
  version: 3.0.0
  
paths:
  /api/v3/messages:
    get:
      summary: List messages with filtering
      parameters:
        - name: workspace
          in: query
          schema:
            type: string
        - name: category
          in: query
          schema:
            type: string
            enum: [alert, notification, customer, test]
        - name: validated
          in: query
          schema:
            type: boolean
        - name: from
          in: query
          schema:
            type: string
            format: date-time
        - name: to
          in: query
          schema:
            type: string
            format: date-time
            
  /api/v3/messages/{id}/validate:
    post:
      summary: Validate a message
      parameters:
        - name: id
          in: path
          required: true
        - name: validators
          in: query
          schema:
            type: array
            items:
              type: string
              
  /api/v3/test-scenarios:
    get:
      summary: List test scenarios
    post:
      summary: Create test scenario
      
  /api/v3/test-scenarios/{id}/execute:
    post:
      summary: Execute test scenario
      responses:
        202:
          description: Execution started
          content:
            application/json:
              schema:
                type: object
                properties:
                  execution_id:
                    type: string
                  status_url:
                    type: string
```

### 6.2 GraphQL API

```graphql
type Query {
  messages(
    workspace: ID!
    filter: MessageFilter
    pagination: PaginationInput
  ): MessageConnection!
  
  message(id: ID!): Message
  
  testScenarios(workspace: ID!): [TestScenario!]!
  
  validationRules(workspace: ID!, active: Boolean): [ValidationRule!]!
  
  reports(
    workspace: ID!
    type: ReportType
    from: DateTime
    to: DateTime
  ): [Report!]!
}

type Mutation {
  validateMessage(
    id: ID!
    validators: [String!]
  ): ValidationResult!
  
  createTestScenario(
    input: TestScenarioInput!
  ): TestScenario!
  
  executeTestScenario(
    id: ID!
    parameters: JSON
  ): TestExecution!
  
  updateValidationRule(
    id: ID!
    input: ValidationRuleInput!
  ): ValidationRule!
}

type Subscription {
  messageReceived(workspace: ID!): Message!
  
  testExecutionUpdate(executionId: ID!): TestExecutionUpdate!
}
```

### 6.3 WebSocket Events

```typescript
// Real-time event types
enum PatEventType {
  MESSAGE_RECEIVED = 'message.received',
  MESSAGE_VALIDATED = 'message.validated',
  TEST_STARTED = 'test.started',
  TEST_STEP_COMPLETED = 'test.step.completed',
  TEST_COMPLETED = 'test.completed',
  ALERT_TRIGGERED = 'alert.triggered'
}

// Event payload
interface PatEvent {
  type: PatEventType;
  workspace: string;
  timestamp: string;
  data: any;
}

// WebSocket connection
const ws = new WebSocket('ws://localhost:8025/ws');
ws.on('message', (event: PatEvent) => {
  switch(event.type) {
    case PatEventType.MESSAGE_RECEIVED:
      updateMessageList(event.data);
      break;
    // ... handle other events
  }
});
```

---

## 7. User Interface Design

### 7.1 UI Architecture

```typescript
// Main app structure
const PatApp = () => {
  return (
    <ThemeProvider theme={patTheme}>
      <Router>
        <Layout>
          <Header />
          <Sidebar />
          <MainContent>
            <Routes>
              <Route path="/messages" element={<MessagesView />} />
              <Route path="/test-scenarios" element={<TestScenariosView />} />
              <Route path="/templates" element={<TemplatesView />} />
              <Route path="/validations" element={<ValidationsView />} />
              <Route path="/reports" element={<ReportsView />} />
              <Route path="/settings" element={<SettingsView />} />
            </Routes>
          </MainContent>
        </Layout>
      </Router>
    </ThemeProvider>
  );
};
```

### 7.2 Key UI Components

#### Message List View
```typescript
interface MessageListProps {
  workspace: string;
  filters: MessageFilters;
  onMessageSelect: (id: string) => void;
}

const MessageList: React.FC<MessageListProps> = ({ 
  workspace, 
  filters, 
  onMessageSelect 
}) => {
  const { data, loading, error } = useMessages(workspace, filters);
  
  return (
    <div className="message-list">
      <FilterBar filters={filters} onChange={updateFilters} />
      <VirtualizedList
        items={data.messages}
        renderItem={(msg) => (
          <MessageRow
            key={msg.id}
            message={msg}
            onClick={() => onMessageSelect(msg.id)}
            showValidation={true}
            highlight={msg.priority === 'urgent'}
          />
        )}
      />
      <Pagination {...data.pagination} />
    </div>
  );
};
```

#### Email Inspector
```typescript
const EmailInspector: React.FC<{ messageId: string }> = ({ messageId }) => {
  const message = useMessage(messageId);
  const [view, setView] = useState<'rendered' | 'source' | 'headers'>('rendered');
  
  return (
    <div className="email-inspector">
      <InspectorHeader>
        <ViewToggle value={view} onChange={setView} />
        <ValidationBadge results={message.validationResults} />
        <ActionButtons message={message} />
      </InspectorHeader>
      
      <InspectorContent>
        {view === 'rendered' && <RenderedView content={message.body} />}
        {view === 'source' && <SourceView content={message.raw} />}
        {view === 'headers' && <HeadersView headers={message.headers} />}
      </InspectorContent>
      
      <InspectorSidebar>
        <MessageMetadata message={message} />
        <ValidationDetails results={message.validationResults} />
        <RelatedMessages ticketId={message.ticketId} />
      </InspectorSidebar>
    </div>
  );
};
```

#### Test Scenario Runner
```typescript
const TestScenarioRunner: React.FC = () => {
  const [selectedScenario, setSelectedScenario] = useState<string>();
  const [execution, setExecution] = useState<TestExecution>();
  
  return (
    <div className="test-runner">
      <ScenarioSelector
        value={selectedScenario}
        onChange={setSelectedScenario}
      />
      
      {selectedScenario && (
        <>
          <ScenarioConfig
            scenarioId={selectedScenario}
            onRun={(config) => runScenario(selectedScenario, config)}
          />
          
          {execution && (
            <ExecutionMonitor
              execution={execution}
              showSteps={true}
              showLogs={true}
            />
          )}
        </>
      )}
    </div>
  );
};
```

### 7.3 UI Features

```yaml
Core Features:
  - Real-time message updates
  - Advanced filtering and search
  - Message validation visualization
  - Test scenario management
  - Template preview and testing
  - Report generation
  - Dark mode support
  - Responsive design

CS-Specific Features:
  - Alert email monitoring
  - Response time tracking
  - Compliance checking
  - Workflow visualization
  - Team collaboration
  - Audit trail
```

---

## 8. Deployment Architecture

### 8.1 Container Architecture

```dockerfile
# Multi-stage build for Pat
FROM golang:1.21-alpine AS backend-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o pat-server ./cmd/server

FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app

COPY --from=backend-builder /app/pat-server .
COPY --from=frontend-builder /app/dist ./static

EXPOSE 1025 8025
CMD ["./pat-server"]
```

### 8.2 Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pat
  namespace: pat-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pat
  template:
    metadata:
      labels:
        app: pat
    spec:
      containers:
      - name: pat
        image: pat:latest
        ports:
        - containerPort: 1025
          name: smtp
        - containerPort: 8025
          name: http
        env:
        - name: PAT_MODE
          value: "standalone"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: pat-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: pat-secrets
              key: redis-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8025
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8025
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: pat-smtp
  namespace: pat-system
spec:
  selector:
    app: pat
  ports:
  - port: 1025
    targetPort: 1025
    name: smtp
  type: LoadBalancer
---
apiVersion: v1
kind: Service
metadata:
  name: pat-http
  namespace: pat-system
spec:
  selector:
    app: pat
  ports:
  - port: 80
    targetPort: 8025
    name: http
  type: ClusterIP
```

### 8.3 High Availability Setup

```yaml
Architecture:
  Load Balancer:
    - HAProxy or NGINX
    - Health checks
    - SSL termination
    
  Application Tier:
    - 3+ Pat instances
    - Horizontal pod autoscaling
    - Rolling updates
    
  Data Tier:
    - PostgreSQL with replication
    - Redis Sentinel
    - S3-compatible object storage
    
  Monitoring:
    - Prometheus metrics
    - Grafana dashboards
    - Alert manager
```

---

## 9. Standalone vs Plugin Architecture

### 9.1 Architecture Comparison

```mermaid
graph TB
    subgraph "Standalone Deployment"
        SA[Pat Standalone]
        SDB[(Pat Database)]
        SUI[Pat Web UI]
        SAPI[Pat API]
        
        SA --> SDB
        SA --> SUI
        SA --> SAPI
    end
    
    subgraph "Plugin Deployment"
        Alexandria[Alexandria Platform]
        PP[Pat Plugin]
        ADB[(Alexandria DB)]
        AUI[Alexandria UI]
        AAPI[Alexandria API]
        
        Alexandria --> PP
        PP --> ADB
        PP --> AUI
        PP --> AAPI
    end
    
    subgraph "Shared Core"
        Core[Pat Core Engine]
        SMTP[SMTP Server]
        Valid[Validation Engine]
        
        SA --> Core
        PP --> Core
        Core --> SMTP
        Core --> Valid
    end
```

### 9.2 Standalone Mode

#### Configuration
```yaml
# config/standalone.yaml
mode: standalone
server:
  smtp:
    host: 0.0.0.0
    port: 1025
  http:
    host: 0.0.0.0
    port: 8025
    
database:
  type: postgresql
  url: postgresql://pat:password@localhost/pat
  
auth:
  provider: local
  config:
    bcrypt_cost: 12
    session_timeout: 24h
    
features:
  multi_workspace: true
  user_management: true
  api_keys: true
```

#### Standalone Features
```go
// Standalone-specific services
type StandaloneServices struct {
    // User management
    UserService     *UserService
    AuthService     *AuthService
    
    // Workspace management
    WorkspaceService *WorkspaceService
    
    // API key management
    APIKeyService   *APIKeyService
    
    // Standalone UI
    UIServer        *UIServer
}

// Initialize standalone mode
func InitStandalone(config *Config) (*PatServer, error) {
    server := &PatServer{
        Mode: ModeStandalone,
    }
    
    // Initialize all services
    server.InitCore()
    server.InitStandaloneServices()
    server.InitAPI()
    server.InitUI()
    
    return server, nil
}
```

### 9.3 Plugin Mode

#### Plugin Interface
```go
// Alexandria plugin interface
type AlexandriaPlugin interface {
    // Metadata
    Name() string
    Version() string
    Description() string
    
    // Lifecycle
    Initialize(ctx context.Context, config map[string]interface{}) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    
    // Integration points
    RegisterRoutes(router Router)
    RegisterMenuItems() []MenuItem
    RegisterWidgets() []Widget
    RegisterPermissions() []Permission
}

// Pat plugin implementation
type PatPlugin struct {
    core     *PatCore
    config   *PluginConfig
}

func (p *PatPlugin) Name() string {
    return "Pat Email Testing"
}

func (p *PatPlugin) RegisterRoutes(router Router) {
    // API routes
    router.Group("/pat/api/v3", p.apiRoutes)
    
    // UI routes
    router.Static("/pat/ui", p.uiAssets)
}

func (p *PatPlugin) RegisterMenuItems() []MenuItem {
    return []MenuItem{
        {
            ID:    "pat-messages",
            Label: "Email Testing",
            Icon:  "mail",
            Path:  "/pat/messages",
            Permission: "pat.view",
        },
    }
}
```

#### Plugin Configuration
```yaml
# config/plugin.yaml
mode: plugin
plugin:
  # Use Alexandria's database
  database: shared
  
  # Use Alexandria's auth
  auth: delegated
  
  # Plugin-specific settings
  namespace: pat
  
  # Integration points
  hooks:
    on_ticket_created: true
    on_alert_sent: true
    on_customer_email: true
```

#### Alexandria Integration Points
```typescript
// Alexandria SDK for Pat integration
class PatIntegration {
  constructor(private alexandria: AlexandriaSDK) {}
  
  // Register Pat within Alexandria
  async register(): Promise<void> {
    await this.alexandria.plugins.register({
      id: 'pat',
      name: 'Pat Email Testing',
      version: '1.0.0',
      endpoints: {
        api: '/pat/api/v3',
        ui: '/pat/ui',
        health: '/pat/health'
      }
    });
  }
  
  // Hook into Alexandria events
  async setupHooks(): Promise<void> {
    // Capture ticket emails
    this.alexandria.events.on('ticket.email.sent', async (event) => {
      await this.captureEmail(event.email);
    });
    
    // Capture alerts
    this.alexandria.events.on('alert.sent', async (event) => {
      await this.captureAlert(event);
    });
  }
  
  // Provide Pat data to Alexandria
  async provideData(): Promise<void> {
    // Email metrics widget
    this.alexandria.dashboard.registerWidget({
      id: 'pat-email-metrics',
      name: 'Email Testing Metrics',
      component: PatMetricsWidget,
      permissions: ['pat.view.metrics']
    });
  }
}
```

### 9.4 Shared Core Architecture

```go
// Core engine used by both modes
type PatCore struct {
    // Core services
    SMTPServer       *SMTPServer
    Storage          StorageService
    ValidationEngine *ValidationEngine
    TemplateService  *TemplateService
    WorkflowEngine   *WorkflowEngine
    
    // Mode-specific adapter
    ModeAdapter      ModeAdapter
}

// Mode adapter interface
type ModeAdapter interface {
    // Database access
    GetDB() Database
    
    // Authentication
    AuthenticateUser(token string) (*User, error)
    
    // Workspace resolution
    GetWorkspace(id string) (*Workspace, error)
    
    // Event publishing
    PublishEvent(event Event) error
}

// Standalone adapter
type StandaloneAdapter struct {
    db   *sql.DB
    auth *AuthService
}

// Plugin adapter
type PluginAdapter struct {
    alexandria *AlexandriaClient
}

func (p *PluginAdapter) GetDB() Database {
    // Use Alexandria's database with Pat tables
    return p.alexandria.GetDB().WithPrefix("pat_")
}

func (p *PluginAdapter) AuthenticateUser(token string) (*User, error) {
    // Delegate to Alexandria's auth
    return p.alexandria.Auth.ValidateToken(token)
}
```

### 9.5 Deployment Strategies

#### Standalone Deployment
```bash
# Docker Compose for standalone
docker-compose -f docker-compose.standalone.yml up -d

# Kubernetes for standalone
kubectl apply -f k8s/standalone/

# Direct binary
./pat-server --mode=standalone --config=./config/standalone.yaml
```

#### Plugin Deployment
```bash
# Install as Alexandria plugin
alexandria plugin install pat

# Configure plugin
alexandria plugin configure pat --workspace=cs-team

# Enable plugin
alexandria plugin enable pat
```

### 9.6 Feature Matrix

| Feature | Standalone | Plugin |
|---------|------------|--------|
| SMTP Server | ✅ Full control | ✅ Dedicated port |
| User Management | ✅ Built-in | ❌ Uses Alexandria |
| Authentication | ✅ Built-in | ❌ Uses Alexandria |
| Database | ✅ Dedicated | ⚡ Shared (isolated tables) |
| UI | ✅ Full app | ⚡ Embedded in Alexandria |
| API | ✅ Full API | ⚡ Namespaced endpoints |
| Workspaces | ✅ Built-in | ❌ Uses Alexandria |
| Permissions | ✅ Built-in | ❌ Uses Alexandria |
| Updates | ✅ Independent | ⚡ With Alexandria |
| Backup | ✅ Separate | ⚡ With Alexandria |

---

## 10. Security & Compliance

### 10.1 Security Architecture

```yaml
Security Layers:
  Network:
    - TLS 1.3 for all HTTP traffic
    - STARTTLS for SMTP (optional)
    - Network segmentation
    - Rate limiting
    
  Authentication:
    - JWT tokens (standalone)
    - Alexandria SSO (plugin)
    - API key authentication
    - 2FA support
    
  Authorization:
    - RBAC with fine-grained permissions
    - Workspace isolation
    - Row-level security
    
  Data:
    - Encryption at rest
    - Encryption in transit
    - PII data masking
    - Audit logging
```

### 10.2 Security Features

```go
// Security middleware
type SecurityMiddleware struct {
    RateLimiter     *RateLimiter
    AuthValidator   *AuthValidator
    IPWhitelist     *IPWhitelist
    CSRFProtection  *CSRFProtection
}

// Email sanitization
type EmailSanitizer struct {
    RemoveScripts    bool
    RemoveTracking   bool
    MaskPII          bool
    SanitizeHeaders  bool
}

// Audit logging
type AuditLogger struct {
    storage AuditStorage
}

func (a *AuditLogger) LogAccess(user, resource, action string) {
    a.storage.Store(AuditEntry{
        Timestamp: time.Now(),
        User:      user,
        Resource:  resource,
        Action:    action,
        IP:        getClientIP(),
    })
}
```

### 10.3 Compliance Features

```yaml
Compliance Support:
  CAN-SPAM:
    - Unsubscribe link validation
    - Physical address check
    - Subject line compliance
    
  GDPR:
    - Data retention policies
    - Right to erasure
    - Data export
    - Consent tracking
    
  Accessibility:
    - WCAG 2.1 AA compliance
    - Screen reader support
    - Keyboard navigation
    - High contrast mode
```

---

## 11. Performance Requirements

### 11.1 Performance Targets

```yaml
SMTP Performance:
  - Connection acceptance: <10ms
  - Message processing: <50ms
  - Storage write: <20ms
  - Concurrent connections: 1000+
  
API Performance:
  - Response time (p50): <20ms
  - Response time (p95): <100ms
  - Response time (p99): <500ms
  - Throughput: 10,000 req/s
  
UI Performance:
  - Initial load: <2s
  - Time to interactive: <3s
  - API response rendering: <100ms
  
Storage Performance:
  - Message retrieval: <5ms
  - Search query: <100ms
  - Bulk operations: <1s for 1000 items
```

### 11.2 Optimization Strategies

```go
// Performance optimizations
type PerformanceConfig struct {
    // Connection pooling
    DBPoolSize      int
    RedisPoolSize   int
    
    // Caching
    CacheTTL        time.Duration
    CacheSize       int
    
    // Batching
    BatchSize       int
    BatchTimeout    time.Duration
    
    // Compression
    EnableGzip      bool
    MinGzipSize     int
}

// Message indexing for fast retrieval
type MessageIndexer struct {
    primaryIndex   map[string]*Message  // By ID
    workspaceIndex map[string][]string  // By workspace
    timeIndex      *btree.BTree         // By timestamp
    searchIndex    *SearchEngine        // Full-text
}
```

---

## 12. Implementation Roadmap

### 12.1 Phase 1: Foundation (Weeks 1-4)

```yaml
Week 1-2: Core Infrastructure
  - Set up project structure
  - Implement enhanced SMTP server
  - Create storage layer with PostgreSQL
  - Basic API structure
  
Week 3-4: Essential Features
  - Message capture and storage
  - Basic validation engine
  - Simple web UI
  - API v3 endpoints
```

### 12.2 Phase 2: CS Features (Weeks 5-8)

```yaml
Week 5-6: CS Enhancements
  - Workspace management
  - Alert email handling
  - Template testing
  - Validation rules
  
Week 7-8: Advanced Features
  - Workflow engine
  - Test scenarios
  - Compliance checking
  - Report generation
```

### 12.3 Phase 3: Integration (Weeks 9-10)

```yaml
Week 9: Plugin Architecture
  - Alexandria plugin interface
  - Shared database support
  - Authentication delegation
  - UI embedding
  
Week 10: Testing & Polish
  - Integration testing
  - Performance optimization
  - Documentation
  - Deployment scripts
```

### 12.4 Phase 4: Production Ready (Weeks 11-12)

```yaml
Week 11: Production Features
  - Monitoring and alerting
  - Backup and recovery
  - Security hardening
  - Load testing
  
Week 12: Launch Preparation
  - Final testing
  - Migration tools
  - Training materials
  - Go-live plan
```

### 12.5 Success Criteria

```yaml
Technical:
  - All MailHog features preserved
  - CS features fully functional
  - Performance targets met
  - Security scan passed
  
Business:
  - CS team trained
  - Documentation complete
  - Both deployment modes working
  - Positive user feedback
```

---

## Conclusion

Pat represents a significant evolution of MailHog, transforming it from a developer tool into a comprehensive email testing platform for Customer Service teams. The dual deployment model (standalone and plugin) provides flexibility while the enhanced features address specific CS testing needs.

The architecture maintains MailHog's simplicity while adding enterprise features like workspaces, validation, compliance checking, and comprehensive reporting. The implementation roadmap provides a clear path from concept to production-ready platform.