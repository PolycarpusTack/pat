# EPIC 1: Plugin Foundation & Architecture - Detailed Implementation Guide

## Overview
This document provides detailed implementation guidance for EPIC 1, which establishes the core Pat plugin structure and basic functionality within the Alexandria platform.

**Duration**: 4 weeks  
**Team**: 1-2 developers  
**Dependencies**: Alexandria Platform SDK v0.1.0+

---

## Pre-Development Checklist

- [ ] Alexandria development environment set up
- [ ] Access to Alexandria plugin SDK documentation
- [ ] Go 1.21+ installed
- [ ] Node.js 18+ and npm installed
- [ ] MongoDB/PostgreSQL development instances available
- [ ] Git repository created with proper .gitignore

---

## Week 1: Plugin Scaffold & Structure

### Day 1-2: Project Setup

#### Directory Structure Creation
```bash
pat-plugin/
├── .github/
│   └── workflows/
│       ├── ci.yml              # CI pipeline
│       └── release.yml         # Release automation
├── src/                        # TypeScript/React source
│   ├── index.ts               # Plugin entry point
│   ├── types/                 # TypeScript definitions
│   │   ├── email.ts
│   │   ├── workflow.ts
│   │   └── index.ts
│   ├── api/                   # API layer
│   │   ├── graphql/
│   │   │   ├── schema.graphql
│   │   │   └── resolvers.ts
│   │   └── rest/
│   │       └── routes.ts
│   ├── services/              # Business logic
│   │   ├── EmailService.ts
│   │   ├── StorageService.ts
│   │   └── ValidationService.ts
│   ├── components/            # React components
│   │   ├── EmailList/
│   │   ├── EmailViewer/
│   │   └── common/
│   └── hooks/                 # React hooks
│       └── useEmails.ts
├── pkg/                       # Go packages
│   ├── smtp/                  # SMTP server
│   │   ├── server.go
│   │   ├── handler.go
│   │   └── server_test.go
│   ├── storage/               # Storage abstraction
│   │   ├── interface.go
│   │   ├── memory.go
│   │   └── storage_test.go
│   ├── models/                # Data models
│   │   └── email.go
│   └── config/                # Configuration
│       └── config.go
├── cmd/
│   └── server/
│       └── main.go            # Go server entry
├── scripts/                   # Build & dev scripts
│   ├── build.sh
│   └── dev.sh
├── tests/                     # Integration tests
│   ├── e2e/
│   └── integration/
├── docs/                      # Documentation
├── plugin.json               # Plugin manifest
├── package.json              # NPM configuration
├── tsconfig.json             # TypeScript config
├── go.mod                    # Go modules
├── go.sum
├── Dockerfile                # Container image
└── README.md
```

#### Initial Configuration Files

**plugin.json**:
```json
{
  "id": "pat-email-testing",
  "name": "Pat - Email Testing Platform",
  "version": "0.1.0",
  "description": "Comprehensive email testing and CS workflow validation",
  "author": {
    "name": "Your Team",
    "email": "team@example.com",
    "url": "https://github.com/yourorg/pat-plugin"
  },
  "main": "dist/index.js",
  "binary": "dist/pat-server",
  "minPlatformVersion": "0.1.0",
  "maxPlatformVersion": "1.x",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/yourorg/pat-plugin.git"
  },
  "permissions": [
    "network:listen:1025",
    "network:listen:8025",
    "database:read",
    "database:write",
    "event:publish",
    "event:subscribe",
    "file:read",
    "file:write",
    "process:spawn"
  ],
  "services": {
    "smtp": {
      "port": 1025,
      "protocol": "tcp",
      "description": "SMTP server for email capture"
    },
    "api": {
      "port": 8025,
      "protocol": "http",
      "routes": "/pat/*",
      "description": "HTTP API for email management"
    }
  },
  "configuration": {
    "schema": {
      "storage": {
        "type": "string",
        "enum": ["memory", "mongodb", "postgresql"],
        "default": "memory",
        "description": "Storage backend for emails"
      },
      "smtp": {
        "type": "object",
        "properties": {
          "port": {
            "type": "integer",
            "default": 1025,
            "minimum": 1024,
            "maximum": 65535
          },
          "hostname": {
            "type": "string",
            "default": "localhost"
          },
          "maxMessageSize": {
            "type": "integer",
            "default": 10485760,
            "description": "Maximum message size in bytes (10MB default)"
          }
        }
      },
      "retention": {
        "type": "object",
        "properties": {
          "enabled": {
            "type": "boolean",
            "default": true
          },
          "days": {
            "type": "integer",
            "default": 7,
            "minimum": 1,
            "maximum": 365
          }
        }
      }
    }
  },
  "uiContributions": {
    "routes": [
      {
        "path": "/pat",
        "component": "PatDashboard",
        "title": "Email Testing",
        "icon": "mail"
      },
      {
        "path": "/pat/emails/:id",
        "component": "EmailDetail",
        "title": "Email Detail"
      },
      {
        "path": "/pat/settings",
        "component": "PatSettings",
        "title": "Pat Settings"
      }
    ],
    "menuItems": [
      {
        "id": "pat-main",
        "title": "Email Testing",
        "icon": "mail",
        "path": "/pat",
        "position": "main",
        "order": 100
      }
    ],
    "widgets": [
      {
        "id": "pat-email-count",
        "component": "EmailCountWidget",
        "title": "Captured Emails",
        "description": "Shows count of captured emails",
        "defaultSize": { "width": 2, "height": 1 }
      }
    ]
  },
  "eventSubscriptions": [
    {
      "topic": "system:ready",
      "handler": "onSystemReady"
    },
    {
      "topic": "system:shutdown",
      "handler": "onSystemShutdown"
    }
  ],
  "eventPublications": [
    {
      "topic": "pat:email:received",
      "description": "Emitted when a new email is captured",
      "schema": {
        "type": "object",
        "properties": {
          "id": { "type": "string" },
          "from": { "type": "string" },
          "to": { "type": "array", "items": { "type": "string" } },
          "subject": { "type": "string" },
          "timestamp": { "type": "string", "format": "date-time" }
        }
      }
    }
  ]
}
```

**package.json**:
```json
{
  "name": "pat-plugin",
  "version": "0.1.0",
  "description": "Pat Email Testing Plugin for Alexandria",
  "main": "dist/index.js",
  "scripts": {
    "dev": "concurrently \"npm:dev:*\"",
    "dev:ts": "webpack --watch --mode development",
    "dev:go": "air -c .air.toml",
    "build": "npm run build:ts && npm run build:go",
    "build:ts": "webpack --mode production",
    "build:go": "go build -o dist/pat-server ./cmd/server",
    "test": "npm run test:ts && npm run test:go",
    "test:ts": "jest",
    "test:go": "go test ./...",
    "lint": "npm run lint:ts && npm run lint:go",
    "lint:ts": "eslint src --ext .ts,.tsx",
    "lint:go": "golangci-lint run",
    "package": "npm run build && node scripts/package.js",
    "clean": "rimraf dist coverage"
  },
  "dependencies": {
    "@alexandria/plugin-sdk": "^0.1.0",
    "@apollo/client": "^3.8.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "@mui/material": "^5.14.0",
    "@emotion/react": "^11.11.0",
    "@emotion/styled": "^11.11.0",
    "axios": "^1.6.0",
    "date-fns": "^2.30.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "@types/node": "^20.10.0",
    "typescript": "^5.3.0",
    "webpack": "^5.89.0",
    "webpack-cli": "^5.1.0",
    "ts-loader": "^9.5.0",
    "@testing-library/react": "^14.1.0",
    "jest": "^29.7.0",
    "eslint": "^8.55.0",
    "concurrently": "^8.2.0",
    "rimraf": "^5.0.0"
  }
}
```

**go.mod**:
```go
module github.com/alexandria/pat-plugin

go 1.21

require (
    github.com/gorilla/mux v1.8.1
    github.com/sirupsen/logrus v1.9.3
    github.com/stretchr/testify v1.8.4
    github.com/google/uuid v1.5.0
    github.com/spf13/viper v1.18.0
    go.mongodb.org/mongo-driver v1.13.1
    github.com/lib/pq v1.10.9
)
```

### Day 3-4: Plugin Lifecycle Implementation

**src/index.ts**:
```typescript
import { 
  PluginLifecycle, 
  PluginContext, 
  Logger,
  EventBus,
  ConfigService 
} from '@alexandria/plugin-sdk';
import { PatServer } from './services/PatServer';
import { EmailService } from './services/EmailService';
import { setupGraphQLExtensions } from './api/graphql/extensions';
import { PatDashboard } from './components/PatDashboard';
import { EmailDetail } from './components/EmailDetail';
import { PatSettings } from './components/PatSettings';
import { EmailCountWidget } from './components/widgets/EmailCountWidget';

export default class PatPlugin implements PluginLifecycle {
  private context?: PluginContext;
  private server?: PatServer;
  private logger?: Logger;
  private cleanup: (() => void)[] = [];

  async onInstall(): Promise<void> {
    // Perform one-time installation tasks
    console.log('Pat Plugin: Installing...');
  }

  async onActivate(context: PluginContext): Promise<void> {
    this.context = context;
    this.logger = context.getLogger('pat-plugin');
    
    this.logger.info('Activating Pat Email Testing Plugin');

    try {
      // Initialize services
      await this.initializeServices();
      
      // Register UI components
      this.registerUIComponents();
      
      // Set up API extensions
      await this.setupAPIExtensions();
      
      // Subscribe to events
      this.subscribeToEvents();
      
      // Start SMTP server
      await this.startSMTPServer();
      
      this.logger.info('Pat Plugin activated successfully');
    } catch (error) {
      this.logger.error('Failed to activate Pat Plugin', error);
      throw error;
    }
  }

  async onDeactivate(): Promise<void> {
    this.logger?.info('Deactivating Pat Plugin');

    // Run cleanup in reverse order
    for (const cleanupFn of this.cleanup.reverse()) {
      try {
        await cleanupFn();
      } catch (error) {
        this.logger?.error('Cleanup error', error);
      }
    }

    // Stop SMTP server
    if (this.server) {
      await this.server.stop();
    }

    this.logger?.info('Pat Plugin deactivated');
  }

  async onUpdate(fromVersion: string, toVersion: string): Promise<void> {
    this.logger?.info(`Updating Pat Plugin from ${fromVersion} to ${toVersion}`);
    
    // Perform migration tasks based on version
    if (fromVersion < '0.2.0' && toVersion >= '0.2.0') {
      await this.migrateToV2();
    }
  }

  async onUninstall(): Promise<void> {
    this.logger?.info('Uninstalling Pat Plugin');
    
    // Clean up persistent data if requested
    const config = this.context?.config;
    if (config?.get('cleanupOnUninstall', false)) {
      await this.cleanupAllData();
    }
  }

  private async initializeServices(): Promise<void> {
    const config = this.context!.config;
    const dataService = this.context!.services.data;
    const eventBus = this.context!.services.events;

    // Initialize email service
    const emailService = new EmailService({
      storage: config.get('storage', 'memory'),
      dataService,
      eventBus,
      logger: this.logger!
    });

    this.context!.services.register('emailService', emailService);
    
    this.cleanup.push(() => emailService.shutdown());
  }

  private registerUIComponents(): void {
    const ui = this.context!.ui;

    // Register main components
    ui.registerComponent('PatDashboard', PatDashboard);
    ui.registerComponent('EmailDetail', EmailDetail);
    ui.registerComponent('PatSettings', PatSettings);
    
    // Register widgets
    ui.registerComponent('EmailCountWidget', EmailCountWidget);

    this.cleanup.push(() => {
      ui.unregisterComponent('PatDashboard');
      ui.unregisterComponent('EmailDetail');
      ui.unregisterComponent('PatSettings');
      ui.unregisterComponent('EmailCountWidget');
    });
  }

  private async setupAPIExtensions(): Promise<void> {
    const api = this.context!.api;
    
    // GraphQL extensions
    const removeGraphQL = await setupGraphQLExtensions(api, this.context!);
    this.cleanup.push(removeGraphQL);

    // REST endpoints (for backwards compatibility)
    api.rest.get('/pat/api/v2/messages', this.handleGetMessages.bind(this));
    api.rest.get('/pat/api/v2/messages/:id', this.handleGetMessage.bind(this));
    api.rest.delete('/pat/api/v2/messages/:id', this.handleDeleteMessage.bind(this));
  }

  private subscribeToEvents(): void {
    const events = this.context!.services.events;

    const unsubscribe = events.subscribe('system:ready', this.onSystemReady.bind(this));
    this.cleanup.push(unsubscribe);
  }

  private async startSMTPServer(): Promise<void> {
    const config = this.context!.config;
    const processService = this.context!.services.process;

    // Start Go SMTP server as subprocess
    this.server = new PatServer({
      binaryPath: './dist/pat-server',
      config: {
        smtpPort: config.get('smtp.port', 1025),
        apiPort: config.get('api.port', 8025),
        storage: config.get('storage', 'memory'),
        hostname: config.get('smtp.hostname', 'localhost')
      },
      processService,
      logger: this.logger!
    });

    await this.server.start();
  }

  // Event handlers
  private async onSystemReady(): Promise<void> {
    this.logger?.info('System ready, Pat Plugin is operational');
    
    // Emit ready event
    this.context?.services.events.publish('pat:ready', {
      smtpPort: this.context?.config.get('smtp.port', 1025),
      apiPort: this.context?.config.get('api.port', 8025)
    });
  }

  // API handlers
  private async handleGetMessages(req: any, res: any): Promise<void> {
    const emailService = this.context!.services.get('emailService') as EmailService;
    const messages = await emailService.getMessages(req.query);
    res.json(messages);
  }

  private async handleGetMessage(req: any, res: any): Promise<void> {
    const emailService = this.context!.services.get('emailService') as EmailService;
    const message = await emailService.getMessage(req.params.id);
    if (message) {
      res.json(message);
    } else {
      res.status(404).json({ error: 'Message not found' });
    }
  }

  private async handleDeleteMessage(req: any, res: any): Promise<void> {
    const emailService = this.context!.services.get('emailService') as EmailService;
    await emailService.deleteMessage(req.params.id);
    res.status(204).send();
  }

  // Migration methods
  private async migrateToV2(): Promise<void> {
    // Implement data migration logic
    this.logger?.info('Migrating data to v2 format');
  }

  private async cleanupAllData(): Promise<void> {
    // Remove all plugin data
    this.logger?.info('Cleaning up all Pat Plugin data');
  }
}
```

### Day 5: Basic SMTP Server Structure

**pkg/smtp/server.go**:
```go
package smtp

import (
    "context"
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/alexandria/pat-plugin/pkg/config"
    "github.com/alexandria/pat-plugin/pkg/models"
    "github.com/alexandria/pat-plugin/pkg/storage"
    "github.com/google/uuid"
    "github.com/sirupsen/logrus"
)

type Server struct {
    config    *config.SMTPConfig
    storage   storage.Backend
    logger    *logrus.Logger
    listener  net.Listener
    wg        sync.WaitGroup
    ctx       context.Context
    cancel    context.CancelFunc
    sessions  sync.Map
}

func NewServer(cfg *config.SMTPConfig, storage storage.Backend, logger *logrus.Logger) *Server {
    ctx, cancel := context.WithCancel(context.Background())
    
    return &Server{
        config:  cfg,
        storage: storage,
        logger:  logger,
        ctx:     ctx,
        cancel:  cancel,
    }
}

func (s *Server) Start() error {
    addr := fmt.Sprintf("%s:%d", s.config.BindAddr, s.config.Port)
    
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return fmt.Errorf("failed to listen on %s: %w", addr, err)
    }
    
    s.listener = listener
    s.logger.Infof("SMTP server listening on %s", addr)
    
    s.wg.Add(1)
    go s.acceptConnections()
    
    return nil
}

func (s *Server) Stop() error {
    s.logger.Info("Stopping SMTP server")
    
    // Cancel context to signal shutdown
    s.cancel()
    
    // Close listener
    if s.listener != nil {
        s.listener.Close()
    }
    
    // Wait for all connections to close
    done := make(chan struct{})
    go func() {
        s.wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        s.logger.Info("SMTP server stopped gracefully")
    case <-time.After(30 * time.Second):
        s.logger.Warn("SMTP server shutdown timeout")
    }
    
    return nil
}

func (s *Server) acceptConnections() {
    defer s.wg.Done()
    
    for {
        conn, err := s.listener.Accept()
        if err != nil {
            select {
            case <-s.ctx.Done():
                return
            default:
                s.logger.Errorf("Accept error: %v", err)
                continue
            }
        }
        
        s.wg.Add(1)
        go s.handleConnection(conn)
    }
}

func (s *Server) handleConnection(conn net.Conn) {
    defer s.wg.Done()
    defer conn.Close()
    
    sessionID := uuid.New().String()
    session := NewSession(sessionID, conn, s.config, s.storage, s.logger)
    
    s.sessions.Store(sessionID, session)
    defer s.sessions.Delete(sessionID)
    
    if err := session.Serve(); err != nil {
        s.logger.Errorf("Session error: %v", err)
    }
}
```

**pkg/smtp/session.go**:
```go
package smtp

import (
    "bufio"
    "fmt"
    "io"
    "net"
    "strings"
    "time"

    "github.com/alexandria/pat-plugin/pkg/config"
    "github.com/alexandria/pat-plugin/pkg/models"
    "github.com/alexandria/pat-plugin/pkg/storage"
    "github.com/google/uuid"
    "github.com/sirupsen/logrus"
)

type Session struct {
    id       string
    conn     net.Conn
    reader   *bufio.Reader
    writer   *bufio.Writer
    config   *config.SMTPConfig
    storage  storage.Backend
    logger   *logrus.Logger
    
    // Session state
    from     string
    to       []string
    data     []byte
    state    string
}

const (
    StateInit = "INIT"
    StateHelo = "HELO"
    StateMail = "MAIL"
    StateRcpt = "RCPT"
    StateData = "DATA"
    StateQuit = "QUIT"
)

func NewSession(id string, conn net.Conn, config *config.SMTPConfig, storage storage.Backend, logger *logrus.Logger) *Session {
    return &Session{
        id:      id,
        conn:    conn,
        reader:  bufio.NewReader(conn),
        writer:  bufio.NewWriter(conn),
        config:  config,
        storage: storage,
        logger:  logger,
        state:   StateInit,
        to:      make([]string, 0),
    }
}

func (s *Session) Serve() error {
    s.logger.Debugf("New SMTP session: %s", s.id)
    
    // Send greeting
    if err := s.writeLine(220, fmt.Sprintf("%s ESMTP Pat", s.config.Hostname)); err != nil {
        return err
    }
    
    // Main command loop
    for {
        if err := s.conn.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
            return err
        }
        
        line, err := s.readLine()
        if err != nil {
            if err == io.EOF {
                return nil
            }
            return err
        }
        
        if err := s.handleCommand(line); err != nil {
            s.logger.Errorf("Command error: %v", err)
            s.writeLine(500, "Command error")
        }
        
        if s.state == StateQuit {
            return nil
        }
    }
}

func (s *Session) handleCommand(line string) error {
    parts := strings.Fields(line)
    if len(parts) == 0 {
        return s.writeLine(500, "Empty command")
    }
    
    command := strings.ToUpper(parts[0])
    args := strings.Join(parts[1:], " ")
    
    switch command {
    case "HELO", "EHLO":
        return s.handleHelo(command, args)
    case "MAIL":
        return s.handleMail(args)
    case "RCPT":
        return s.handleRcpt(args)
    case "DATA":
        return s.handleData()
    case "RSET":
        return s.handleReset()
    case "NOOP":
        return s.writeLine(250, "OK")
    case "QUIT":
        s.state = StateQuit
        return s.writeLine(221, "Bye")
    default:
        return s.writeLine(502, "Command not implemented")
    }
}

func (s *Session) handleHelo(command, domain string) error {
    s.state = StateHelo
    
    if command == "EHLO" {
        // Send ESMTP capabilities
        s.writeLine(250, fmt.Sprintf("%s Hello %s", s.config.Hostname, domain))
        s.writeLine(250, "PIPELINING")
        s.writeLine(250, "SIZE 10485760")
        s.writeLine(250, "8BITMIME")
        return s.writeLine(250, "STARTTLS")
    }
    
    return s.writeLine(250, fmt.Sprintf("%s Hello %s", s.config.Hostname, domain))
}

func (s *Session) handleMail(args string) error {
    if s.state != StateHelo {
        return s.writeLine(503, "Bad sequence of commands")
    }
    
    if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
        return s.writeLine(501, "Syntax error")
    }
    
    from := extractEmail(args[5:])
    if from == "" {
        return s.writeLine(501, "Bad sender address")
    }
    
    s.from = from
    s.state = StateMail
    
    return s.writeLine(250, "Sender OK")
}

func (s *Session) handleRcpt(args string) error {
    if s.state != StateMail && s.state != StateRcpt {
        return s.writeLine(503, "Bad sequence of commands")
    }
    
    if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
        return s.writeLine(501, "Syntax error")
    }
    
    to := extractEmail(args[3:])
    if to == "" {
        return s.writeLine(501, "Bad recipient address")
    }
    
    s.to = append(s.to, to)
    s.state = StateRcpt
    
    return s.writeLine(250, "Recipient OK")
}

func (s *Session) handleData() error {
    if s.state != StateRcpt {
        return s.writeLine(503, "Bad sequence of commands")
    }
    
    if err := s.writeLine(354, "End data with <CR><LF>.<CR><LF>"); err != nil {
        return err
    }
    
    // Read message data
    data := make([]byte, 0)
    for {
        line, err := s.readLine()
        if err != nil {
            return err
        }
        
        if line == "." {
            break
        }
        
        // Handle dot-stuffing
        if strings.HasPrefix(line, "..") {
            line = line[1:]
        }
        
        data = append(data, []byte(line+"\r\n")...)
        
        // Check size limit
        if len(data) > s.config.MaxMessageSize {
            return s.writeLine(552, "Message too large")
        }
    }
    
    // Store the email
    email := &models.Email{
        ID:         uuid.New().String(),
        MessageID:  extractMessageID(data),
        From:       s.from,
        To:         s.to,
        Raw:        data,
        ReceivedAt: time.Now(),
        Size:       len(data),
    }
    
    if err := s.storage.Store(email); err != nil {
        s.logger.Errorf("Failed to store email: %v", err)
        return s.writeLine(451, "Failed to store message")
    }
    
    // Reset session state
    s.from = ""
    s.to = []string{}
    s.data = nil
    s.state = StateHelo
    
    return s.writeLine(250, "Message accepted")
}

func (s *Session) handleReset() error {
    s.from = ""
    s.to = []string{}
    s.data = nil
    s.state = StateHelo
    
    return s.writeLine(250, "Reset OK")
}

// Helper methods
func (s *Session) readLine() (string, error) {
    line, err := s.reader.ReadString('\n')
    if err != nil {
        return "", err
    }
    
    line = strings.TrimRight(line, "\r\n")
    s.logger.Debugf("C: %s", line)
    
    return line, nil
}

func (s *Session) writeLine(code int, message string) error {
    line := fmt.Sprintf("%d %s\r\n", code, message)
    s.logger.Debugf("S: %s", strings.TrimRight(line, "\r\n"))
    
    if _, err := s.writer.WriteString(line); err != nil {
        return err
    }
    
    return s.writer.Flush()
}

func extractEmail(s string) string {
    s = strings.TrimSpace(s)
    
    if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
        return s[1 : len(s)-1]
    }
    
    return s
}

func extractMessageID(data []byte) string {
    // Simple extraction - in production, use proper MIME parser
    lines := strings.Split(string(data), "\n")
    for _, line := range lines {
        if strings.HasPrefix(strings.ToLower(line), "message-id:") {
            return strings.TrimSpace(line[11:])
        }
    }
    return ""
}
```

## Week 2: Storage & Basic UI

### Day 6-7: Storage Implementation

**pkg/storage/interface.go**:
```go
package storage

import (
    "context"
    "time"

    "github.com/alexandria/pat-plugin/pkg/models"
)

type Backend interface {
    // Store saves an email
    Store(email *models.Email) error
    
    // Get retrieves an email by ID
    Get(id string) (*models.Email, error)
    
    // List returns emails matching the filter
    List(filter *Filter) ([]*models.Email, error)
    
    // Delete removes an email
    Delete(id string) error
    
    // DeleteAll removes all emails
    DeleteAll() error
    
    // Count returns the number of emails matching the filter
    Count(filter *Filter) (int64, error)
    
    // Search performs full-text search
    Search(query string, filter *Filter) ([]*models.Email, error)
    
    // Close closes the storage backend
    Close() error
}

type Filter struct {
    From      string
    To        string
    Subject   string
    Since     *time.Time
    Before    *time.Time
    Limit     int
    Offset    int
    SortBy    string
    SortOrder string
}

type Factory func(config map[string]interface{}) (Backend, error)

var backends = make(map[string]Factory)

func Register(name string, factory Factory) {
    backends[name] = factory
}

func Create(name string, config map[string]interface{}) (Backend, error) {
    factory, ok := backends[name]
    if !ok {
        return nil, fmt.Errorf("unknown storage backend: %s", name)
    }
    
    return factory(config)
}
```

**pkg/storage/memory.go**:
```go
package storage

import (
    "fmt"
    "sort"
    "strings"
    "sync"
    "time"

    "github.com/alexandria/pat-plugin/pkg/models"
)

func init() {
    Register("memory", NewMemoryBackend)
}

type MemoryBackend struct {
    mu       sync.RWMutex
    emails   map[string]*models.Email
    index    map[string][]string // field -> email IDs
    maxSize  int
}

func NewMemoryBackend(config map[string]interface{}) (Backend, error) {
    maxSize := 1000
    if v, ok := config["maxSize"].(int); ok {
        maxSize = v
    }
    
    return &MemoryBackend{
        emails:  make(map[string]*models.Email),
        index:   make(map[string][]string),
        maxSize: maxSize,
    }, nil
}

func (m *MemoryBackend) Store(email *models.Email) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // Check size limit
    if len(m.emails) >= m.maxSize {
        // Remove oldest email
        var oldest *models.Email
        for _, e := range m.emails {
            if oldest == nil || e.ReceivedAt.Before(oldest.ReceivedAt) {
                oldest = e
            }
        }
        if oldest != nil {
            delete(m.emails, oldest.ID)
            m.removeFromIndex(oldest)
        }
    }
    
    // Parse email content
    if err := email.Parse(); err != nil {
        return fmt.Errorf("failed to parse email: %w", err)
    }
    
    // Store email
    m.emails[email.ID] = email
    
    // Update indexes
    m.addToIndex(email)
    
    return nil
}

func (m *MemoryBackend) Get(id string) (*models.Email, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    email, ok := m.emails[id]
    if !ok {
        return nil, fmt.Errorf("email not found: %s", id)
    }
    
    return email, nil
}

func (m *MemoryBackend) List(filter *Filter) ([]*models.Email, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    // Collect matching emails
    var results []*models.Email
    
    for _, email := range m.emails {
        if m.matches(email, filter) {
            results = append(results, email)
        }
    }
    
    // Sort results
    m.sortEmails(results, filter.SortBy, filter.SortOrder)
    
    // Apply pagination
    start := filter.Offset
    if start > len(results) {
        start = len(results)
    }
    
    end := start + filter.Limit
    if end > len(results) || filter.Limit == 0 {
        end = len(results)
    }
    
    return results[start:end], nil
}

func (m *MemoryBackend) Delete(id string) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    email, ok := m.emails[id]
    if !ok {
        return fmt.Errorf("email not found: %s", id)
    }
    
    delete(m.emails, id)
    m.removeFromIndex(email)
    
    return nil
}

func (m *MemoryBackend) DeleteAll() error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    m.emails = make(map[string]*models.Email)
    m.index = make(map[string][]string)
    
    return nil
}

func (m *MemoryBackend) Count(filter *Filter) (int64, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    var count int64
    
    for _, email := range m.emails {
        if m.matches(email, filter) {
            count++
        }
    }
    
    return count, nil
}

func (m *MemoryBackend) Search(query string, filter *Filter) ([]*models.Email, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    query = strings.ToLower(query)
    var results []*models.Email
    
    for _, email := range m.emails {
        if m.matches(email, filter) && m.contains(email, query) {
            results = append(results, email)
        }
    }
    
    m.sortEmails(results, filter.SortBy, filter.SortOrder)
    
    return results, nil
}

func (m *MemoryBackend) Close() error {
    // Nothing to close for memory backend
    return nil
}

// Helper methods
func (m *MemoryBackend) matches(email *models.Email, filter *Filter) bool {
    if filter == nil {
        return true
    }
    
    if filter.From != "" && !strings.Contains(strings.ToLower(email.From), strings.ToLower(filter.From)) {
        return false
    }
    
    if filter.To != "" {
        found := false
        for _, to := range email.To {
            if strings.Contains(strings.ToLower(to), strings.ToLower(filter.To)) {
                found = true
                break
            }
        }
        if !found {
            return false
        }
    }
    
    if filter.Subject != "" && !strings.Contains(strings.ToLower(email.Subject), strings.ToLower(filter.Subject)) {
        return false
    }
    
    if filter.Since != nil && email.ReceivedAt.Before(*filter.Since) {
        return false
    }
    
    if filter.Before != nil && email.ReceivedAt.After(*filter.Before) {
        return false
    }
    
    return true
}

func (m *MemoryBackend) contains(email *models.Email, query string) bool {
    // Search in various fields
    fields := []string{
        email.From,
        email.Subject,
        email.Body.Text,
        email.Body.HTML,
    }
    
    fields = append(fields, email.To...)
    
    for _, field := range fields {
        if strings.Contains(strings.ToLower(field), query) {
            return true
        }
    }
    
    return false
}

func (m *MemoryBackend) sortEmails(emails []*models.Email, sortBy, sortOrder string) {
    if sortBy == "" {
        sortBy = "receivedAt"
    }
    
    if sortOrder == "" {
        sortOrder = "desc"
    }
    
    sort.Slice(emails, func(i, j int) bool {
        var less bool
        
        switch sortBy {
        case "from":
            less = emails[i].From < emails[j].From
        case "subject":
            less = emails[i].Subject < emails[j].Subject
        case "size":
            less = emails[i].Size < emails[j].Size
        default: // receivedAt
            less = emails[i].ReceivedAt.Before(emails[j].ReceivedAt)
        }
        
        if sortOrder == "desc" {
            return !less
        }
        return less
    })
}

func (m *MemoryBackend) addToIndex(email *models.Email) {
    // Index by from
    m.index["from:"+strings.ToLower(email.From)] = append(
        m.index["from:"+strings.ToLower(email.From)], 
        email.ID,
    )
    
    // Index by to
    for _, to := range email.To {
        m.index["to:"+strings.ToLower(to)] = append(
            m.index["to:"+strings.ToLower(to)], 
            email.ID,
        )
    }
    
    // Index by date
    dateKey := email.ReceivedAt.Format("2006-01-02")
    m.index["date:"+dateKey] = append(m.index["date:"+dateKey], email.ID)
}

func (m *MemoryBackend) removeFromIndex(email *models.Email) {
    // Remove from all indexes
    for key, ids := range m.index {
        filtered := make([]string, 0)
        for _, id := range ids {
            if id != email.ID {
                filtered = append(filtered, id)
            }
        }
        
        if len(filtered) == 0 {
            delete(m.index, key)
        } else {
            m.index[key] = filtered
        }
    }
}
```

### Day 8-10: Basic UI Components

**src/components/PatDashboard/index.tsx**:
```tsx
import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  IconButton,
  Toolbar,
  TextField,
  InputAdornment,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Search as SearchIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';
import { useAlexandria } from '@alexandria/plugin-sdk';
import { EmailList } from '../EmailList';
import { useEmails } from '../../hooks/useEmails';

export const PatDashboard: React.FC = () => {
  const { api, events, notifications } = useAlexandria();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEmails, setSelectedEmails] = useState<string[]>([]);
  
  const {
    emails,
    loading,
    error,
    refresh,
    deleteEmails,
    totalCount,
    page,
    setPage,
    pageSize,
    setPageSize,
  } = useEmails({ searchQuery });

  // Subscribe to email received events
  useEffect(() => {
    const unsubscribe = events.subscribe('pat:email:received', () => {
      refresh();
      notifications.show({
        message: 'New email received',
        severity: 'info',
      });
    });

    return () => unsubscribe();
  }, [events, refresh, notifications]);

  const handleDelete = async () => {
    if (selectedEmails.length === 0) return;

    try {
      await deleteEmails(selectedEmails);
      setSelectedEmails([]);
      notifications.show({
        message: `Deleted ${selectedEmails.length} email(s)`,
        severity: 'success',
      });
    } catch (error) {
      notifications.show({
        message: 'Failed to delete emails',
        severity: 'error',
      });
    }
  };

  const handleClearAll = async () => {
    if (!window.confirm('Are you sure you want to delete all emails?')) {
      return;
    }

    try {
      await api.mutation(`
        mutation ClearAllEmails {
          patClearAllEmails
        }
      `);
      refresh();
      notifications.show({
        message: 'All emails cleared',
        severity: 'success',
      });
    } catch (error) {
      notifications.show({
        message: 'Failed to clear emails',
        severity: 'error',
      });
    }
  };

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Paper sx={{ mb: 2 }}>
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            Email Testing
          </Typography>
          
          <TextField
            size="small"
            placeholder="Search emails..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            sx={{ mr: 2, width: 300 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
          />
          
          <IconButton onClick={refresh} disabled={loading}>
            <RefreshIcon />
          </IconButton>
          
          {selectedEmails.length > 0 && (
            <IconButton onClick={handleDelete} color="error">
              <DeleteIcon />
            </IconButton>
          )}
          
          <Button
            variant="outlined"
            size="small"
            onClick={handleClearAll}
            sx={{ ml: 1 }}
          >
            Clear All
          </Button>
        </Toolbar>
      </Paper>

      <Paper sx={{ flexGrow: 1, overflow: 'hidden' }}>
        <EmailList
          emails={emails}
          loading={loading}
          error={error}
          selectedEmails={selectedEmails}
          onSelectionChange={setSelectedEmails}
          totalCount={totalCount}
          page={page}
          onPageChange={setPage}
          pageSize={pageSize}
          onPageSizeChange={setPageSize}
        />
      </Paper>

      <Box sx={{ mt: 2, p: 2, bgcolor: 'background.paper' }}>
        <Typography variant="body2" color="text.secondary">
          SMTP Server: localhost:1025 | Total Emails: {totalCount}
        </Typography>
      </Box>
    </Box>
  );
};
```

**src/components/EmailList/index.tsx**:
```tsx
import React from 'react';
import {
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Checkbox,
  Typography,
  Chip,
  CircularProgress,
  Alert,
} from '@mui/material';
import { formatDistanceToNow } from 'date-fns';
import { useNavigate } from 'react-router-dom';
import { Email } from '../../types';

interface EmailListProps {
  emails: Email[];
  loading: boolean;
  error?: Error;
  selectedEmails: string[];
  onSelectionChange: (ids: string[]) => void;
  totalCount: number;
  page: number;
  onPageChange: (page: number) => void;
  pageSize: number;
  onPageSizeChange: (size: number) => void;
}

export const EmailList: React.FC<EmailListProps> = ({
  emails,
  loading,
  error,
  selectedEmails,
  onSelectionChange,
  totalCount,
  page,
  onPageChange,
  pageSize,
  onPageSizeChange,
}) => {
  const navigate = useNavigate();

  const handleSelectAll = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.checked) {
      onSelectionChange(emails.map(email => email.id));
    } else {
      onSelectionChange([]);
    }
  };

  const handleSelectOne = (id: string) => {
    const selectedIndex = selectedEmails.indexOf(id);
    let newSelected: string[] = [];

    if (selectedIndex === -1) {
      newSelected = [...selectedEmails, id];
    } else {
      newSelected = selectedEmails.filter(item => item !== id);
    }

    onSelectionChange(newSelected);
  };

  const handleRowClick = (id: string) => {
    navigate(`/pat/emails/${id}`);
  };

  if (loading && emails.length === 0) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 2 }}>
        <Alert severity="error">
          Failed to load emails: {error.message}
        </Alert>
      </Box>
    );
  }

  if (emails.length === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography variant="h6" color="text.secondary">
          No emails captured yet
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          Configure your application to send emails to localhost:1025
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <TableContainer sx={{ flexGrow: 1 }}>
        <Table stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell padding="checkbox">
                <Checkbox
                  indeterminate={
                    selectedEmails.length > 0 && 
                    selectedEmails.length < emails.length
                  }
                  checked={
                    emails.length > 0 && 
                    selectedEmails.length === emails.length
                  }
                  onChange={handleSelectAll}
                />
              </TableCell>
              <TableCell>From</TableCell>
              <TableCell>To</TableCell>
              <TableCell>Subject</TableCell>
              <TableCell>Size</TableCell>
              <TableCell>Received</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {emails.map((email) => {
              const isSelected = selectedEmails.includes(email.id);
              
              return (
                <TableRow
                  key={email.id}
                  hover
                  selected={isSelected}
                  onClick={() => handleRowClick(email.id)}
                  sx={{ cursor: 'pointer' }}
                >
                  <TableCell padding="checkbox">
                    <Checkbox
                      checked={isSelected}
                      onClick={(e) => e.stopPropagation()}
                      onChange={() => handleSelectOne(email.id)}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                      {email.from}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                      {email.to.slice(0, 2).map((to, index) => (
                        <Chip
                          key={index}
                          label={to}
                          size="small"
                          variant="outlined"
                        />
                      ))}
                      {email.to.length > 2 && (
                        <Chip
                          label={`+${email.to.length - 2}`}
                          size="small"
                          variant="outlined"
                        />
                      )}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" noWrap sx={{ maxWidth: 300 }}>
                      {email.subject || '(no subject)'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {formatBytes(email.size)}
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {formatDistanceToNow(new Date(email.receivedAt), { 
                        addSuffix: true 
                      })}
                    </Typography>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
      
      <TablePagination
        component="div"
        count={totalCount}
        page={page}
        onPageChange={(_, newPage) => onPageChange(newPage)}
        rowsPerPage={pageSize}
        onRowsPerPageChange={(e) => onPageSizeChange(parseInt(e.target.value))}
        rowsPerPageOptions={[10, 25, 50, 100]}
      />
    </Box>
  );
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}
```

## Week 3-4: Testing & Integration

### Testing Strategy

**tests/integration/smtp_test.go**:
```go
package integration

import (
    "net/smtp"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestSMTPServer(t *testing.T) {
    // Start test server
    server := startTestServer(t)
    defer server.Stop()

    // Give server time to start
    time.Sleep(100 * time.Millisecond)

    t.Run("Send Simple Email", func(t *testing.T) {
        // Connect to SMTP server
        c, err := smtp.Dial("localhost:1025")
        require.NoError(t, err)
        defer c.Close()

        // Send HELO
        err = c.Hello("test.example.com")
        assert.NoError(t, err)

        // Set sender
        err = c.Mail("sender@example.com")
        assert.NoError(t, err)

        // Set recipient
        err = c.Rcpt("recipient@example.com")
        assert.NoError(t, err)

        // Send data
        wc, err := c.Data()
        require.NoError(t, err)

        _, err = wc.Write([]byte("Subject: Test Email\r\n\r\nThis is a test email."))
        assert.NoError(t, err)

        err = wc.Close()
        assert.NoError(t, err)

        // Quit
        err = c.Quit()
        assert.NoError(t, err)

        // Verify email was stored
        emails, err := server.Storage.List(nil)
        require.NoError(t, err)
        assert.Len(t, emails, 1)
        assert.Equal(t, "sender@example.com", emails[0].From)
        assert.Equal(t, []string{"recipient@example.com"}, emails[0].To)
        assert.Equal(t, "Test Email", emails[0].Subject)
    })

    t.Run("Multiple Recipients", func(t *testing.T) {
        c, err := smtp.Dial("localhost:1025")
        require.NoError(t, err)
        defer c.Close()

        err = c.Hello("test.example.com")
        require.NoError(t, err)

        err = c.Mail("sender@example.com")
        require.NoError(t, err)

        // Multiple recipients
        recipients := []string{
            "user1@example.com",
            "user2@example.com",
            "user3@example.com",
        }

        for _, rcpt := range recipients {
            err = c.Rcpt(rcpt)
            require.NoError(t, err)
        }

        wc, err := c.Data()
        require.NoError(t, err)

        _, err = wc.Write([]byte("Subject: Multi Recipient Test\r\n\r\nTest"))
        require.NoError(t, err)

        err = wc.Close()
        require.NoError(t, err)

        err = c.Quit()
        require.NoError(t, err)

        // Verify
        emails, err := server.Storage.List(nil)
        require.NoError(t, err)
        
        found := false
        for _, email := range emails {
            if email.Subject == "Multi Recipient Test" {
                assert.Equal(t, recipients, email.To)
                found = true
                break
            }
        }
        assert.True(t, found, "Email with multiple recipients not found")
    })
}
```

**tests/e2e/plugin_test.ts**:
```typescript
import { test, expect } from '@playwright/test';
import { AlexandriaTestHelper } from '@alexandria/test-utils';

test.describe('Pat Plugin E2E Tests', () => {
  let alexandria: AlexandriaTestHelper;

  test.beforeAll(async () => {
    alexandria = new AlexandriaTestHelper();
    await alexandria.start();
    await alexandria.installPlugin('pat-plugin');
  });

  test.afterAll(async () => {
    await alexandria.stop();
  });

  test('should display Pat dashboard', async ({ page }) => {
    await alexandria.login(page);
    await page.goto('/pat');

    await expect(page.locator('h6:has-text("Email Testing")')).toBeVisible();
    await expect(page.locator('text=SMTP Server: localhost:1025')).toBeVisible();
  });

  test('should capture and display email', async ({ page }) => {
    // Send test email
    await alexandria.sendEmail({
      from: 'test@example.com',
      to: ['recipient@example.com'],
      subject: 'E2E Test Email',
      body: 'This is a test email for E2E testing',
    });

    // Navigate to Pat dashboard
    await page.goto('/pat');

    // Wait for email to appear
    await expect(page.locator('text=test@example.com')).toBeVisible();
    await expect(page.locator('text=E2E Test Email')).toBeVisible();

    // Click on email to view details
    await page.click('text=E2E Test Email');

    // Verify email detail view
    await expect(page.locator('h4:has-text("E2E Test Email")')).toBeVisible();
    await expect(page.locator('text=This is a test email for E2E testing')).toBeVisible();
  });

  test('should delete email', async ({ page }) => {
    // Send test email
    await alexandria.sendEmail({
      from: 'delete@example.com',
      to: ['recipient@example.com'],
      subject: 'Delete Test',
      body: 'This email will be deleted',
    });

    await page.goto('/pat');

    // Select email
    const row = page.locator('tr:has-text("Delete Test")');
    await row.locator('input[type="checkbox"]').check();

    // Click delete button
    await page.click('button[aria-label="delete"]');

    // Confirm deletion
    await expect(page.locator('text=Deleted 1 email(s)')).toBeVisible();
    await expect(page.locator('text=Delete Test')).not.toBeVisible();
  });

  test('should search emails', async ({ page }) => {
    // Send multiple test emails
    await alexandria.sendEmail({
      from: 'search1@example.com',
      to: ['recipient@example.com'],
      subject: 'Important Meeting',
      body: 'Meeting details',
    });

    await alexandria.sendEmail({
      from: 'search2@example.com',
      to: ['recipient@example.com'],
      subject: 'Project Update',
      body: 'Project status',
    });

    await page.goto('/pat');

    // Search for "meeting"
    await page.fill('input[placeholder="Search emails..."]', 'meeting');
    await page.keyboard.press('Enter');

    // Verify search results
    await expect(page.locator('text=Important Meeting')).toBeVisible();
    await expect(page.locator('text=Project Update')).not.toBeVisible();
  });
});
```

## Deliverables Checklist

### Week 1 Deliverables
- [x] Plugin directory structure created
- [x] Plugin manifest (plugin.json) configured
- [x] TypeScript/React build pipeline set up
- [x] Go module initialized with dependencies
- [x] Plugin lifecycle implementation complete
- [x] Basic SMTP server functional
- [x] Memory storage implementation
- [x] Minimal UI displaying email list

### Week 2 Deliverables
- [ ] MongoDB storage backend
- [ ] PostgreSQL storage backend
- [ ] Storage backend configuration UI
- [ ] Enhanced email viewer with HTML rendering
- [ ] REST API endpoints
- [ ] GraphQL schema extensions
- [ ] Search and filter functionality

### Week 3 Deliverables
- [ ] Unit tests (80% coverage)
- [ ] Integration tests for SMTP
- [ ] E2E tests for UI flows
- [ ] Performance benchmarks
- [ ] Security audit

### Week 4 Deliverables
- [ ] Documentation complete
- [ ] CI/CD pipeline configured
- [ ] Release build process
- [ ] Deployment guide
- [ ] Demo video recorded

## Next Steps

After completing EPIC 1, the team should:

1. **Code Review**: Conduct thorough review of all code
2. **Security Audit**: Ensure plugin follows Alexandria security guidelines
3. **Performance Testing**: Verify SMTP server can handle load
4. **User Testing**: Get feedback from potential users
5. **Plan EPIC 2**: Refine requirements based on learnings

## Success Criteria

EPIC 1 is considered complete when:

1. ✅ Plugin installs and activates in Alexandria without errors
2. ✅ SMTP server accepts emails on port 1025
3. ✅ Emails are stored and retrievable via UI
4. ✅ Basic email list and detail views are functional
5. ✅ Memory storage handles 1000+ emails efficiently
6. ✅ All tests pass with >80% coverage
7. ✅ Documentation is complete and accurate
8. ✅ Plugin can be packaged and distributed

---

This implementation guide provides a solid foundation for building the Pat plugin. The modular architecture ensures easy extension in future EPICs while maintaining compatibility with Alexandria's plugin system.