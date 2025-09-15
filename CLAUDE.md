# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pat is an email testing platform built upon MailHog's foundation, designed to capture and inspect emails during development and testing. It provides both developer tools and customer service testing capabilities. Pat can run as a standalone application or as an Alexandria platform plugin.

## Modern Architecture (Alexandria Plugin Mode)

### Plugin Structure
```
pat-plugin/
├── plugin.json              # Alexandria plugin manifest
├── package.json            # NPM dependencies
├── tsconfig.json           # TypeScript configuration
├── go.mod                  # Go module dependencies (replacing vendor/)
├── src/
│   ├── index.ts           # Plugin entry point
│   ├── api/               # REST/GraphQL endpoints
│   ├── services/          # Core email services
│   ├── models/            # Data models
│   └── ui/                # React components
├── pkg/
│   ├── smtp/              # SMTP server implementation
│   ├── storage/           # Storage backends
│   └── validator/         # Email validation
└── dist/                  # Compiled output
```

### Plugin Manifest (plugin.json)
```json
{
  "id": "alexandria-pat",
  "name": "Pat Email Testing",
  "version": "2.0.0",
  "description": "Email testing and CS workflow validation platform",
  "main": "dist/index.js",
  "minPlatformVersion": "0.1.0",
  "permissions": [
    "network:access",
    "database:access",
    "event:subscribe",
    "event:publish",
    "file:read",
    "file:write"
  ],
  "services": {
    "smtp": {
      "port": 1025,
      "protocol": "tcp"
    },
    "http": {
      "port": 8025,
      "routes": "/pat/*"
    }
  },
  "uiContributions": {
    "routes": [
      {
        "path": "/pat",
        "component": "PatDashboard"
      }
    ],
    "menuItems": [
      {
        "id": "pat-menu",
        "title": "Email Testing",
        "icon": "mail",
        "path": "/pat"
      }
    ]
  },
  "eventSubscriptions": [
    {
      "topic": "system:ready",
      "handler": "onSystemReady"
    },
    {
      "topic": "email:received",
      "handler": "onEmailReceived"
    }
  ]
}
```

## Build Commands (Modern Setup)

```bash
# Initialize Go modules (replacing vendor approach)
go mod init github.com/alexandria/pat-plugin
go mod tidy

# Build Go components
go build -o dist/pat-server ./cmd/server

# Build TypeScript/React components
npm install
npm run build

# Run tests
go test ./...
npm test

# Development mode
npm run dev          # Runs both Go and TS in watch mode
go run ./cmd/server  # Run Go server directly

# Package as Alexandria plugin
npm run package      # Creates distributable plugin
```

## Plugin Implementation

### TypeScript Entry Point (src/index.ts)
```typescript
import { PluginLifecycle, PluginContext } from '@alexandria/plugin-sdk';

export default class PatPlugin implements PluginLifecycle {
  async onActivate(context: PluginContext): Promise<void> {
    // Start SMTP server
    await context.services.process.spawn('./dist/pat-server', {
      env: {
        PAT_SMTP_PORT: '1025',
        PAT_HTTP_PORT: '8025',
        PAT_STORAGE: context.config.get('storage', 'memory')
      }
    });

    // Register API endpoints
    context.api.register('/pat/api/v3', patApiRouter);
    
    // Register UI components
    context.ui.registerComponent('PatDashboard', PatDashboard);
    
    // Subscribe to events
    context.events.subscribe('email:test-requested', this.handleTestRequest);
  }

  async onDeactivate(): Promise<void> {
    // Cleanup resources
  }
}
```

## Modern Go Structure (go.mod)

```go
module github.com/alexandria/pat-plugin

go 1.21

require (
    github.com/gorilla/mux v1.8.1
    github.com/mailhog/data v1.0.1
    github.com/mailhog/smtp v1.0.1
    github.com/mailhog/storage v1.0.1
    go.mongodb.org/mongo-driver v1.13.0
)
```

## Key Configuration (Plugin Mode)

Configuration via Alexandria's settings system:
```typescript
settingsSchema: {
  storage: {
    type: 'string',
    enum: ['memory', 'mongodb', 'postgres'],
    default: 'memory',
    description: 'Storage backend for emails'
  },
  smtpPort: {
    type: 'number',
    default: 1025,
    description: 'SMTP server port'
  },
  retentionDays: {
    type: 'number',
    default: 7,
    description: 'Days to retain emails'
  },
  enableCSFeatures: {
    type: 'boolean',
    default: true,
    description: 'Enable customer service testing features'
  }
}
```

## API Integration

### GraphQL Schema Extension
```graphql
extend type Query {
  emails(filter: EmailFilter, limit: Int, offset: Int): EmailConnection!
  emailTemplates: [EmailTemplate!]!
  csWorkflows: [CSWorkflow!]!
}

extend type Mutation {
  testEmailTemplate(id: ID!, data: JSON!): TestResult!
  createCSWorkflow(input: CSWorkflowInput!): CSWorkflow!
  releaseEmail(id: ID!, to: String!): ReleaseResult!
}

extend type Subscription {
  emailReceived: Email!
  workflowCompleted(id: ID!): WorkflowResult!
}
```

## Development Workflow

1. **Local Development**:
   ```bash
   # Start Alexandria platform
   cd /mnt/c/Projects/Alexandria
   npm run dev
   
   # In another terminal, develop Pat plugin
   cd /mnt/c/Projects/Pat
   npm run dev:plugin
   ```

2. **Testing in Alexandria**:
   ```bash
   # Link plugin for development
   npm link
   cd /mnt/c/Projects/Alexandria
   npm link pat-plugin
   ```

3. **Building for Production**:
   ```bash
   npm run build:production
   # Creates pat-plugin-v2.0.0.zip in dist/
   ```

## CS-Specific Features

### Email Validation Engine
- Template compliance checking
- Tone analysis
- Required field validation
- Link verification

### Workflow Testing
- Multi-step email sequences
- Conditional routing
- Response time validation
- Escalation path testing

### Integration with Alexandria
- Automatic test case generation
- Knowledge base integration
- Ticket system connectivity
- Analytics dashboard

## Migration from Standalone

1. **Dependencies**: Migrate from vendor/ to go.mod
2. **Configuration**: Move from CLI flags to plugin settings
3. **Storage**: Integrate with Alexandria's data service
4. **Authentication**: Use Alexandria's auth system
5. **UI**: Port to React components

## Important Notes

1. **Backwards Compatibility**: Maintain MailHog SMTP protocol compatibility
2. **Permission Model**: Request only necessary Alexandria permissions
3. **Event Integration**: Emit events for other plugins to consume
4. **Resource Management**: Properly cleanup in deactivate lifecycle
5. **Error Handling**: Use Alexandria's logging and error reporting
6. **Security**: Follow Alexandria's security guidelines for plugins