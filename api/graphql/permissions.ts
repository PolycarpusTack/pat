import { shield, rule, allow, deny, and, or } from 'graphql-shield';
import { Context } from './context';
import { ForbiddenError, AuthenticationError } from './errors';

// Rule definitions
const isAuthenticated = rule({ cache: 'contextual' })(
  async (parent, args, ctx: Context) => {
    return ctx.user.id !== 'anonymous';
  }
);

const isAdmin = rule({ cache: 'contextual' })(
  async (parent, args, ctx: Context) => {
    return ctx.user.role === 'admin';
  }
);

const isManager = rule({ cache: 'contextual' })(
  async (parent, args, ctx: Context) => {
    return ctx.user.role === 'manager' || ctx.user.role === 'admin';
  }
);

const isOwner = rule({ cache: 'strict' })(
  async (parent, args, ctx: Context) => {
    // Check if user owns the resource
    if (parent.userId === ctx.user.id) return true;
    if (parent.createdBy === ctx.user.id) return true;
    if (parent.tenantId === ctx.user.tenantId) return true;
    return false;
  }
);

const canViewEmail = rule({ cache: 'strict' })(
  async (parent, args, ctx: Context) => {
    // Admin can view all emails
    if (ctx.user.role === 'admin') return true;
    
    // Users can view emails in their tenant
    const email = parent || await ctx.services.email.getEmail(args.id);
    return email && email.tenantId === ctx.user.tenantId;
  }
);

const canManageWorkflows = rule({ cache: 'contextual' })(
  async (parent, args, ctx: Context) => {
    return ['admin', 'manager'].includes(ctx.user.role);
  }
);

const canManagePlugins = rule({ cache: 'contextual' })(
  async (parent, args, ctx: Context) => {
    return ctx.user.role === 'admin';
  }
);

const canManageWebhooks = rule({ cache: 'contextual' })(
  async (parent, args, ctx: Context) => {
    return ['admin', 'developer'].includes(ctx.user.role);
  }
);

const canManageTemplates = rule({ cache: 'contextual' })(
  async (parent, args, ctx: Context) => {
    return ['admin', 'manager', 'developer'].includes(ctx.user.role);
  }
);

const canViewStats = rule({ cache: 'contextual' })(
  async (parent, args, ctx: Context) => {
    return ['admin', 'manager'].includes(ctx.user.role);
  }
);

// Permission schema
export const permissions = shield(
  {
    Query: {
      // Email queries
      email: and(isAuthenticated, canViewEmail),
      emails: isAuthenticated,
      emailSearch: isAuthenticated,
      emailConversation: isAuthenticated,
      
      // Workflow queries
      workflow: and(isAuthenticated, canManageWorkflows),
      workflows: and(isAuthenticated, canManageWorkflows),
      workflowExecutions: and(isAuthenticated, canManageWorkflows),
      
      // Plugin queries
      plugin: and(isAuthenticated, canManagePlugins),
      plugins: and(isAuthenticated, canManagePlugins),
      
      // Template queries
      template: isAuthenticated,
      templates: isAuthenticated,
      
      // User queries
      me: isAuthenticated,
      user: isManager,
      users: isAdmin,
      
      // Webhook queries
      webhookEndpoint: and(isAuthenticated, canManageWebhooks),
      webhookEndpoints: and(isAuthenticated, canManageWebhooks),
      
      // Stats queries
      systemStats: and(isAuthenticated, canViewStats),
      
      // API Key queries
      apiKey: isAuthenticated,
      apiKeys: isAuthenticated,
    },
    
    Mutation: {
      // Email mutations
      createEmail: isAuthenticated,
      updateEmail: and(isAuthenticated, canViewEmail),
      deleteEmail: and(isAuthenticated, or(isAdmin, isOwner)),
      tagEmail: and(isAuthenticated, canViewEmail),
      untagEmail: and(isAuthenticated, canViewEmail),
      markEmailAsSpam: isAuthenticated,
      markEmailAsNotSpam: isAuthenticated,
      resendEmail: and(isAuthenticated, canViewEmail),
      forwardEmail: and(isAuthenticated, canViewEmail),
      
      // Workflow mutations
      createWorkflow: and(isAuthenticated, canManageWorkflows),
      updateWorkflow: and(isAuthenticated, canManageWorkflows),
      deleteWorkflow: and(isAuthenticated, canManageWorkflows),
      executeWorkflow: and(isAuthenticated, canManageWorkflows),
      cancelWorkflowExecution: and(isAuthenticated, canManageWorkflows),
      
      // Plugin mutations
      installPlugin: and(isAuthenticated, canManagePlugins),
      updatePluginConfig: and(isAuthenticated, canManagePlugins),
      activatePlugin: and(isAuthenticated, canManagePlugins),
      deactivatePlugin: and(isAuthenticated, canManagePlugins),
      uninstallPlugin: and(isAuthenticated, canManagePlugins),
      
      // Template mutations
      createTemplate: and(isAuthenticated, canManageTemplates),
      updateTemplate: and(isAuthenticated, canManageTemplates),
      deleteTemplate: and(isAuthenticated, canManageTemplates),
      sendTemplatedEmail: isAuthenticated,
      
      // Webhook mutations
      createWebhookEndpoint: and(isAuthenticated, canManageWebhooks),
      updateWebhookEndpoint: and(isAuthenticated, canManageWebhooks),
      deleteWebhookEndpoint: and(isAuthenticated, canManageWebhooks),
      testWebhookEndpoint: and(isAuthenticated, canManageWebhooks),
      
      // User mutations
      updateProfile: isAuthenticated,
      
      // API Key mutations
      createApiKey: isAuthenticated,
      revokeApiKey: isAuthenticated,
    },
    
    Subscription: {
      // All subscriptions require authentication
      emailReceived: isAuthenticated,
      emailStatusChanged: isAuthenticated,
      workflowExecutionStarted: and(isAuthenticated, canManageWorkflows),
      workflowExecutionCompleted: and(isAuthenticated, canManageWorkflows),
      systemAlert: and(isAuthenticated, isAdmin),
      statsUpdated: and(isAuthenticated, canViewStats),
    },
    
    // Type-level permissions
    Email: {
      // Sensitive fields
      headers: or(isAdmin, isOwner),
      rawEmail: or(isAdmin, isOwner),
      metadata: or(isAdmin, isManager),
    },
    
    User: {
      // Only admins can see user details
      email: or(isAdmin, isOwner),
      settings: or(isAdmin, isOwner),
      lastLoginAt: or(isAdmin, isOwner),
    },
    
    ApiKey: {
      // Hide sensitive key data
      secretKey: deny,
    },
  },
  {
    fallbackRule: allow,
    fallbackError: async (thrownError, parent, args, context: Context, info) => {
      if (thrownError instanceof AuthenticationError) {
        return thrownError;
      }
      if (thrownError instanceof ForbiddenError) {
        return thrownError;
      }
      if (context.user.id === 'anonymous') {
        return new AuthenticationError('Authentication required');
      }
      return new ForbiddenError('Access denied');
    },
    debug: process.env.NODE_ENV !== 'production',
  }
);