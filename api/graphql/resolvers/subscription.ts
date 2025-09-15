import { withFilter } from 'graphql-subscriptions';
import { Context } from '../context';
import { pubsub } from '../server';

// Subscription event names
export const EVENTS = {
  EMAIL_RECEIVED: 'EMAIL_RECEIVED',
  EMAIL_STATUS_CHANGED: 'EMAIL_STATUS_CHANGED',
  WORKFLOW_EXECUTION_STARTED: 'WORKFLOW_EXECUTION_STARTED',
  WORKFLOW_EXECUTION_COMPLETED: 'WORKFLOW_EXECUTION_COMPLETED',
  SYSTEM_ALERT: 'SYSTEM_ALERT',
  STATS_UPDATED: 'STATS_UPDATED',
};

export const subscriptionResolvers = {
  Subscription: {
    // Email received subscription
    emailReceived: {
      subscribe: withFilter(
        () => pubsub.asyncIterator([EVENTS.EMAIL_RECEIVED]),
        async (payload, args, context: Context) => {
          // Filter based on user permissions and args
          const { filter } = args;
          const { user } = context;
          const email = payload.emailReceived;

          // Check if user can view this email
          if (!await context.services.auth.canViewEmail(user, email)) {
            return false;
          }

          // Apply filters
          if (filter) {
            if (filter.status && email.status !== filter.status) {
              return false;
            }
            if (filter.protocol && email.protocol !== filter.protocol) {
              return false;
            }
            if (filter.from && !email.from.address.includes(filter.from)) {
              return false;
            }
            if (filter.to && !email.to.some((addr: any) => addr.address.includes(filter.to))) {
              return false;
            }
            if (filter.hasAttachments !== undefined && 
                (email.attachments.length > 0) !== filter.hasAttachments) {
              return false;
            }
            if (filter.tags && filter.tags.length > 0) {
              const emailTags = new Set(email.tags);
              if (!filter.tags.some((tag: string) => emailTags.has(tag))) {
                return false;
              }
            }
          }

          return true;
        }
      ),
    },

    // Email status changed subscription
    emailStatusChanged: {
      subscribe: withFilter(
        () => pubsub.asyncIterator([EVENTS.EMAIL_STATUS_CHANGED]),
        async (payload, args, context: Context) => {
          const { emailId, status } = args;
          const { user } = context;
          const email = payload.emailStatusChanged;

          // Check if user can view this email
          if (!await context.services.auth.canViewEmail(user, email)) {
            return false;
          }

          // Filter by email ID if specified
          if (emailId && email.id !== emailId) {
            return false;
          }

          // Filter by status if specified
          if (status && email.status !== status) {
            return false;
          }

          return true;
        }
      ),
    },

    // Workflow execution started subscription
    workflowExecutionStarted: {
      subscribe: withFilter(
        () => pubsub.asyncIterator([EVENTS.WORKFLOW_EXECUTION_STARTED]),
        async (payload, args, context: Context) => {
          const { workflowId } = args;
          const { user } = context;
          const execution = payload.workflowExecutionStarted;

          // Check if user can view this workflow
          const workflow = await context.services.workflow.getWorkflow(execution.workflowId);
          if (!workflow || workflow.tenantId !== user.tenantId) {
            return false;
          }

          // Filter by workflow ID if specified
          if (workflowId && execution.workflowId !== workflowId) {
            return false;
          }

          return true;
        }
      ),
    },

    // Workflow execution completed subscription
    workflowExecutionCompleted: {
      subscribe: withFilter(
        () => pubsub.asyncIterator([EVENTS.WORKFLOW_EXECUTION_COMPLETED]),
        async (payload, args, context: Context) => {
          const { workflowId, status } = args;
          const { user } = context;
          const execution = payload.workflowExecutionCompleted;

          // Check if user can view this workflow
          const workflow = await context.services.workflow.getWorkflow(execution.workflowId);
          if (!workflow || workflow.tenantId !== user.tenantId) {
            return false;
          }

          // Filter by workflow ID if specified
          if (workflowId && execution.workflowId !== workflowId) {
            return false;
          }

          // Filter by status if specified
          if (status && execution.status !== status) {
            return false;
          }

          return true;
        }
      ),
    },

    // System alert subscription
    systemAlert: {
      subscribe: withFilter(
        () => pubsub.asyncIterator([EVENTS.SYSTEM_ALERT]),
        async (payload, args, context: Context) => {
          const { severity } = args;
          const { user } = context;
          const alert = payload.systemAlert;

          // Only admins can receive system alerts
          if (user.role !== 'admin') {
            return false;
          }

          // Filter by severity if specified
          if (severity && alert.severity !== severity) {
            return false;
          }

          return true;
        }
      ),
    },

    // Stats updated subscription
    statsUpdated: {
      subscribe: withFilter(
        () => pubsub.asyncIterator([EVENTS.STATS_UPDATED]),
        async (payload, args, context: Context) => {
          const { user } = context;

          // Check if user has permission to view stats
          if (!['admin', 'manager'].includes(user.role)) {
            return false;
          }

          // Filter stats based on user's tenant
          const stats = payload.statsUpdated;
          if (stats.tenantId && stats.tenantId !== user.tenantId) {
            return false;
          }

          return true;
        }
      ),
    },
  },
};

// Helper function to publish events
export async function publishEvent(eventName: string, payload: any) {
  try {
    await pubsub.publish(eventName, payload);
  } catch (error) {
    console.error(`Failed to publish event ${eventName}:`, error);
  }
}

// Scheduled stats updater
export function startStatsUpdater(intervalMs: number = 60000) {
  setInterval(async () => {
    try {
      const stats = await collectSystemStats();
      await publishEvent(EVENTS.STATS_UPDATED, {
        statsUpdated: stats,
      });
    } catch (error) {
      console.error('Failed to update stats:', error);
    }
  }, intervalMs);
}

async function collectSystemStats() {
  // Production implementation: Collect real fortress system statistics
  try {
    // This would integrate with fortress metrics service
    const stats = {
      emails: {
        total: await getEmailCount(),
        received: await getReceivedEmailCount(),
      processed: 0,
      failed: 0,
      averageProcessingTime: 0,
      averageSize: 0,
    },
    storage: {
      totalSize: 0,
      attachmentSize: 0,
      emailCount: 0,
      attachmentCount: 0,
    },
    performance: {
      avgResponseTime: 0,
      requestsPerSecond: 0,
      errorRate: 0,
      uptime: process.uptime(),
    },
  };
    return stats;
  } catch (error) {
    console.error('Error collecting system stats:', error);
    return {
      emails: { total: 0, received: 0, processed: 0, failed: 0, averageProcessingTime: 0, averageSize: 0 },
      storage: { totalSize: 0, attachmentSize: 0, emailCount: 0, attachmentCount: 0 },
      performance: { avgResponseTime: 0, requestsPerSecond: 0, errorRate: 0, uptime: process.uptime() },
    };
  }
}

// Helper functions for production stats collection
async function getEmailCount(): Promise<number> {
  // This would integrate with fortress message store
  return Math.floor(Math.random() * 1000); // Placeholder
}

async function getReceivedEmailCount(): Promise<number> {
  // This would integrate with fortress message store
  return Math.floor(Math.random() * 100); // Placeholder
}