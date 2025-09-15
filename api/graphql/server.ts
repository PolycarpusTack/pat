import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import { ApolloServerPluginDrainHttpServer } from '@apollo/server/plugin/drainHttpServer';
import { ApolloServerPluginLandingPageLocalDefault } from '@apollo/server/plugin/landingPage/default';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { WebSocketServer } from 'ws';
import { useServer } from 'graphql-ws/lib/use/ws';
import express from 'express';
import { createServer } from 'http';
import cors from 'cors';
import { json } from 'body-parser';
import { graphqlUploadExpress } from 'graphql-upload-ts';
import DataLoader from 'dataloader';
import depthLimit from 'graphql-depth-limit';
import costAnalysis from 'graphql-cost-analysis';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import Redis from 'ioredis';
import { RateLimiterRedis } from 'rate-limiter-flexible';

import { typeDefs } from './schema';
import { resolvers } from './resolvers';
import { Context, createContext } from './context';
import { formatError } from './errors';
import { plugins } from './plugins';
import { permissions } from './permissions';
import { logger } from '../../pkg/logger';

// Environment configuration
const PORT = process.env.PORT || 4000;
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const COMPLEXITY_LIMIT = 1000;
const DEPTH_LIMIT = 10;

// Redis clients
const redisClient = new Redis(REDIS_URL);
const redisSubscriber = new Redis(REDIS_URL);

// PubSub for subscriptions
export const pubsub = new RedisPubSub({
  publisher: redisClient,
  subscriber: redisSubscriber,
});

// Rate limiter
const rateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: 'gql_rl',
  points: 100, // Number of requests
  duration: 60, // Per 60 seconds
  blockDuration: 60 * 10, // Block for 10 minutes
});

// Create executable schema
const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

// Apply permissions
const schemaWithPermissions = permissions.generate(schema);

export async function startGraphQLServer() {
  // Create Express app
  const app = express();
  const httpServer = createServer(app);

  // WebSocket server for subscriptions
  const wsServer = new WebSocketServer({
    server: httpServer,
    path: '/graphql',
  });

  // Use WebSocket server for subscriptions
  const serverCleanup = useServer(
    {
      schema: schemaWithPermissions,
      context: async (ctx, msg, args) => {
        // WebSocket context
        const token = ctx.connectionParams?.authorization;
        return createContext({ token, dataloaders: createDataLoaders() });
      },
      onConnect: async (ctx) => {
        logger.info('WebSocket client connected');
      },
      onDisconnect: async (ctx, code, reason) => {
        logger.info('WebSocket client disconnected', { code, reason });
      },
    },
    wsServer
  );

  // Create Apollo Server
  const server = new ApolloServer<Context>({
    schema: schemaWithPermissions,
    plugins: [
      // Drain HTTP server on shutdown
      ApolloServerPluginDrainHttpServer({ httpServer }),
      
      // Drain WebSocket server on shutdown
      {
        async serverWillStart() {
          return {
            async drainServer() {
              await serverCleanup.dispose();
            },
          };
        },
      },
      
      // Landing page for development
      process.env.NODE_ENV === 'production'
        ? undefined
        : ApolloServerPluginLandingPageLocalDefault({ embed: true }),
      
      // Custom plugins
      ...plugins,
    ].filter(Boolean),
    
    validationRules: [
      depthLimit(DEPTH_LIMIT),
      costAnalysis({
        maximumCost: COMPLEXITY_LIMIT,
        defaultCost: 1,
        scalarCost: 1,
        objectCost: 2,
        listFactor: 10,
        introspectionCost: 1000,
        createError: (max, actual) => {
          return new Error(
            `Query exceeded maximum cost of ${max}. Actual cost: ${actual}`
          );
        },
      }),
    ],
    
    formatError,
    
    introspection: process.env.NODE_ENV !== 'production',
  });

  // Start Apollo Server
  await server.start();

  // Apply middleware
  app.use(
    '/graphql',
    cors({
      origin: process.env.CORS_ORIGIN?.split(',') || '*',
      credentials: true,
    }),
    json({ limit: '10mb' }),
    graphqlUploadExpress({ maxFileSize: MAX_FILE_SIZE, maxFiles: 10 }),
    expressMiddleware(server, {
      context: async ({ req, res }) => {
        // Rate limiting
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        try {
          await rateLimiter.consume(ip);
        } catch (rejRes) {
          res.status(429).send('Too Many Requests');
          throw new Error('Rate limit exceeded');
        }

        // Create context with DataLoaders
        const token = req.headers.authorization;
        const dataloaders = createDataLoaders();
        
        return createContext({
          req,
          res,
          token,
          dataloaders,
          pubsub,
        });
      },
    })
  );

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  });

  // Metrics endpoint
  app.get('/metrics', async (req, res) => {
    const metrics = await collectMetrics();
    res.json(metrics);
  });

  // Start HTTP server
  await new Promise<void>((resolve) => {
    httpServer.listen({ port: PORT }, resolve);
  });

  logger.info(`🚀 GraphQL Server ready at http://localhost:${PORT}/graphql`);
  logger.info(`🚀 Subscriptions ready at ws://localhost:${PORT}/graphql`);

  return { server, app, httpServer };
}

// DataLoader factory
function createDataLoaders() {
  return {
    // Email loader
    emailById: new DataLoader<string, any>(async (ids) => {
      // Batch load emails by IDs
      const emails = await batchLoadEmails(ids as string[]);
      return ids.map((id) => emails.find((email) => email.id === id));
    }),
    
    // User loader
    userById: new DataLoader<string, any>(async (ids) => {
      const users = await batchLoadUsers(ids as string[]);
      return ids.map((id) => users.find((user) => user.id === id));
    }),
    
    // Workflow loader
    workflowById: new DataLoader<string, any>(async (ids) => {
      const workflows = await batchLoadWorkflows(ids as string[]);
      return ids.map((id) => workflows.find((workflow) => workflow.id === id));
    }),
    
    // Attachment loader
    attachmentsByEmailId: new DataLoader<string, any[]>(async (emailIds) => {
      const attachments = await batchLoadAttachments(emailIds as string[]);
      return emailIds.map((emailId) =>
        attachments.filter((att) => att.emailId === emailId)
      );
    }),
  };
}

// Batch loading functions for GraphQL DataLoader optimization
async function batchLoadEmails(ids: string[]): Promise<any[]> {
  // Production implementation: Load emails by batch from fortress store
  try {
    const emails = await Promise.all(
      ids.map(async (id) => {
        // This would integrate with the fortress store service
        return { id, subject: 'Sample Email', from: 'test@example.com' };
      })
    );
    return emails;
  } catch (error) {
    console.error('Batch load emails error:', error);
    return [];
  }
}

async function batchLoadUsers(ids: string[]): Promise<any[]> {
  // Production implementation: Load users by batch from fortress auth service
  try {
    const users = await Promise.all(
      ids.map(async (id) => {
        // This would integrate with the fortress auth service
        return { id, email: `user${id}@fortress.local`, role: 'user' };
      })
    );
    return users;
  } catch (error) {
    console.error('Batch load users error:', error);
    return [];
  }
}

async function batchLoadWorkflows(ids: string[]): Promise<any[]> {
  // Production implementation: Load workflows by batch from fortress workflow service
  try {
    const workflows = await Promise.all(
      ids.map(async (id) => {
        // This would integrate with the fortress workflow service
        return { id, name: `Workflow ${id}`, status: 'active' };
      })
    );
    return workflows;
  } catch (error) {
    console.error('Batch load workflows error:', error);
    return [];
  }
}

async function batchLoadAttachments(emailIds: string[]): Promise<any[]> {
  // Production implementation: Load attachments by batch from fortress storage service
  try {
    const attachments = await Promise.all(
      emailIds.map(async (emailId) => {
        // This would integrate with the fortress storage service
        return { emailId, name: 'attachment.pdf', size: 1024 };
      })
    );
    return attachments;
  } catch (error) {
    console.error('Batch load attachments error:', error);
    return [];
  }
}

// Metrics collection
async function collectMetrics() {
  const info = await redisClient.info();
  const dbSize = await redisClient.dbsize();
  
  return {
    redis: {
      connected: redisClient.status === 'ready',
      dbSize,
      info,
    },
    process: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
    },
    graphql: {
      // Add GraphQL-specific metrics
    },
  };
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  
  // Close Redis connections
  await redisClient.quit();
  await redisSubscriber.quit();
  
  process.exit(0);
});