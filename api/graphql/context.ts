import { Request, Response } from 'express';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import DataLoader from 'dataloader';
import { verify } from 'jsonwebtoken';

import { EmailService } from '../../services/email';
import { WorkflowService } from '../../services/workflow';
import { PluginService } from '../../services/plugin';
import { TemplateService } from '../../services/template';
import { UserService } from '../../services/user';
import { WebhookService } from '../../services/webhook';
import { AuthService } from '../../services/auth';
import { StorageService } from '../../services/storage';
import { SpamService } from '../../services/spam';
import { StatsService } from '../../services/stats';
import { logger } from '../../pkg/logger';

export interface User {
  id: string;
  tenantId: string;
  email: string;
  name: string;
  role: string;
}

export interface Services {
  email: EmailService;
  workflow: WorkflowService;
  plugin: PluginService;
  template: TemplateService;
  user: UserService;
  webhook: WebhookService;
  auth: AuthService;
  storage: StorageService;
  spam: SpamService;
  stats: StatsService;
}

export interface DataLoaders {
  emailById: DataLoader<string, any>;
  userById: DataLoader<string, any>;
  workflowById: DataLoader<string, any>;
  attachmentsByEmailId: DataLoader<string, any[]>;
}

export interface Context {
  req?: Request;
  res?: Response;
  user: User;
  services: Services;
  dataloaders: DataLoaders;
  pubsub: RedisPubSub;
}

interface CreateContextParams {
  req?: Request;
  res?: Response;
  token?: string;
  dataloaders: DataLoaders;
  pubsub?: RedisPubSub;
}

// JWT secret from environment
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Service instances (would be injected via DI in production)
const services: Services = {
  email: new EmailService(),
  workflow: new WorkflowService(),
  plugin: new PluginService(),
  template: new TemplateService(),
  user: new UserService(),
  webhook: new WebhookService(),
  auth: new AuthService(),
  storage: new StorageService(),
  spam: new SpamService(),
  stats: new StatsService(),
};

export async function createContext(params: CreateContextParams): Promise<Context> {
  const { req, res, token, dataloaders, pubsub } = params;

  let user: User | null = null;

  // Extract token from various sources
  const authToken = token || 
    req?.headers.authorization?.replace('Bearer ', '') ||
    req?.cookies?.token;

  if (authToken) {
    try {
      // Verify JWT token
      const decoded = verify(authToken, JWT_SECRET) as any;
      
      // Load user from database
      user = await services.user.getUserById(decoded.userId);
      
      if (!user) {
        throw new Error('User not found');
      }

      // Update last activity
      await services.user.updateLastActivity(user.id);
    } catch (error) {
      logger.warn('Invalid auth token', { error });
    }
  }

  // Create default user for unauthenticated requests
  if (!user) {
    user = {
      id: 'anonymous',
      tenantId: 'public',
      email: 'anonymous@example.com',
      name: 'Anonymous',
      role: 'guest',
    };
  }

  return {
    req,
    res,
    user,
    services,
    dataloaders,
    pubsub: pubsub!,
  };
}

// Helper to check if user is authenticated
export function isAuthenticated(context: Context): boolean {
  return context.user.id !== 'anonymous';
}

// Helper to check if user has role
export function hasRole(context: Context, role: string): boolean {
  return context.user.role === role;
}

// Helper to check if user is admin
export function isAdmin(context: Context): boolean {
  return context.user.role === 'admin';
}