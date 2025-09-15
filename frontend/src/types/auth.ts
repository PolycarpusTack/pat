export interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  isActive: boolean;
  emailVerified: boolean;
  settings: Record<string, any>;
  lastLoginAt: Date | null;
  mfaEnabled: boolean;
  createdAt: Date;
}

export interface LoginRequest {
  email: string;
  password: string;
  mfa_code?: string;
  device_id?: string;
  remember_me?: boolean;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  refreshTokenExpiresAt: Date;
  user: User;
  requiresMFA?: boolean;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  refreshTokenExpiresAt: Date;
  user: User;
}

export interface RegisterRequest {
  email: string;
  name: string;
  password: string;
  tenantId?: string;
}

export interface UpdateProfileRequest {
  name?: string;
  settings?: Record<string, any>;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

export interface EnableMFAResponse {
  qrCode: string;
  recoveryCodes: string[];
  secret: string;
}

export interface VerifyMFARequest {
  code: string;
}

export interface DisableMFARequest {
  password: string;
}

export interface Session {
  id: string;
  userId: string;
  deviceId?: string;
  ipAddress?: string;
  userAgent?: string;
  isActive: boolean;
  expiresAt: Date;
  createdAt: Date;
}

export interface ApiKey {
  id: string;
  name: string;
  keyPreview: string;
  permissions: string[];
  rateLimit: number;
  isActive: boolean;
  expiresAt?: Date;
  lastUsedAt?: Date;
  createdAt: Date;
}

export interface Tenant {
  id: string;
  name: string;
  domain?: string;
  settings: Record<string, any>;
  planType: string;
  isActive: boolean;
  createdAt: Date;
}

export interface AuditLog {
  id: string;
  userId?: string;
  tenantId?: string;
  action: string;
  resource?: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
  createdAt: Date;
}

export interface AuthError {
  code: string;
  message: string;
  details?: Record<string, any>;
}

// JWT Token payload structure
export interface TokenPayload {
  user_id: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  tenant_id: string;
  session_id: string;
  device_id?: string;
  ip_address?: string;
  iss: string; // issuer
  sub: string; // subject (user_id)
  aud: string[]; // audience
  exp: number; // expiration time
  nbf: number; // not before
  iat: number; // issued at
  jti: string; // JWT ID
}

// Permission constants
export const PERMISSIONS = {
  EMAILS_READ: 'emails:read',
  EMAILS_WRITE: 'emails:write',
  EMAILS_DELETE: 'emails:delete',
  
  USERS_READ: 'users:read',
  USERS_WRITE: 'users:write',
  USERS_DELETE: 'users:delete',
  
  WORKFLOWS_READ: 'workflows:read',
  WORKFLOWS_WRITE: 'workflows:write',
  WORKFLOWS_DELETE: 'workflows:delete',
  WORKFLOWS_EXECUTE: 'workflows:execute',
  
  PLUGINS_READ: 'plugins:read',
  PLUGINS_WRITE: 'plugins:write',
  PLUGINS_INSTALL: 'plugins:install',
  PLUGINS_UNINSTALL: 'plugins:uninstall',
  
  TEMPLATES_READ: 'templates:read',
  TEMPLATES_WRITE: 'templates:write',
  TEMPLATES_DELETE: 'templates:delete',
  
  WEBHOOKS_READ: 'webhooks:read',
  WEBHOOKS_WRITE: 'webhooks:write',
  WEBHOOKS_DELETE: 'webhooks:delete',
  
  SETTINGS_READ: 'settings:read',
  SETTINGS_WRITE: 'settings:write',
  
  STATS_READ: 'stats:read',
  
  API_KEYS_READ: 'api_keys:read',
  API_KEYS_WRITE: 'api_keys:write',
  API_KEYS_DELETE: 'api_keys:delete',
  
  ALL: '*',
} as const;

// Role constants
export const ROLES = {
  SUPER_ADMIN: 'super_admin',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
  USER: 'user',
  READONLY: 'readonly',
  API_USER: 'api_user',
} as const;

// Type guards
export const isUser = (obj: any): obj is User => {
  return obj && typeof obj.id === 'string' && typeof obj.email === 'string';
};

export const isLoginResponse = (obj: any): obj is LoginResponse => {
  return obj && 
    typeof obj.accessToken === 'string' && 
    typeof obj.refreshToken === 'string' &&
    isUser(obj.user);
};

export const hasRole = (user: User | null, role: string): boolean => {
  return user?.roles?.includes(role) || false;
};

export const hasPermission = (user: User | null, permission: string): boolean => {
  if (!user || !user.roles) return false;
  
  // Super admin has all permissions
  if (user.roles.includes(ROLES.SUPER_ADMIN)) return true;
  
  // Define role permissions mapping
  const rolePermissions: Record<string, string[]> = {
    [ROLES.ADMIN]: Object.values(PERMISSIONS).filter(p => p !== PERMISSIONS.ALL),
    [ROLES.MODERATOR]: [
      PERMISSIONS.EMAILS_READ, PERMISSIONS.EMAILS_WRITE,
      PERMISSIONS.USERS_READ,
      PERMISSIONS.WORKFLOWS_READ, PERMISSIONS.WORKFLOWS_WRITE,
      PERMISSIONS.TEMPLATES_READ, PERMISSIONS.TEMPLATES_WRITE,
      PERMISSIONS.WEBHOOKS_READ, PERMISSIONS.WEBHOOKS_WRITE,
      PERMISSIONS.STATS_READ,
    ],
    [ROLES.USER]: [
      PERMISSIONS.EMAILS_READ,
      PERMISSIONS.WORKFLOWS_READ,
      PERMISSIONS.TEMPLATES_READ,
      PERMISSIONS.STATS_READ,
    ],
    [ROLES.READONLY]: [
      PERMISSIONS.EMAILS_READ,
      PERMISSIONS.WORKFLOWS_READ,
      PERMISSIONS.TEMPLATES_READ,
      PERMISSIONS.STATS_READ,
    ],
    [ROLES.API_USER]: [
      PERMISSIONS.EMAILS_READ, PERMISSIONS.EMAILS_WRITE,
      PERMISSIONS.WORKFLOWS_READ, PERMISSIONS.WORKFLOWS_WRITE, PERMISSIONS.WORKFLOWS_EXECUTE,
      PERMISSIONS.TEMPLATES_READ, PERMISSIONS.TEMPLATES_WRITE,
    ],
  };

  const userPermissions = user.roles.reduce<string[]>((acc, role) => {
    return acc.concat(rolePermissions[role] || []);
  }, []);

  return userPermissions.includes(permission);
};

export const canAccessResource = (
  user: User | null, 
  resource: string, 
  action: 'read' | 'write' | 'delete' | 'execute' = 'read'
): boolean => {
  const permission = `${resource}:${action}`;
  return hasPermission(user, permission);
};