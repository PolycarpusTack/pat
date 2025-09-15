'use client';

import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type { User } from '../types/auth';

interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isInitialized: boolean;
}

interface AuthActions {
  setAuth: (user: User, accessToken: string, refreshToken: string) => void;
  clearAuth: () => void;
  updateUser: (user: User) => void;
  updateTokens: (accessToken: string, refreshToken: string) => void;
  setInitialized: (initialized: boolean) => void;
}

type AuthStore = AuthState & AuthActions;

const initialState: AuthState = {
  user: null,
  accessToken: null,
  refreshToken: null,
  isAuthenticated: false,
  isInitialized: false,
};

export const useAuthStore = create<AuthStore>()(
  persist(
    (set, get) => ({
      ...initialState,

      setAuth: (user: User, accessToken: string, refreshToken: string) => {
        set({
          user,
          accessToken,
          refreshToken,
          isAuthenticated: true,
          isInitialized: true,
        });
      },

      clearAuth: () => {
        set({
          ...initialState,
          isInitialized: true,
        });
      },

      updateUser: (user: User) => {
        const currentState = get();
        if (currentState.isAuthenticated) {
          set({ user });
        }
      },

      updateTokens: (accessToken: string, refreshToken: string) => {
        const currentState = get();
        if (currentState.isAuthenticated) {
          set({
            accessToken,
            refreshToken,
          });
        }
      },

      setInitialized: (initialized: boolean) => {
        set({ isInitialized: initialized });
      },
    }),
    {
      name: 'pat-auth-storage',
      storage: createJSONStorage(() => {
        if (typeof window !== 'undefined') {
          return localStorage;
        }
        // Fallback for SSR
        return {
          getItem: () => null,
          setItem: () => {},
          removeItem: () => {},
        };
      }),
      // Only persist user data, not sensitive tokens
      partialize: (state) => ({
        user: state.user,
        isInitialized: state.isInitialized,
        // Don't persist tokens in zustand storage for security
        // Tokens are handled separately in localStorage
      }),
      version: 1,
      migrate: (persistedState: any, version: number) => {
        // Handle migration between versions if needed
        if (version === 0) {
          // Migration logic for version 0 -> 1
          return {
            ...persistedState,
            isInitialized: false,
          };
        }
        return persistedState;
      },
    }
  )
);

// Selectors for easy access to specific parts of the store
export const useAuthUser = () => useAuthStore((state) => state.user);
export const useIsAuthenticated = () => useAuthStore((state) => state.isAuthenticated);
export const useAuthTokens = () => useAuthStore((state) => ({
  accessToken: state.accessToken,
  refreshToken: state.refreshToken,
}));

// Helper functions
export const hasRole = (role: string): boolean => {
  const user = useAuthStore.getState().user;
  return user?.roles?.includes(role) || false;
};

export const hasPermission = (permission: string): boolean => {
  const user = useAuthStore.getState().user;
  if (!user || !user.roles) return false;
  
  // Super admin has all permissions
  if (user.roles.includes('super_admin')) return true;
  
  // Check if user has the specific permission based on their roles
  const rolePermissions: Record<string, string[]> = {
    admin: [
      'emails:read', 'emails:write', 'emails:delete',
      'users:read', 'users:write', 'users:delete',
      'workflows:read', 'workflows:write', 'workflows:delete',
      'plugins:read', 'plugins:write', 'plugins:install', 'plugins:uninstall',
      'templates:read', 'templates:write', 'templates:delete',
      'webhooks:read', 'webhooks:write', 'webhooks:delete',
      'settings:read', 'settings:write',
      'stats:read',
      'api_keys:read', 'api_keys:write', 'api_keys:delete',
    ],
    moderator: [
      'emails:read', 'emails:write',
      'users:read',
      'workflows:read', 'workflows:write',
      'templates:read', 'templates:write',
      'webhooks:read', 'webhooks:write',
      'stats:read',
    ],
    user: [
      'emails:read',
      'workflows:read',
      'templates:read',
      'stats:read',
    ],
    readonly: [
      'emails:read',
      'workflows:read',
      'templates:read',
      'stats:read',
    ],
    api_user: [
      'emails:read', 'emails:write',
      'workflows:read', 'workflows:write', 'workflows:execute',
      'templates:read', 'templates:write',
    ],
  };

  const userPermissions = user.roles.reduce<string[]>((acc, role) => {
    return acc.concat(rolePermissions[role] || []);
  }, []);

  return userPermissions.includes(permission);
};

// Auth guard hook for components
export const useAuthGuard = (requiredRole?: string, requiredPermission?: string) => {
  const { isAuthenticated, user } = useAuthStore();

  const canAccess = () => {
    if (!isAuthenticated || !user) return false;
    
    if (requiredRole && !hasRole(requiredRole)) return false;
    if (requiredPermission && !hasPermission(requiredPermission)) return false;
    
    return true;
  };

  return {
    canAccess: canAccess(),
    isAuthenticated,
    user,
    hasRole,
    hasPermission,
  };
};