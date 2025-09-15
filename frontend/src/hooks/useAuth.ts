'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'react-hot-toast';
import { useAuthStore } from '../stores/authStore';
import { authService } from '../services/authService';
import type { LoginRequest, LoginResponse, User } from '../types/auth';

interface UseAuthReturn {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginRequest) => Promise<LoginResponse>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<void>;
  updateProfile: (data: Partial<User>) => Promise<User>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  enableMFA: () => Promise<{ qrCode: string; recoveryCodes: string[] }>;
  verifyMFA: (code: string) => Promise<void>;
  disableMFA: (password: string) => Promise<void>;
}

export const useAuth = (): UseAuthReturn => {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);
  
  const {
    user,
    isAuthenticated,
    accessToken,
    refreshToken: storedRefreshToken,
    setAuth,
    clearAuth,
    updateUser,
  } = useAuthStore();

  // Initialize auth state on mount
  useEffect(() => {
    const initializeAuth = async () => {
      const token = localStorage.getItem('pat_access_token');
      const refreshToken = localStorage.getItem('pat_refresh_token');
      
      if (token && refreshToken) {
        try {
          // Validate token and get user data
          const userData = await authService.getCurrentUser();
          setAuth(userData, token, refreshToken);
        } catch (error) {
          // Token invalid, try to refresh
          if (refreshToken) {
            try {
              await refreshTokens();
            } catch (refreshError) {
              clearAuth();
              localStorage.removeItem('pat_access_token');
              localStorage.removeItem('pat_refresh_token');
            }
          }
        }
      }
    };

    initializeAuth();
  }, []);

  const login = useCallback(async (credentials: LoginRequest): Promise<LoginResponse> => {
    setIsLoading(true);
    
    try {
      const response = await authService.login(credentials);
      
      if (response.requiresMFA) {
        return response;
      }

      // Store tokens
      localStorage.setItem('pat_access_token', response.accessToken);
      localStorage.setItem('pat_refresh_token', response.refreshToken);
      
      // Update auth state
      setAuth(response.user, response.accessToken, response.refreshToken);
      
      toast.success(`Welcome back, ${response.user.name}!`);
      
      return response;
    } catch (error: any) {
      toast.error(error.message || 'Login failed');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [setAuth]);

  const logout = useCallback(async (): Promise<void> => {
    setIsLoading(true);
    
    try {
      if (accessToken) {
        await authService.logout();
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear auth state and storage regardless of API call result
      clearAuth();
      localStorage.removeItem('pat_access_token');
      localStorage.removeItem('pat_refresh_token');
      localStorage.removeItem('pat_device_id');
      
      setIsLoading(false);
      toast.success('You have been logged out');
      router.push('/login');
    }
  }, [accessToken, clearAuth, router]);

  const refreshTokens = useCallback(async (): Promise<void> => {
    if (!storedRefreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await authService.refreshToken(storedRefreshToken);
      
      // Update tokens
      localStorage.setItem('pat_access_token', response.accessToken);
      localStorage.setItem('pat_refresh_token', response.refreshToken);
      
      // Update auth state
      setAuth(response.user, response.accessToken, response.refreshToken);
    } catch (error) {
      // Refresh failed, force logout
      clearAuth();
      localStorage.removeItem('pat_access_token');
      localStorage.removeItem('pat_refresh_token');
      router.push('/login');
      throw error;
    }
  }, [storedRefreshToken, setAuth, clearAuth, router]);

  const updateProfile = useCallback(async (data: Partial<User>): Promise<User> => {
    if (!isAuthenticated) {
      throw new Error('Not authenticated');
    }

    setIsLoading(true);
    
    try {
      const updatedUser = await authService.updateProfile(data);
      updateUser(updatedUser);
      toast.success('Profile updated successfully');
      return updatedUser;
    } catch (error: any) {
      toast.error(error.message || 'Failed to update profile');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated, updateUser]);

  const changePassword = useCallback(async (
    currentPassword: string, 
    newPassword: string
  ): Promise<void> => {
    if (!isAuthenticated) {
      throw new Error('Not authenticated');
    }

    setIsLoading(true);
    
    try {
      await authService.changePassword(currentPassword, newPassword);
      toast.success('Password changed successfully');
    } catch (error: any) {
      toast.error(error.message || 'Failed to change password');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  const enableMFA = useCallback(async (): Promise<{ qrCode: string; recoveryCodes: string[] }> => {
    if (!isAuthenticated) {
      throw new Error('Not authenticated');
    }

    setIsLoading(true);
    
    try {
      const result = await authService.enableMFA();
      return result;
    } catch (error: any) {
      toast.error(error.message || 'Failed to enable MFA');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  const verifyMFA = useCallback(async (code: string): Promise<void> => {
    if (!isAuthenticated) {
      throw new Error('Not authenticated');
    }

    setIsLoading(true);
    
    try {
      const updatedUser = await authService.verifyMFA(code);
      updateUser(updatedUser);
      toast.success('MFA enabled successfully');
    } catch (error: any) {
      toast.error(error.message || 'Failed to verify MFA');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated, updateUser]);

  const disableMFA = useCallback(async (password: string): Promise<void> => {
    if (!isAuthenticated) {
      throw new Error('Not authenticated');
    }

    setIsLoading(true);
    
    try {
      const updatedUser = await authService.disableMFA(password);
      updateUser(updatedUser);
      toast.success('MFA disabled successfully');
    } catch (error: any) {
      toast.error(error.message || 'Failed to disable MFA');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated, updateUser]);

  return {
    user,
    isAuthenticated,
    isLoading,
    login,
    logout,
    refreshToken: refreshTokens,
    updateProfile,
    changePassword,
    enableMFA,
    verifyMFA,
    disableMFA,
  };
};