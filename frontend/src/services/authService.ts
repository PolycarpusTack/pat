'use client';

import { graphqlClient } from './graphql/client';
import { 
  LoginDocument, 
  RefreshTokenDocument, 
  LogoutDocument,
  GetCurrentUserDocument,
  UpdateProfileDocument,
  ChangePasswordDocument,
  EnableMfaDocument,
  VerifyMfaDocument,
  DisableMfaDocument,
} from '../generated/graphql';
import type { 
  LoginRequest, 
  LoginResponse, 
  User,
  RefreshTokenResponse,
  UpdateProfileRequest,
  ChangePasswordRequest,
  EnableMFAResponse,
  VerifyMFARequest,
  DisableMFARequest,
} from '../types/auth';

class AuthService {
  private readonly baseURL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8025';

  async login(credentials: LoginRequest): Promise<LoginResponse> {
    try {
      const response = await graphqlClient.request(LoginDocument, {
        input: {
          email: credentials.email,
          password: credentials.password,
          mfaCode: credentials.mfa_code,
          deviceId: credentials.device_id,
          rememberMe: credentials.remember_me,
        },
      });

      if (!response.login) {
        throw new Error('Login failed');
      }

      return {
        accessToken: response.login.accessToken,
        refreshToken: response.login.refreshToken,
        expiresAt: new Date(response.login.expiresAt),
        refreshTokenExpiresAt: new Date(response.login.refreshTokenExpiresAt),
        user: this.mapUserFromGraphQL(response.login.user),
        requiresMFA: response.login.requiresMfa || false,
      };
    } catch (error: any) {
      throw new Error(this.parseErrorMessage(error));
    }
  }

  async refreshToken(refreshToken: string): Promise<RefreshTokenResponse> {
    try {
      const response = await graphqlClient.request(RefreshTokenDocument, {
        refreshToken,
      });

      if (!response.refreshToken) {
        throw new Error('Token refresh failed');
      }

      return {
        accessToken: response.refreshToken.accessToken,
        refreshToken: response.refreshToken.refreshToken,
        expiresAt: new Date(response.refreshToken.expiresAt),
        refreshTokenExpiresAt: new Date(response.refreshToken.refreshTokenExpiresAt),
        user: this.mapUserFromGraphQL(response.refreshToken.user),
      };
    } catch (error: any) {
      throw new Error(this.parseErrorMessage(error));
    }
  }

  async logout(): Promise<void> {
    try {
      await graphqlClient.request(LogoutDocument);
    } catch (error: any) {
      // Log error but don't throw - logout should always succeed locally
      console.error('Logout error:', error);
    }
  }

  async getCurrentUser(): Promise<User> {
    try {
      const response = await graphqlClient.request(GetCurrentUserDocument);

      if (!response.me) {
        throw new Error('User not found');
      }

      return this.mapUserFromGraphQL(response.me);
    } catch (error: any) {
      throw new Error(this.parseErrorMessage(error));
    }
  }

  async updateProfile(data: UpdateProfileRequest): Promise<User> {
    try {
      const response = await graphqlClient.request(UpdateProfileDocument, {
        input: {
          name: data.name,
          settings: data.settings,
        },
      });

      if (!response.updateProfile) {
        throw new Error('Profile update failed');
      }

      return this.mapUserFromGraphQL(response.updateProfile);
    } catch (error: any) {
      throw new Error(this.parseErrorMessage(error));
    }
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    try {
      await graphqlClient.request(ChangePasswordDocument, {
        input: {
          currentPassword,
          newPassword,
        },
      });
    } catch (error: any) {
      throw new Error(this.parseErrorMessage(error));
    }
  }

  async enableMFA(): Promise<EnableMFAResponse> {
    try {
      const response = await graphqlClient.request(EnableMfaDocument);

      if (!response.enableMfa) {
        throw new Error('MFA enable failed');
      }

      return {
        qrCode: response.enableMfa.qrCodeUrl,
        recoveryCodes: response.enableMfa.recoveryCodes,
        secret: response.enableMfa.secret,
      };
    } catch (error: any) {
      throw new Error(this.parseErrorMessage(error));
    }
  }

  async verifyMFA(code: string): Promise<User> {
    try {
      const response = await graphqlClient.request(VerifyMfaDocument, {
        input: {
          code,
        },
      });

      if (!response.verifyMfa) {
        throw new Error('MFA verification failed');
      }

      return this.mapUserFromGraphQL(response.verifyMfa);
    } catch (error: any) {
      throw new Error(this.parseErrorMessage(error));
    }
  }

  async disableMFA(password: string): Promise<User> {
    try {
      const response = await graphqlClient.request(DisableMfaDocument, {
        input: {
          password,
        },
      });

      if (!response.disableMfa) {
        throw new Error('MFA disable failed');
      }

      return this.mapUserFromGraphQL(response.disableMfa);
    } catch (error: any) {
      throw new Error(this.parseErrorMessage(error));
    }
  }

  // REST API fallback methods (if GraphQL is not available)
  async loginREST(credentials: LoginRequest): Promise<LoginResponse> {
    const response = await this.fetchAPI('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });

    return response;
  }

  async refreshTokenREST(refreshToken: string): Promise<RefreshTokenResponse> {
    const response = await this.fetchAPI('/api/v1/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    return response;
  }

  private async fetchAPI(endpoint: string, options: RequestInit = {}): Promise<any> {
    const url = `${this.baseURL}${endpoint}`;
    
    const defaultOptions: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...this.getAuthHeaders(),
      },
      ...options,
    };

    const response = await fetch(url, defaultOptions);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
    }

    return response.json();
  }

  private getAuthHeaders(): Record<string, string> {
    if (typeof window === 'undefined') return {};
    
    const token = localStorage.getItem('pat_access_token');
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  private mapUserFromGraphQL(user: any): User {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      roles: user.role ? [user.role] : ['user'], // GraphQL schema has 'role' as string
      isActive: true, // Assumption: if user is returned, they're active
      emailVerified: true, // Assumption: if user can login, email is verified
      settings: user.settings || {},
      lastLoginAt: user.lastLoginAt ? new Date(user.lastLoginAt) : null,
      mfaEnabled: false, // Would need to be added to GraphQL schema
      createdAt: user.createdAt ? new Date(user.createdAt) : new Date(),
    };
  }

  private parseErrorMessage(error: any): string {
    if (error.response?.errors?.length > 0) {
      return error.response.errors[0].message;
    }
    
    if (error.message) {
      return error.message;
    }

    return 'An unexpected error occurred';
  }

  // Utility methods
  isTokenExpired(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp * 1000 < Date.now();
    } catch {
      return true;
    }
  }

  getTokenExpiryTime(token: string): Date | null {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return new Date(payload.exp * 1000);
    } catch {
      return null;
    }
  }

  shouldRefreshToken(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const expiryTime = payload.exp * 1000;
      const now = Date.now();
      const fiveMinutes = 5 * 60 * 1000;
      
      // Refresh if token expires within 5 minutes
      return expiryTime - now < fiveMinutes;
    } catch {
      return true;
    }
  }
}

export const authService = new AuthService();