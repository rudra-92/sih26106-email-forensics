import axios from 'axios';
import { apiClient } from '../api/client';
import type {
  LoginPayload,
  RegisterPayload,
  RegisterResponse,
  AuthResponse,
  User,
} from './types';

/**
 * Cleanly format and sanitize backend authentication errors
 */
export function formatAuthError(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (!error.response) {
      return 'Unable to reach investigation backend. Please verify network connection or server status.';
    }

    const { status, data } = error.response;

    if (status === 401) {
      if (typeof data?.detail === 'string') {
        return data.detail;
      }
      return 'Invalid email or password.';
    }

    if (status === 409) {
      if (typeof data?.detail === 'string') {
        return data.detail;
      }
      return 'An account with this email already exists.';
    }

    if (status === 422) {
      if (typeof data?.detail === 'string') {
        return data.detail;
      }
      if (Array.isArray(data?.detail)) {
        // Extract Pydantic validation messages cleanly
        const messages = data.detail.map((d: { msg?: string }) => d.msg).filter(Boolean);
        if (messages.length > 0) {
          return messages.join('. ');
        }
      }
      return 'Validation failed. Please verify submitted form inputs.';
    }

    if (status === 403) {
      return 'Access forbidden. Account lacks required privileges.';
    }

    if (status >= 500) {
      return 'Forensic service encountered an error. Please try again later.';
    }

    if (typeof data?.detail === 'string') {
      return data.detail;
    }
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'An unexpected authentication error occurred.';
}

export const authService = {
  /**
   * Authenticate investigator and acquire JWT bearer token
   * POST /api/auth/login
   */
  async login(payload: LoginPayload): Promise<AuthResponse> {
    const { data } = await apiClient.post<AuthResponse>('/api/auth/login', {
      email: payload.email.trim(),
      password: payload.password,
    });
    return data;
  },

  /**
   * Register new investigator account
   * POST /api/auth/register
   */
  async register(payload: RegisterPayload): Promise<RegisterResponse> {
    const { data } = await apiClient.post<RegisterResponse>('/api/auth/register', {
      full_name: payload.full_name.trim(),
      email: payload.email.trim(),
      password: payload.password,
    });
    return data;
  },

  /**
   * Validate session and retrieve current user profile
   * GET /api/auth/me
   */
  async getMe(): Promise<User> {
    const { data } = await apiClient.get<User>('/api/auth/me');
    return data;
  },
};
