import axios from 'axios';
import type { User as SupabaseUser } from '@supabase/supabase-js';
import { supabase } from '../lib/supabase';
import type {
  LoginPayload,
  RegisterPayload,
  RegisterResponse,
  AuthResponse,
  User,
} from './types';

/**
 * Maps a Supabase user object into the platform's standardized User interface.
 */
export function mapSupabaseUser(sbUser: SupabaseUser): User {
  const metadata = sbUser.user_metadata || {};
  const appMetadata = sbUser.app_metadata || {};

  return {
    id: sbUser.id,
    email: sbUser.email || '',
    full_name:
      metadata.full_name ||
      metadata.name ||
      (sbUser.email ? sbUser.email.split('@')[0] : 'Investigator'),
    role: metadata.role || appMetadata.role || 'investigator',
    is_active: true,
    created_at: sbUser.created_at,
    last_login_at: sbUser.last_sign_in_at || null,
  };
}

/**
 * Cleanly format and sanitize authentication errors from Supabase, Axios, or JavaScript runtime.
 */
export function formatAuthError(error: unknown): string {
  if (!error) {
    return 'An unexpected authentication error occurred.';
  }

  // Handle Supabase AuthError / Error instances
  if (typeof error === 'object' && error !== null) {
    const err = error as { message?: string; name?: string; status?: number; code?: string };
    const rawMessage = (err.message || '').toLowerCase();

    if (rawMessage.includes('invalid login credentials') || rawMessage.includes('invalid grant')) {
      return 'Invalid email or password.';
    }

    if (rawMessage.includes('user already registered') || rawMessage.includes('already exists')) {
      return 'An account with this email already exists.';
    }

    if (rawMessage.includes('email not confirmed') || rawMessage.includes('email link is invalid')) {
      return 'Please verify your email before signing in.';
    }

    if (rawMessage.includes('failed to fetch') || rawMessage.includes('networkerror') || rawMessage.includes('authretryableresponseerror')) {
      return 'Unable to reach authentication service. Please check your network connection or verify Supabase configuration.';
    }

    if (rawMessage.includes('password should be at least')) {
      return err.message || 'Password must be at least 6 characters.';
    }

    if (rawMessage.includes('rate limit')) {
      return 'Too many authentication attempts. Please wait a moment and try again.';
    }

    // Axios backend error support
    if (axios.isAxiosError(error)) {
      if (!error.response) {
        return 'Unable to reach forensic backend. Please verify server connectivity.';
      }

      const { status, data } = error.response;

      if (status === 401) {
        return typeof data?.detail === 'string' ? data.detail : 'Invalid email or password.';
      }

      if (status === 409) {
        return typeof data?.detail === 'string' ? data.detail : 'An account with this email already exists.';
      }

      if (status === 422) {
        if (typeof data?.detail === 'string') return data.detail;
        if (Array.isArray(data?.detail)) {
          const msgs = data.detail.map((d: { msg?: string }) => d.msg).filter(Boolean);
          if (msgs.length > 0) return msgs.join('. ');
        }
        return 'Validation failed. Please verify form inputs.';
      }

      if (status === 403) {
        return 'Access forbidden. Account lacks required privileges.';
      }

      if (status >= 500) {
        return 'Authentication service encountered an error. Please try again later.';
      }

      if (typeof data?.detail === 'string') {
        return data.detail;
      }
    }

    if (err.message && typeof err.message === 'string') {
      return err.message;
    }
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'An unexpected authentication error occurred.';
}

export const authService = {
  /**
   * Authenticate investigator via Supabase Auth
   */
  async login(payload: LoginPayload): Promise<AuthResponse> {
    const { data, error } = await supabase.auth.signInWithPassword({
      email: payload.email.trim(),
      password: payload.password,
    });

    if (error) {
      throw error;
    }

    if (!data.session || !data.user) {
      throw new Error('No session returned from authentication provider.');
    }

    return {
      access_token: data.session.access_token,
      token_type: data.session.token_type || 'bearer',
      expires_in: data.session.expires_in || 3600,
      user: mapSupabaseUser(data.user),
    };
  },

  /**
   * Register new investigator account via Supabase Auth
   */
  async register(payload: RegisterPayload): Promise<RegisterResponse> {
    const { data, error } = await supabase.auth.signUp({
      email: payload.email.trim(),
      password: payload.password,
      options: {
        data: {
          full_name: payload.full_name.trim(),
          role: 'investigator',
        },
      },
    });

    if (error) {
      throw error;
    }

    if (!data.user) {
      throw new Error('Registration failed: no user record created.');
    }

    return {
      id: data.user.id,
      user_id: data.user.id,
      email: payload.email.trim(),
      full_name: payload.full_name.trim(),
      role: 'investigator',
    };
  },

  /**
   * Validate session and retrieve current user profile from Supabase
   */
  async getMe(): Promise<User> {
    const { data, error } = await supabase.auth.getUser();

    if (error || !data.user) {
      throw error || new Error('No active authenticated user.');
    }

    return mapSupabaseUser(data.user);
  },

  /**
   * Sign out current investigator from Supabase Auth
   */
  async logout(): Promise<void> {
    try {
      const { error } = await supabase.auth.signOut({ scope: 'local' });
      if (error) {
        console.warn('[Supabase Auth] SignOut warning:', error.message);
      }
    } catch (err: unknown) {
      console.warn('[Supabase Auth] SignOut exception:', err);
    }
  },
};
