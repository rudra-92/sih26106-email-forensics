import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { authService, mapSupabaseUser } from './authService';
import { getStoredToken, setStoredToken } from '../api/client';
import type {
  AuthContextType,
  AuthStatus,
  User,
  LoginPayload,
  RegisterPayload,
  RegisterResponse,
} from './types';

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [status, setStatus] = useState<AuthStatus>('loading');
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(getStoredToken());

  // Logout action: sign out from Supabase, wipe credentials, and reset local state
  const logout = useCallback(async () => {
    try {
      await authService.logout();
    } catch (err) {
      console.warn('[AuthContext] Logout exception:', err);
    } finally {
      setStoredToken(null);
      setToken(null);
      setUser(null);
      setStatus('unauthenticated');
    }
  }, []);

  // Session restoration and real-time subscription
  useEffect(() => {
    let mounted = true;

    // 1. Initial Supabase session check
    supabase.auth
      .getSession()
      .then(({ data: { session }, error }) => {
        if (!mounted) return;
        if (error || !session?.user) {
          setStoredToken(null);
          setToken(null);
          setUser(null);
          setStatus('unauthenticated');
          return;
        }

        setStoredToken(session.access_token);
        setToken(session.access_token);
        setUser(mapSupabaseUser(session.user));
        setStatus('authenticated');
      })
      .catch(() => {
        if (!mounted) return;
        setStoredToken(null);
        setToken(null);
        setUser(null);
        setStatus('unauthenticated');
      });

    // 2. Real-time auth state change subscription
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      if (!mounted) return;
      if (session?.user) {
        setStoredToken(session.access_token);
        setToken(session.access_token);
        setUser(mapSupabaseUser(session.user));
        setStatus('authenticated');
      } else {
        setStoredToken(null);
        setToken(null);
        setUser(null);
        setStatus('unauthenticated');
      }
    });

    // 3. Listen for unauthorized events emitted by apiClient 401 interceptor
    const handleUnauthorized = () => {
      logout();
    };

    window.addEventListener('auth:unauthorized', handleUnauthorized);

    return () => {
      mounted = false;
      subscription.unsubscribe();
      window.removeEventListener('auth:unauthorized', handleUnauthorized);
    };
  }, [logout]);

  // Login flow via Supabase
  const login = async (payload: LoginPayload): Promise<void> => {
    const response = await authService.login(payload);
    setStoredToken(response.access_token);
    setToken(response.access_token);
    setUser(response.user);
    setStatus('authenticated');
  };

  // Register flow via Supabase
  const register = async (payload: RegisterPayload): Promise<RegisterResponse> => {
    return await authService.register(payload);
  };

  const value: AuthContextType = {
    user,
    token,
    status,
    isAuthenticated: status === 'authenticated' && user !== null,
    isLoading: status === 'loading',
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
