import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { authService } from './authService';
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

  // Logout action: wipe credentials and reset state
  const logout = useCallback(() => {
    setStoredToken(null);
    setToken(null);
    setUser(null);
    setStatus('unauthenticated');
  }, []);

  // Session restoration on startup
  const restoreSession = useCallback(async () => {
    const existingToken = getStoredToken();
    if (!existingToken) {
      setStatus('unauthenticated');
      setUser(null);
      return;
    }

    try {
      const currentUser = await authService.getMe();
      setUser(currentUser);
      setToken(existingToken);
      setStatus('authenticated');
    } catch {
      // Token invalid or expired: clear storage and reset to unauthenticated
      setStoredToken(null);
      setToken(null);
      setUser(null);
      setStatus('unauthenticated');
    }
  }, []);

  useEffect(() => {
    restoreSession();

    // Listen for unauthorized events emitted by apiClient 401 interceptor
    const handleUnauthorized = () => {
      logout();
    };

    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => {
      window.removeEventListener('auth:unauthorized', handleUnauthorized);
    };
  }, [restoreSession, logout]);

  // Login flow
  const login = async (payload: LoginPayload): Promise<void> => {
    const response = await authService.login(payload);
    setStoredToken(response.access_token);
    setToken(response.access_token);
    setUser(response.user);
    setStatus('authenticated');
  };

  // Register flow
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
