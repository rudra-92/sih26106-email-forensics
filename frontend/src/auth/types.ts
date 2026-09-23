import type { User, LoginPayload, RegisterPayload, RegisterResponse, AuthResponse } from '../types';

export type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated';

export interface AuthState {
  status: AuthStatus;
  user: User | null;
  token: string | null;
}

export interface AuthContextType {
  user: User | null;
  token: string | null;
  status: AuthStatus;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (payload: LoginPayload) => Promise<void>;
  register: (payload: RegisterPayload) => Promise<RegisterResponse>;
  logout: () => void;
}

export type { User, LoginPayload, RegisterPayload, RegisterResponse, AuthResponse };
