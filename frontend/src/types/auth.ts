/**
 * Authentication and User Identity Types
 */

export type UserRole = 'investigator' | 'admin';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole | string;
  is_active: boolean;
  created_at: string;
  last_login_at?: string | null;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface RegisterResponse {
  id: string;
  user_id: string;
  email: string;
  full_name: string;
  role: string;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface RegisterPayload {
  full_name: string;
  email: string;
  password: string;
}
