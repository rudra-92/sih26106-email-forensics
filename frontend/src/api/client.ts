import axios, { type AxiosError, type AxiosInstance, type InternalAxiosRequestConfig } from 'axios';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || '';
export const AUTH_TOKEN_KEY = 'sih26106_auth_token';

export interface HealthCheckResponse {
  status: 'ok' | 'degraded';
  service: string;
  version: string;
  database: 'connected' | 'disconnected';
}

/**
 * Standardized API client for SIH26106 Forensics Backend
 */
export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },
});

/**
 * Retrieve current stored JWT authentication token
 */
export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
}

/**
 * Store or clear JWT token
 */
export function setStoredToken(token: string | null): void {
  try {
    if (token) {
      localStorage.setItem(AUTH_TOKEN_KEY, token);
    } else {
      localStorage.removeItem(AUTH_TOKEN_KEY);
    }
  } catch {
    // Gracefully handle storage quota or privacy restrictions
  }
}

// Request interceptor: inject Authorization Bearer token if present
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = getStoredToken();
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error: AxiosError) => Promise.reject(error)
);

// Response interceptor: detect 401 from protected endpoints and notify session
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      const url = error.config?.url || '';
      // Do not trigger global logout on login attempts returning 401
      if (!url.includes('/api/auth/login')) {
        setStoredToken(null);
        window.dispatchEvent(new CustomEvent('auth:unauthorized'));
      }
    }
    return Promise.reject(error);
  }
);

/**
 * Probe backend API and database connectivity
 */
export async function checkBackendHealth(): Promise<HealthCheckResponse> {
  const { data } = await apiClient.get<HealthCheckResponse>('/health');
  return data;
}
