/** Auth API types and calls (hand-written shim; generated client comes later). */

import { api } from './client';

export type Role = 'viewer' | 'operator' | 'admin';

export interface UserInfo {
  id: number;
  username: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface AuthStatus {
  needs_setup: boolean;
  authenticated: boolean;
  user: UserInfo | null;
}

interface LoginResponse {
  user: UserInfo;
  csrf_token: string;
}

export function fetchAuthStatus(): Promise<AuthStatus> {
  return api<AuthStatus>('/api/auth/status');
}

export function login(username: string, password: string): Promise<LoginResponse> {
  return api<LoginResponse>('/api/auth/login', { method: 'POST', body: { username, password } });
}

export function setupFirstAdmin(username: string, password: string): Promise<LoginResponse> {
  return api<LoginResponse>('/api/auth/setup', { method: 'POST', body: { username, password } });
}

export function logout(): Promise<void> {
  return api<void>('/api/auth/logout', { method: 'POST' });
}
