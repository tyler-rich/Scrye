/** Auth API types and calls (hand-written shim; generated client comes later). */

import { api } from './client';

export type Role = 'viewer' | 'operator' | 'admin';

export interface UserInfo {
  id: number;
  username: string;
  role: Role;
  is_active: boolean;
  mfa_enabled: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface OidcStatus {
  enabled: boolean;
  display_name: string;
}

export interface AuthStatus {
  needs_setup: boolean;
  authenticated: boolean;
  user: UserInfo | null;
  oidc: OidcStatus;
}

export interface LoginResponse {
  user: UserInfo | null;
  csrf_token: string | null;
  mfa_required: boolean;
  mfa_token: string | null;
  /** Set when a mandatory-MFA policy requires this account to enroll before access. */
  enrollment_required?: boolean;
  /** One-time TOTP secret (manual entry key) for forced enrollment. */
  mfa_secret?: string | null;
  /** otpauth:// provisioning URI for forced enrollment. */
  otpauth_uri?: string | null;
}

export function fetchAuthStatus(): Promise<AuthStatus> {
  return api<AuthStatus>('/api/auth/status');
}

export function login(username: string, password: string): Promise<LoginResponse> {
  return api<LoginResponse>('/api/auth/login', { method: 'POST', body: { username, password } });
}

export function verifyMfa(mfaToken: string, code: string): Promise<LoginResponse> {
  return api<LoginResponse>('/api/auth/mfa/verify', {
    method: 'POST',
    body: { mfa_token: mfaToken, code },
  });
}

export function setupFirstAdmin(username: string, password: string): Promise<LoginResponse> {
  return api<LoginResponse>('/api/auth/setup', { method: 'POST', body: { username, password } });
}

export function logout(): Promise<void> {
  return api<void>('/api/auth/logout', { method: 'POST' });
}
