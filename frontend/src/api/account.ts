/** API calls for the signed-in user's own account: password, MFA, sessions. */

import { api, apiList } from './client';

export interface SessionInfo {
  id: number;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  ip: string | null;
  user_agent: string | null;
  current: boolean;
}

export interface MfaEnrollment {
  secret: string;
  otpauth_uri: string;
}

export const changePassword = (current_password: string, new_password: string) =>
  api<void>('/api/auth/password', {
    method: 'POST',
    body: { current_password, new_password },
  });

export const listSessions = () => apiList<SessionInfo>('/api/auth/sessions');
export const revokeSession = (id: number) =>
  api<void>(`/api/auth/sessions/${id}`, { method: 'DELETE' });

export const enrollMfa = (currentPassword?: string) =>
  api<MfaEnrollment>('/api/auth/mfa/enroll', {
    method: 'POST',
    // current_password is only required when re-enrolling while MFA is active;
    // the account page only enrolls from the disabled state, so it is omitted.
    body: { current_password: currentPassword ?? null },
  });
export const activateMfa = (code: string) =>
  api<void>('/api/auth/mfa/activate', { method: 'POST', body: { code } });
export const disableMfa = (password: string) =>
  api<void>('/api/auth/mfa/disable', { method: 'POST', body: { password } });
