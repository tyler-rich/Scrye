/** API types and calls for personal API tokens. */

import { api, apiList } from './client';
import type { Role } from './auth';

export interface ApiTokenInfo {
  id: number;
  name: string;
  token_prefix: string;
  role: Role;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface ApiTokenCreated extends ApiTokenInfo {
  /** The plaintext token — returned once at creation and never again. */
  token: string;
}

export interface ApiTokenCreate {
  name: string;
  role?: Role;
  expires_in_days?: number | null;
}

export const listApiTokens = () => apiList<ApiTokenInfo>('/api/api-tokens');
export const createApiToken = (body: ApiTokenCreate) =>
  api<ApiTokenCreated>('/api/api-tokens', { method: 'POST', body });
export const revokeApiToken = (id: number) =>
  api<void>(`/api/api-tokens/${id}`, { method: 'DELETE' });
