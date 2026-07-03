/** API types and calls for OIDC provider configuration. */

import { api } from './client';
import type { MaskedSecret } from './targets';
import type { Role } from './auth';

export interface OidcConfig {
  enabled: boolean;
  display_name: string;
  issuer: string | null;
  client_id: string | null;
  client_secret: MaskedSecret;
  scopes: string;
  username_claim: string;
  email_claim: string;
  groups_claim: string | null;
  admin_group: string | null;
  auto_provision: boolean;
  default_role: Role;
  callback_path: string;
}

export interface OidcConfigUpdate {
  enabled?: boolean;
  display_name?: string;
  issuer?: string | null;
  client_id?: string | null;
  client_secret?: string;
  scopes?: string;
  username_claim?: string;
  email_claim?: string;
  groups_claim?: string | null;
  admin_group?: string | null;
  auto_provision?: boolean;
  default_role?: Role;
}

export const getOidcConfig = () => api<OidcConfig>('/api/oidc/config');
export const updateOidcConfig = (body: OidcConfigUpdate) =>
  api<OidcConfig>('/api/oidc/config', { method: 'PUT', body });

/** Path the browser navigates to in order to begin an OIDC login. */
export const OIDC_LOGIN_PATH = '/api/auth/oidc/login';
