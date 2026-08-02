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

/**
 * The caller's own OIDC link state.
 *
 * Note what is *absent*: there is no subject field, here or in any request type
 * below. The subject is read only from a verified ID token on the server and is
 * never typed, chosen, or displayed — that is the whole point of the feature.
 */
export interface OidcLinkStatus {
  linked: boolean;
  issuer: string | null;
  email: string | null;
  linked_at: string | null;
  /** When the link was last used to sign in; `null` if it never has. */
  last_login_at: string | null;
  /** OIDC is enabled and fully configured, so a link can be started. */
  provider_ready: boolean;
  display_name: string;
  /** The account has TOTP active, so the re-auth form must collect a code. */
  mfa_enrolled: boolean;
  /** Linking would create a sign-in path that skips this account's local MFA. */
  mfa_delegation_warning: boolean;
}

/**
 * Fresh full re-authentication, required to link *and* to unlink.
 *
 * A live session is deliberately not sufficient: linking creates a new way to
 * sign in to the account, so it costs the password (and the second factor, when
 * enrolled) to create one. See the README security model.
 */
export interface OidcReauth {
  current_password: string;
  totp_code?: string;
}

export const getOidcLinkStatus = () => api<OidcLinkStatus>('/api/auth/oidc/link');

/**
 * Begin a link flow and return the provider URL the browser must navigate to.
 * The response also sets the short-lived, HttpOnly browser-binding cookie that
 * confines the flow to this browser.
 */
export const startOidcLink = (body: OidcReauth) =>
  api<{ authorization_url: string }>('/api/auth/oidc/link', { method: 'POST', body });

export const unlinkOidcIdentity = (body: OidcReauth) =>
  api<void>('/api/auth/oidc/link', { method: 'DELETE', body });
