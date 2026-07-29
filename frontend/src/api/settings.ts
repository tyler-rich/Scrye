/** API types and calls for general/authentication/scanner settings and About. */

import { api } from './client';

export interface GeneralSettings {
  instance_name: string;
  admin_note: string;
}

export type MfaPolicy = 'optional' | 'required_admin' | 'required_all';

export interface AuthSettings {
  local_login_enabled: boolean;
  mfa_policy: MfaPolicy;
}

export interface ScannerSettings {
  default_severities: string[];
  default_ignore_unfixed: boolean;
  trivyignore: string;
  grype_ignore: string;
  auto_update_db: boolean;
  db_update_interval_hours: number;
}

export interface ScannerInfo {
  name: string;
  available: boolean;
  version: string | null;
  detail: string | null;
}

/**
 * Which master key the instance is using. Never key material — only the source
 * and the path. Admin-only: the API omits it for other roles.
 */
export interface MasterKeyInfo {
  source: 'auto_generated' | 'secret_file';
  path: string;
}

export interface AboutInfo {
  app_name: string;
  version: string;
  status: string;
  database: string;
  python_version: string;
  platform: string;
  user_count: number;
  scan_count: number;
  oidc_enabled: boolean;
  scanners: ScannerInfo[];
  /** Admin-only; null for other roles and when no key is resolvable. */
  master_key: MasterKeyInfo | null;
}

export const getGeneralSettings = () => api<GeneralSettings>('/api/settings/general');
export const updateGeneralSettings = (body: GeneralSettings) =>
  api<GeneralSettings>('/api/settings/general', { method: 'PUT', body });

export const getAuthSettings = () => api<AuthSettings>('/api/settings/authentication');
export const updateAuthSettings = (body: AuthSettings) =>
  api<AuthSettings>('/api/settings/authentication', { method: 'PUT', body });

export const getScannerSettings = () => api<ScannerSettings>('/api/settings/scanners');
export const updateScannerSettings = (body: ScannerSettings) =>
  api<ScannerSettings>('/api/settings/scanners', { method: 'PUT', body });

export interface RetentionSettings {
  enabled: boolean;
  max_age_days: number;
}

export const getRetentionSettings = () => api<RetentionSettings>('/api/settings/retention');
export const updateRetentionSettings = (body: RetentionSettings) =>
  api<RetentionSettings>('/api/settings/retention', { method: 'PUT', body });

export const getAbout = () => api<AboutInfo>('/api/settings/about');
