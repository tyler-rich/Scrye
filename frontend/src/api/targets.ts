/** API types and calls for registries, git credentials, and Docker environments. */

import { api, apiList } from './client';

export interface MaskedSecret {
  is_set: boolean;
  value: string;
  updated_at: string | null;
}

/**
 * Minimal id/name pair for picking a credential when launching a scan.
 *
 * The full registry/git-credential lists (with host, username, etc.) are
 * admin-only; operators select from these id/name options instead.
 */
export interface CredentialOption {
  id: number;
  name: string;
}

// --- Registries --------------------------------------------------------------

export type RegistryAuthType =
  | 'username_password'
  | 'token'
  | 'aws_ecr'
  | 'google_gcr'
  | 'azure_acr';

/** Auth types that carry a stored secret (the rest use a credential helper). */
export const SECRET_BEARING_AUTH_TYPES: RegistryAuthType[] = ['username_password', 'token'];

export interface Registry {
  id: number;
  name: string;
  registry_host: string;
  auth_type: RegistryAuthType;
  username: string | null;
  enabled: boolean;
  secret: MaskedSecret;
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface RegistryCreateInput {
  name: string;
  registry_host: string;
  auth_type: RegistryAuthType;
  username?: string | null;
  secret?: string | null;
  enabled?: boolean;
}

export interface RegistryTestResult {
  ok: boolean;
  detail: string;
}

export function listRegistries(): Promise<Registry[]> {
  return apiList<Registry>('/api/registries');
}

/** Operator-accessible id/name options for the scan-launch registry picker. */
export function listRegistryOptions(): Promise<CredentialOption[]> {
  return api<CredentialOption[]>('/api/registries/options');
}

export function createRegistry(input: RegistryCreateInput): Promise<Registry> {
  return api<Registry>('/api/registries', { method: 'POST', body: input });
}

export function deleteRegistry(id: number): Promise<void> {
  return api<void>(`/api/registries/${id}`, { method: 'DELETE' });
}

export function testRegistry(id: number): Promise<RegistryTestResult> {
  return api<RegistryTestResult>(`/api/registries/${id}/test`, { method: 'POST' });
}

// --- Git credentials ---------------------------------------------------------

export type GitProvider = 'github' | 'gitlab' | 'generic';

export interface GitCredential {
  id: number;
  name: string;
  provider: GitProvider;
  host: string | null;
  username: string | null;
  token: MaskedSecret;
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface GitCredentialCreateInput {
  name: string;
  provider: GitProvider;
  host?: string | null;
  username?: string | null;
  token: string;
}

export function listGitCredentials(): Promise<GitCredential[]> {
  return apiList<GitCredential>('/api/git-credentials');
}

/** Operator-accessible id/name options for the scan-launch git-credential picker. */
export function listGitCredentialOptions(): Promise<CredentialOption[]> {
  return api<CredentialOption[]>('/api/git-credentials/options');
}

export function createGitCredential(input: GitCredentialCreateInput): Promise<GitCredential> {
  return api<GitCredential>('/api/git-credentials', { method: 'POST', body: input });
}

export function deleteGitCredential(id: number): Promise<void> {
  return api<void>(`/api/git-credentials/${id}`, { method: 'DELETE' });
}

// --- Docker environments -----------------------------------------------------

export interface DockerEnvironment {
  id: number;
  name: string;
  proxy_url: string;
  risk_acknowledged: boolean;
  enabled: boolean;
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface DockerEnvironmentCreateInput {
  name: string;
  proxy_url: string;
  risk_acknowledged: boolean;
  enabled?: boolean;
}

export interface DockerImage {
  id: string;
  tags: string[];
  size_bytes: number;
}

export function listDockerEnvironments(): Promise<DockerEnvironment[]> {
  return apiList<DockerEnvironment>('/api/docker-environments');
}

export function createDockerEnvironment(
  input: DockerEnvironmentCreateInput,
): Promise<DockerEnvironment> {
  return api<DockerEnvironment>('/api/docker-environments', { method: 'POST', body: input });
}

export function updateDockerEnvironment(
  id: number,
  input: Partial<DockerEnvironmentCreateInput>,
): Promise<DockerEnvironment> {
  return api<DockerEnvironment>(`/api/docker-environments/${id}`, {
    method: 'PATCH',
    body: input,
  });
}

export function deleteDockerEnvironment(id: number): Promise<void> {
  return api<void>(`/api/docker-environments/${id}`, { method: 'DELETE' });
}

export function enumerateImages(id: number): Promise<DockerImage[]> {
  return api<DockerImage[]>(`/api/docker-environments/${id}/images`);
}
