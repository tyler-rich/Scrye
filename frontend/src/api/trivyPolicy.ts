/** API types and calls for Trivy VEX documents and ignore rules (§4.1/§4.5). */

import { api } from './client';

export type VexFormat = 'openvex' | 'cyclonedx' | 'csaf';

export interface VexDocument {
  id: number;
  name: string;
  enabled: boolean;
  format: VexFormat;
  content: string;
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface VexDocumentInput {
  name: string;
  format: VexFormat;
  content: string;
  enabled: boolean;
}

export interface IgnoreRule {
  id: number;
  vuln_id: string;
  reason: string | null;
  expires_at: string | null;
  enabled: boolean;
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface IgnoreRuleInput {
  vuln_id: string;
  reason?: string | null;
  expires_at?: string | null;
  enabled: boolean;
}

export const listVexDocuments = () => api<VexDocument[]>('/api/trivy/vex-documents');
export const createVexDocument = (body: VexDocumentInput) =>
  api<VexDocument>('/api/trivy/vex-documents', { method: 'POST', body });
export const deleteVexDocument = (id: number) =>
  api<void>(`/api/trivy/vex-documents/${id}`, { method: 'DELETE' });

export const listIgnoreRules = () => api<IgnoreRule[]>('/api/trivy/ignore-rules');
export const createIgnoreRule = (body: IgnoreRuleInput) =>
  api<IgnoreRule>('/api/trivy/ignore-rules', { method: 'POST', body });
export const deleteIgnoreRule = (id: number) =>
  api<void>(`/api/trivy/ignore-rules/${id}`, { method: 'DELETE' });
