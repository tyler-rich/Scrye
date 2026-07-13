/** Scan API types and calls (hand-written shim; generated client comes later). */

import { api, apiUpload } from './client';

export type Scanner = 'trivy' | 'grype';
export type TargetType = 'image' | 'repository' | 'filesystem' | 'sbom';
export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'canceled';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'negligible' | 'unknown';
export type FindingClass = 'vulnerability' | 'misconfiguration' | 'secret' | 'license';
export type TrivyScannerName = 'vuln' | 'misconfig' | 'secret' | 'license';
export type TrivySeverity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SbomFormat = 'cyclonedx-json' | 'spdx-json' | 'syft-json';

/** Severity ordering (worst first) for display and sorting. */
export const SEVERITY_ORDER: Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'negligible',
  'unknown',
];

export interface Scan {
  id: number;
  scanner: Scanner;
  target_type: TargetType;
  target: string;
  status: ScanStatus;
  options: Record<string, unknown>;
  severity_counts: Record<string, number>;
  highest_severity: Severity | null;
  findings_count: number;
  scanner_version: string | null;
  error: string | null;
  created_by_username: string | null;
  tags: string[];
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Finding {
  id: number;
  finding_class: FindingClass;
  severity: Severity;
  vuln_id: string | null;
  pkg_name: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  title: string | null;
  description: string | null;
  location: string | null;
  primary_url: string | null;
}

export interface FindingsPage {
  total: number;
  items: Finding[];
}

export interface Artifact {
  id: number;
  kind: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
}

export interface CreateScanInput {
  scanner: Scanner;
  target_type?: TargetType;
  target: string;
  trivy_scanners?: TrivyScannerName[] | null;
  trivy_severity?: TrivySeverity[] | null;
  ignore_unfixed?: boolean;
  registry_id?: number | null;
  git_credential_id?: number | null;
  branch?: string | null;
  commit?: string | null;
  tag?: string | null;
  generate_sbom?: boolean;
  sbom_format?: SbomFormat | null;
}

/** True while a scan is still in a non-terminal state (worth polling). */
export function isActive(status: ScanStatus): boolean {
  return status === 'queued' || status === 'running';
}

export function listScans(
  params: { scanner?: Scanner; status?: ScanStatus } = {},
): Promise<Scan[]> {
  const query = new URLSearchParams();
  if (params.scanner) query.set('scanner', params.scanner);
  if (params.status) query.set('status', params.status);
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return api<Scan[]>(`/api/scans${suffix}`);
}

export function createScan(input: CreateScanInput): Promise<Scan> {
  return api<Scan>('/api/scans', { method: 'POST', body: input });
}

/** Launch a Grype scan of an uploaded SBOM file (multipart). */
export function createSbomScan(file: File, scanner: Scanner = 'grype'): Promise<Scan> {
  const form = new FormData();
  form.append('scanner', scanner);
  form.append('file', file);
  return apiUpload<Scan>('/api/scans/sbom', form);
}

export function getScan(id: number): Promise<Scan> {
  return api<Scan>(`/api/scans/${id}`);
}

export function cancelScan(id: number): Promise<Scan> {
  return api<Scan>(`/api/scans/${id}/cancel`, { method: 'POST' });
}

/** Delete a completed scan and all of its data (findings, artifacts, tags). */
export function deleteScan(id: number): Promise<void> {
  return api<void>(`/api/scans/${id}`, { method: 'DELETE' });
}

export function listFindings(
  id: number,
  params: {
    severity?: Severity;
    finding_class?: FindingClass;
    limit?: number;
    offset?: number;
  } = {},
): Promise<FindingsPage> {
  const query = new URLSearchParams();
  if (params.severity) query.set('severity', params.severity);
  if (params.finding_class) query.set('finding_class', params.finding_class);
  if (params.limit !== undefined) query.set('limit', String(params.limit));
  if (params.offset !== undefined) query.set('offset', String(params.offset));
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return api<FindingsPage>(`/api/scans/${id}/findings${suffix}`);
}

export function listArtifacts(id: number): Promise<Artifact[]> {
  return api<Artifact[]>(`/api/scans/${id}/artifacts`);
}

/** Direct browser download URL for a stored artifact (served by FastAPI). */
export function artifactDownloadUrl(scanId: number, artifactId: number): string {
  return `/api/scans/${scanId}/artifacts/${artifactId}/download`;
}

// --- Phase 4: history, filters, tags, diff, exports -------------------------

export type ExportFormat = 'json' | 'csv' | 'markdown';
export type HistorySort =
  | 'created_at'
  | 'findings_count'
  | 'target'
  | 'status'
  | 'scanner'
  | 'severity';
export type SortOrder = 'asc' | 'desc';

/** The full scan-history filter set (docs/PLAN.md §4.4). */
export interface HistoryFilters {
  scanner?: Scanner | null;
  target_type?: TargetType | null;
  q?: string | null;
  status?: ScanStatus | null;
  created_from?: string | null;
  created_to?: string | null;
  initiator?: string | null;
  highest_severity?: Severity | null;
  min_severity?: Severity | null;
  tags?: string[];
}

export interface HistoryQuery extends HistoryFilters {
  sort?: HistorySort;
  order?: SortOrder;
  limit?: number;
  offset?: number;
}

export interface ScanHistoryPage {
  total: number;
  items: Scan[];
}

export interface FilterOptions {
  initiators: string[];
  tags: string[];
}

export interface DiffFinding {
  finding_class: FindingClass;
  severity: Severity;
  vuln_id: string | null;
  pkg_name: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  title: string | null;
  location: string | null;
}

export interface ScanDiff {
  base_scan_id: number;
  compare_scan_id: number;
  target: string;
  scanner: Scanner;
  added: DiffFinding[];
  removed: DiffFinding[];
  unchanged_count: number;
  added_count: number;
  removed_count: number;
  severity_delta: Record<string, number>;
}

/** Serialize a set of history filters into URL query params (tags repeat). */
export function historyFilterParams(filters: HistoryFilters): URLSearchParams {
  const query = new URLSearchParams();
  if (filters.scanner) query.set('scanner', filters.scanner);
  if (filters.target_type) query.set('target_type', filters.target_type);
  if (filters.q) query.set('q', filters.q);
  if (filters.status) query.set('status', filters.status);
  if (filters.created_from) query.set('created_from', filters.created_from);
  if (filters.created_to) query.set('created_to', filters.created_to);
  if (filters.initiator) query.set('initiator', filters.initiator);
  if (filters.highest_severity) query.set('highest_severity', filters.highest_severity);
  if (filters.min_severity) query.set('min_severity', filters.min_severity);
  for (const tag of filters.tags ?? []) query.append('tags', tag);
  return query;
}

export function listHistory(query: HistoryQuery = {}): Promise<ScanHistoryPage> {
  const params = historyFilterParams(query);
  if (query.sort) params.set('sort', query.sort);
  if (query.order) params.set('order', query.order);
  if (query.limit !== undefined) params.set('limit', String(query.limit));
  if (query.offset !== undefined) params.set('offset', String(query.offset));
  const suffix = params.toString() ? `?${params.toString()}` : '';
  return api<ScanHistoryPage>(`/api/scans/history${suffix}`);
}

export function getFilterOptions(): Promise<FilterOptions> {
  return api<FilterOptions>('/api/scans/filter-options');
}

export function setScanTags(id: number, tags: string[]): Promise<Scan> {
  return api<Scan>(`/api/scans/${id}/tags`, { method: 'PUT', body: { tags } });
}

export function getScanDiff(baseId: number, compareId: number): Promise<ScanDiff> {
  return api<ScanDiff>(`/api/scans/${baseId}/diff/${compareId}`);
}

/** Browser download URL for a single scan's findings export. */
export function scanExportUrl(id: number, format: ExportFormat): string {
  return `/api/scans/${id}/export?format=${format}`;
}

/** Browser download URL for the filtered-history export. */
export function historyExportUrl(filters: HistoryFilters, format: ExportFormat): string {
  const params = historyFilterParams(filters);
  params.set('format', format);
  return `/api/scans/export?${params.toString()}`;
}
