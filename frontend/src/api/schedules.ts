/** API types and calls for scheduled/recurring scans (docs/ARCHIVE.md §4.6). */

import { api } from './client';
import type { Scanner, TargetType, TrivyScannerName, TrivySeverity } from './scans';

export interface ScanSchedule {
  id: number;
  name: string;
  enabled: boolean;
  cron: string;
  scanner: Scanner;
  target_type: TargetType;
  target: string;
  options: Record<string, unknown>;
  registry_id: number | null;
  git_credential_id: number | null;
  last_run_at: string | null;
  last_scan_id: number | null;
  last_status: string | null;
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanScheduleInput {
  name: string;
  cron: string;
  enabled: boolean;
  scanner: Scanner;
  target_type: TargetType;
  target: string;
  trivy_scanners?: TrivyScannerName[] | null;
  trivy_severity?: TrivySeverity[] | null;
  ignore_unfixed?: boolean;
  registry_id?: number | null;
  git_credential_id?: number | null;
  branch?: string | null;
}

export const listSchedules = () => api<ScanSchedule[]>('/api/scan-schedules');
export const createSchedule = (body: ScanScheduleInput) =>
  api<ScanSchedule>('/api/scan-schedules', { method: 'POST', body });
export const updateSchedule = (id: number, body: ScanScheduleInput) =>
  api<ScanSchedule>(`/api/scan-schedules/${id}`, { method: 'PUT', body });
export const deleteSchedule = (id: number) =>
  api<void>(`/api/scan-schedules/${id}`, { method: 'DELETE' });
export const runScheduleNow = (id: number) =>
  api<ScanSchedule>(`/api/scan-schedules/${id}/run`, { method: 'POST' });
