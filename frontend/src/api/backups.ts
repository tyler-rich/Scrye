/** API types and calls for backup, restore, and scheduled backups. */

import { api, apiList, apiUpload } from './client';
import type { MaskedSecret } from './targets';

export interface BackupInfo {
  id: number;
  filename: string;
  size_bytes: number;
  checksum_sha256: string;
  kind: 'manual' | 'scheduled';
  app_version: string;
  created_at: string;
  created_by_username: string | null;
  note: string | null;
}

export interface RestoreResult {
  tables: number;
  rows: number;
  app_version: string;
}

export interface BackupSchedule {
  enabled: boolean;
  interval_hours: number;
  retention_count: number;
  passphrase: MaskedSecret;
  last_run_at: string | null;
  last_status: string | null;
}

export interface BackupScheduleUpdate {
  enabled?: boolean;
  interval_hours?: number;
  retention_count?: number;
  passphrase?: string;
}

export const listBackups = () => apiList<BackupInfo>('/api/backups');
export const createBackup = (passphrase: string, note?: string) =>
  api<BackupInfo>('/api/backups', { method: 'POST', body: { passphrase, note } });
export const deleteBackup = (id: number) => api<void>(`/api/backups/${id}`, { method: 'DELETE' });

/** URL to download a stored bundle (opened directly by the browser). */
export const backupDownloadUrl = (id: number) => `/api/backups/${id}/download`;

export function restoreBackup(file: File, passphrase: string): Promise<RestoreResult> {
  const form = new FormData();
  form.append('file', file);
  form.append('passphrase', passphrase);
  form.append('confirm', 'true');
  return apiUpload<RestoreResult>('/api/backups/restore', form);
}

export const getBackupSchedule = () => api<BackupSchedule>('/api/backups/schedule');
export const updateBackupSchedule = (body: BackupScheduleUpdate) =>
  api<BackupSchedule>('/api/backups/schedule', { method: 'PUT', body });
