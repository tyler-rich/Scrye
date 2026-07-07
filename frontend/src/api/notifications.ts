/** API types and calls for notification channels. */

import { api } from './client';
import type { MaskedSecret } from './targets';

export type NotificationType = 'webhook' | 'discord' | 'smtp' | 'matrix';
export type NotificationEvent = 'scan_completed' | 'scan_failed' | 'scan_high_severity';

/** Channel types where a stored secret is optional. None: webhook/Discord treat
 *  their URL as the write-only credential, and SMTP/Matrix require a secret. */
export const SECRET_OPTIONAL_TYPES: NotificationType[] = [];

/** Channel types whose URL is the write-only credential (stored encrypted). */
export const URL_SECRET_TYPES: NotificationType[] = ['webhook', 'discord'];

/** Human labels for the notification events a channel can subscribe to. */
export const EVENT_LABELS: Record<NotificationEvent, string> = {
  scan_completed: 'Scan completed',
  scan_failed: 'Scan failed',
  scan_high_severity: 'Critical/High findings',
};

export interface NotificationChannel {
  id: number;
  name: string;
  type: NotificationType;
  config: Record<string, unknown>;
  events: NotificationEvent[];
  enabled: boolean;
  secret: MaskedSecret;
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface NotificationChannelCreate {
  name: string;
  type: NotificationType;
  config: Record<string, unknown>;
  events?: NotificationEvent[];
  secret?: string | null;
  enabled?: boolean;
}

export interface NotificationTestResult {
  ok: boolean;
  detail: string;
}

export const listChannels = () => api<NotificationChannel[]>('/api/notifications');
export const createChannel = (body: NotificationChannelCreate) =>
  api<NotificationChannel>('/api/notifications', { method: 'POST', body });
export const deleteChannel = (id: number) =>
  api<void>(`/api/notifications/${id}`, { method: 'DELETE' });
export const testChannel = (id: number) =>
  api<NotificationTestResult>(`/api/notifications/${id}/test`, { method: 'POST' });
