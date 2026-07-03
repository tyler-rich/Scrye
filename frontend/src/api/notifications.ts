/** API types and calls for notification channels. */

import { api } from './client';
import type { MaskedSecret } from './targets';

export type NotificationType = 'webhook' | 'discord' | 'smtp' | 'matrix';

/** Channel types where a stored secret is optional (the rest require one). */
export const SECRET_OPTIONAL_TYPES: NotificationType[] = ['webhook'];

export interface NotificationChannel {
  id: number;
  name: string;
  type: NotificationType;
  config: Record<string, unknown>;
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
