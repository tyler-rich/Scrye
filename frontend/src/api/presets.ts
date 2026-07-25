/** Saved scan-history filter presets (docs/ARCHIVE.md §4.4). Owner-scoped. */

import { api, apiList } from './client';
import type { HistoryFilters } from './scans';

export interface FilterPreset {
  id: number;
  name: string;
  filters: HistoryFilters;
  created_at: string;
  updated_at: string;
}

export function listPresets(): Promise<FilterPreset[]> {
  return apiList<FilterPreset>('/api/filter-presets');
}

export function createPreset(name: string, filters: HistoryFilters): Promise<FilterPreset> {
  return api<FilterPreset>('/api/filter-presets', {
    method: 'POST',
    body: { name, filters },
  });
}

export function updatePreset(
  id: number,
  name: string,
  filters: HistoryFilters,
): Promise<FilterPreset> {
  return api<FilterPreset>(`/api/filter-presets/${id}`, {
    method: 'PUT',
    body: { name, filters },
  });
}

export function deletePreset(id: number): Promise<void> {
  return api<void>(`/api/filter-presets/${id}`, { method: 'DELETE' });
}
