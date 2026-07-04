/** API types and calls for the dashboard aggregate widgets (docs/PLAN.md §4.6). */

import { api } from './client';
import type { Scan } from './scans';

export interface TargetPosture {
  scanner: string;
  target_type: string;
  target: string;
  critical: number;
  high: number;
  total: number;
}

export interface ScannerDbInfo {
  name: string;
  available: boolean;
  updated_at: string | null;
  next_update: string | null;
  detail: string | null;
}

export interface FailedAlert {
  id: number;
  scanner: string;
  target: string;
  error: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface TimePoint {
  date: string;
  count: number;
}

export interface Dashboard {
  total_scans: number;
  scans_by_status: Record<string, number>;
  scans_by_scanner: Record<string, number>;
  open_critical: number;
  open_high: number;
  scans_over_time: TimePoint[];
  top_vulnerable_targets: TargetPosture[];
  recent_scans: Scan[];
  failed_alerts: FailedAlert[];
  scanner_db: ScannerDbInfo[];
  schedules_enabled: number;
  schedules_total: number;
}

export const getDashboard = () => api<Dashboard>('/api/dashboard');
