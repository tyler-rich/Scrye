/**
 * Shared date formatting for backend timestamps (FE-3).
 *
 * The backend serializes **naive UTC** timestamps (no timezone offset), so
 * `new Date("2026-07-05T12:00:00")` would be parsed in the browser's *local*
 * zone and render hours off. Appending `Z` pins the parse to UTC before
 * converting to the viewer's locale. Centralized here so every screen renders
 * backend times consistently.
 */

/** Parse a naive-UTC backend timestamp into a Date (interpreted as UTC). */
export function parseUtc(iso: string): Date {
  // Already zoned (ends with Z or ±HH:MM)? Use as-is; otherwise mark it UTC.
  return /[Z+]|-\d{2}:\d{2}$/.test(iso) ? new Date(iso) : new Date(`${iso}Z`);
}

/** Format a backend timestamp in the viewer's locale, or a dash when absent. */
export function formatWhen(iso: string | null | undefined): string {
  if (!iso) return '—';
  const date = parseUtc(iso);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}
