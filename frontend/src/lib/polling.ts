/**
 * Polling backoff for the scan-detail status poller (M20 / P1-3).
 *
 * The scan-detail page polls a running scan every few seconds. When the
 * endpoint starts failing (backend restart, expired session, deleted scan) the
 * poller must not hammer it forever at the fast cadence — it backs off
 * exponentially on consecutive failures and gives up after a ceiling so the UI
 * can surface the error instead of silently retrying behind a stale "running"
 * badge.
 */

/** Base poll interval while the scan is healthy and active (ms). */
export const POLL_BASE_MS = 2500;

/** Upper bound on the backoff delay between failing polls (ms). */
export const POLL_MAX_MS = 30_000;

/** Consecutive failures after which the poller stops and surfaces the error. */
export const MAX_POLL_FAILURES = 5;

/**
 * Delay before the next poll given the count of consecutive failures so far.
 *
 * Zero failures polls at the base cadence; each subsequent failure doubles the
 * delay (2.5s → 5s → 10s → 20s → capped at {@link POLL_MAX_MS}).
 */
export function pollBackoffMs(consecutiveFailures: number): number {
  if (consecutiveFailures <= 0) return POLL_BASE_MS;
  return Math.min(POLL_BASE_MS * 2 ** (consecutiveFailures - 1), POLL_MAX_MS);
}
