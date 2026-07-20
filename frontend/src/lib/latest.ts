/**
 * Latest-wins guard for out-of-order async responses (M21 / P1-4, L18 / P2-3).
 *
 * When a view fires overlapping fetches (a slow request for one filter, then a
 * fast request for another), the slow response can resolve last and overwrite
 * the UI with results for a filter no longer selected. Each fetch takes a token
 * from {@link begin} before it starts; when it resolves it renders only if its
 * token is still {@link isCurrent}. A newer fetch invalidates all older ones.
 */

export interface LatestGuard {
  /** Start a new request; returns its token and supersedes any prior request. */
  begin(): number;
  /** True only for the most recently begun request. */
  isCurrent(token: number): boolean;
}

/** Create an independent latest-wins guard (one per fetch stream). */
export function createLatestGuard(): LatestGuard {
  let latest = 0;
  return {
    begin(): number {
      latest += 1;
      return latest;
    },
    isCurrent(token: number): boolean {
      return token === latest;
    },
  };
}
