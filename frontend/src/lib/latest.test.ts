import { describe, expect, it } from 'vitest';

import { createLatestGuard } from './latest';

describe('createLatestGuard', () => {
  it('treats the only in-flight request as current', () => {
    const guard = createLatestGuard();
    const token = guard.begin();
    expect(guard.isCurrent(token)).toBe(true);
  });

  it('invalidates an earlier request once a newer one begins', () => {
    const guard = createLatestGuard();
    const first = guard.begin();
    const second = guard.begin();
    // Out-of-order resolution: the stale first response must not win.
    expect(guard.isCurrent(first)).toBe(false);
    expect(guard.isCurrent(second)).toBe(true);
  });

  it('only ever considers the most recent token current', () => {
    const guard = createLatestGuard();
    const tokens = [guard.begin(), guard.begin(), guard.begin()];
    expect(tokens.filter((t) => guard.isCurrent(t))).toEqual([tokens[2]]);
  });

  it('keeps independent guards isolated', () => {
    const a = createLatestGuard();
    const b = createLatestGuard();
    const aToken = a.begin();
    b.begin();
    expect(a.isCurrent(aToken)).toBe(true);
  });
});
