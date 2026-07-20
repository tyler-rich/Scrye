import { describe, expect, it } from 'vitest';

import { MAX_POLL_FAILURES, POLL_BASE_MS, POLL_MAX_MS, pollBackoffMs } from './polling';

describe('pollBackoffMs', () => {
  it('polls at the base cadence while healthy', () => {
    expect(pollBackoffMs(0)).toBe(POLL_BASE_MS);
    expect(pollBackoffMs(-1)).toBe(POLL_BASE_MS);
  });

  it('doubles the delay on each consecutive failure', () => {
    expect(pollBackoffMs(1)).toBe(2500);
    expect(pollBackoffMs(2)).toBe(5000);
    expect(pollBackoffMs(3)).toBe(10000);
    expect(pollBackoffMs(4)).toBe(20000);
  });

  it('caps the delay at the ceiling', () => {
    expect(pollBackoffMs(5)).toBe(POLL_MAX_MS);
    expect(pollBackoffMs(50)).toBe(POLL_MAX_MS);
  });

  it('never exceeds the ceiling before the poller gives up', () => {
    for (let f = 0; f <= MAX_POLL_FAILURES; f += 1) {
      expect(pollBackoffMs(f)).toBeLessThanOrEqual(POLL_MAX_MS);
    }
  });
});
