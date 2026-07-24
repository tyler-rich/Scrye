import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';

import { ScanDetailPage } from './ScanDetailPage';
import { ApiError } from '../api/client';
import { MAX_POLL_FAILURES, POLL_BASE_MS } from '../lib/polling';
import { act, renderWithProviders, screen } from '../test/render';

// Keep the pure helpers (`isActive`, `SEVERITY_ORDER`, …) real — only the
// network calls are stubbed. `getScan` is the one the poller drives.
vi.mock('../api/scans', async () => {
  const actual = await vi.importActual<typeof import('../api/scans')>('../api/scans');
  return {
    ...actual,
    getScan: vi.fn(),
    listArtifacts: vi.fn().mockResolvedValue([]),
    listFindings: vi.fn().mockResolvedValue({ total: 0, items: [] }),
    setScanTags: vi.fn(),
    cancelScan: vi.fn(),
    deleteScan: vi.fn(),
  };
});
vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({ user: { role: 'admin' } }),
}));

import { getScan, type Scan } from '../api/scans';

const mockedGetScan = vi.mocked(getScan);

/** A running scan — `isActive` is true, so the page polls it. */
const RUNNING_SCAN: Scan = {
  id: 7,
  scanner: 'trivy',
  target_type: 'image',
  target: 'alpine:3.19',
  status: 'running',
  severity_counts: {},
  highest_severity: null,
  findings_count: 0,
  scanner_version: null,
  has_error: false,
  created_by_username: 'admin',
  tags: [],
  created_at: '2026-07-24T00:00:00Z',
  started_at: '2026-07-24T00:00:01Z',
  finished_at: null,
  options: {},
  error: null,
};

function renderDetail() {
  return renderWithProviders(
    <Routes>
      <Route path="/scans/:scanId" element={<ScanDetailPage />} />
    </Routes>,
    { initialEntries: ['/scans/7'] },
  );
}

/** Advance fake time and let every resulting promise/state update settle. */
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

/** Flush the mount fetch without moving the clock. */
async function flush() {
  await act(async () => {});
}

describe('ScanDetailPage — M20 / P1-3 poller backoff and halt', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('backs off exponentially instead of re-polling at the base cadence', async () => {
    // The scan loads once, then every poll fails.
    mockedGetScan.mockResolvedValueOnce(RUNNING_SCAN).mockRejectedValue(new Error('backend down'));

    renderDetail();
    await flush();
    expect(mockedGetScan).toHaveBeenCalledTimes(1);

    // First poll at the base cadence — it fails.
    await advance(POLL_BASE_MS);
    expect(mockedGetScan).toHaveBeenCalledTimes(2);

    // Second poll 2.5 s later — also fails.
    await advance(2_500);
    expect(mockedGetScan).toHaveBeenCalledTimes(3);

    // The third retry is now delayed to 5 s, not 2.5 s: at t=9 s a fixed-cadence
    // poller would already have issued its fourth request.
    await advance(4_000);
    expect(mockedGetScan).toHaveBeenCalledTimes(3);

    await advance(1_000);
    expect(mockedGetScan).toHaveBeenCalledTimes(4);
  });

  it('halts at the failure ceiling and surfaces the paused alert', async () => {
    mockedGetScan.mockResolvedValueOnce(RUNNING_SCAN).mockRejectedValue(new Error('backend down'));

    renderDetail();
    await flush();

    // 2.5 + 2.5 + 5 + 10 + 20 = 40 s covers all five permitted failures.
    await advance(60_000);

    // One successful load plus exactly MAX_POLL_FAILURES failed polls.
    expect(mockedGetScan).toHaveBeenCalledTimes(1 + MAX_POLL_FAILURES);
    expect(screen.getByText('Auto-refresh paused')).toBeInTheDocument();

    // And it stays stopped rather than hammering behind a stale "running" badge.
    await advance(300_000);
    expect(mockedGetScan).toHaveBeenCalledTimes(1 + MAX_POLL_FAILURES);
  });

  it('halts immediately when the scan 404s', async () => {
    mockedGetScan
      .mockResolvedValueOnce(RUNNING_SCAN)
      .mockRejectedValue(new ApiError(404, 'Not Found'));

    renderDetail();
    await flush();

    await advance(POLL_BASE_MS);
    expect(mockedGetScan).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/no longer exists/i)).toBeInTheDocument();

    // A deleted scan is never coming back — no retry, at any delay.
    await advance(300_000);
    expect(mockedGetScan).toHaveBeenCalledTimes(2);
  });
});
