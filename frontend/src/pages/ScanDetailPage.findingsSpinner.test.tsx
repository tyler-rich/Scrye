import { Profiler } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';

import { ScanDetailPage } from './ScanDetailPage';
import { act, renderWithProviders, screen, waitFor } from '../test/render';

vi.mock('../api/scans', async () => {
  const actual = await vi.importActual<typeof import('../api/scans')>('../api/scans');
  return {
    ...actual,
    getScan: vi.fn(),
    listArtifacts: vi.fn().mockResolvedValue([]),
    listFindings: vi.fn(),
    setScanTags: vi.fn(),
    cancelScan: vi.fn(),
    deleteScan: vi.fn(),
  };
});
vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({ user: { role: 'admin' } }),
}));

import { getScan, listFindings, type Finding, type FindingsPage, type Scan } from '../api/scans';

const mockedGetScan = vi.mocked(getScan);
const mockedListFindings = vi.mocked(listFindings);

/** A finished scan, so no poll competes with the findings fetch. */
const SCAN: Scan = {
  id: 7,
  scanner: 'trivy',
  target_type: 'image',
  target: 'alpine:3.19',
  status: 'succeeded',
  severity_counts: { high: 1 },
  highest_severity: 'high',
  findings_count: 1,
  scanner_version: '0.58.0',
  has_error: false,
  created_by_username: 'admin',
  tags: [],
  created_at: '2026-07-24T00:00:00Z',
  started_at: '2026-07-24T00:00:00Z',
  finished_at: '2026-07-24T00:00:10Z',
  options: {},
  error: null,
};

const FOUND: FindingsPage = {
  total: 1,
  items: [
    {
      id: 1,
      finding_class: 'vulnerability',
      severity: 'high',
      vuln_id: 'CVE-2026-0001',
      pkg_name: 'openssl',
      installed_version: '1.0.0',
      fixed_version: '1.0.1',
      title: null,
      description: null,
      location: null,
      primary_url: null,
    } satisfies Finding,
  ],
};

const EMPTY_MESSAGE = 'No findings match the current filters.';

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function renderPage(onCommit?: () => void) {
  const page = (
    <Routes>
      <Route path="/scans/:scanId" element={<ScanDetailPage />} />
    </Routes>
  );
  return renderWithProviders(
    onCommit ? (
      <Profiler id="scan-detail" onRender={onCommit}>
        {page}
      </Profiler>
    ) : (
      page
    ),
    { initialEntries: ['/scans/7'] },
  );
}

describe('ScanDetailPage — findings loading state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetScan.mockResolvedValue(SCAN);
  });

  it('shows the loader while the findings request is in flight, then the rows', async () => {
    const pending = deferred<FindingsPage>();
    mockedListFindings.mockReturnValue(pending.promise);

    renderPage();

    expect(await screen.findByText('Loading findings')).toBeInTheDocument();
    expect(screen.queryByText(EMPTY_MESSAGE)).not.toBeInTheDocument();

    await act(async () => {
      pending.resolve(FOUND);
      await pending.promise;
    });

    expect(await screen.findByText('CVE-2026-0001')).toBeInTheDocument();
    expect(screen.queryByText('Loading findings')).not.toBeInTheDocument();
  });

  it('clears the loader and surfaces the error when the request fails', async () => {
    const pending = deferred<FindingsPage>();
    mockedListFindings.mockReturnValue(pending.promise);

    renderPage();
    expect(await screen.findByText('Loading findings')).toBeInTheDocument();

    await act(async () => {
      pending.reject(new Error('boom'));
      await pending.promise.catch(() => undefined);
    });

    expect(await screen.findByText('Failed to load findings.')).toBeInTheDocument();
    // A failed request is settled, not still running: the loader must go.
    await waitFor(() => expect(screen.queryByText('Loading findings')).not.toBeInTheDocument());
  });

  it('reports an empty result set once it has actually arrived', async () => {
    mockedListFindings.mockResolvedValue({ total: 0, items: [] });

    renderPage();

    expect(await screen.findByText(EMPTY_MESSAGE)).toBeInTheDocument();
  });

  it('never claims there are no findings while the first request is still running', async () => {
    const pending = deferred<FindingsPage>();
    mockedListFindings.mockReturnValue(pending.promise);

    // The window this guards is between the scan resolving as succeeded and the
    // findings arriving. A stored loading flag can only be raised from the
    // effect that starts the fetch — i.e. one commit *after* the scan lands —
    // so that commit renders an empty findings list with the loader already
    // down, and the table says there are no findings for a request that has
    // not answered yet.
    const emptyClaims: boolean[] = [];
    renderPage(() => emptyClaims.push(document.body.textContent?.includes(EMPTY_MESSAGE) ?? false));

    await waitFor(() => expect(mockedListFindings).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('Loading findings')).toBeInTheDocument();

    expect(emptyClaims.length).toBeGreaterThan(1);
    expect(emptyClaims).not.toContain(true);

    await act(async () => {
      pending.resolve(FOUND);
      await pending.promise;
    });
    expect(await screen.findByText('CVE-2026-0001')).toBeInTheDocument();
  });
});
