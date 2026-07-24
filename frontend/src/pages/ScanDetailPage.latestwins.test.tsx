import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';

import { ScanDetailPage } from './ScanDetailPage';
import { act, renderWithProviders, screen, userEvent, waitFor } from '../test/render';

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

/** A finished scan — not polled, so the findings fetches are the only traffic. */
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

function finding(id: number, vulnId: string): Finding {
  return {
    id,
    finding_class: 'vulnerability',
    severity: 'high',
    vuln_id: vulnId,
    pkg_name: 'openssl',
    installed_version: '1.0.0',
    fixed_version: '1.0.1',
    title: null,
    description: null,
    location: null,
    primary_url: null,
  };
}

/** Result of the unfiltered fetch (resolves last) and of the filtered one. */
const UNFILTERED: FindingsPage = { total: 1, items: [finding(1, 'CVE-UNFILTERED')] };
const FILTERED: FindingsPage = { total: 1, items: [finding(2, 'CVE-FILTERED')] };

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

async function settle<T>(pending: { promise: Promise<T>; resolve: (value: T) => void }, value: T) {
  await act(async () => {
    pending.resolve(value);
    await pending.promise;
  });
}

describe('ScanDetailPage — M21 / P1-4 latest-wins on findings fetches', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetScan.mockResolvedValue(SCAN);
  });

  it('does not let a slow earlier response overwrite the current filter’s rows', async () => {
    const user = userEvent.setup();
    const slowUnfiltered = deferred<FindingsPage>();
    const fastFiltered = deferred<FindingsPage>();
    mockedListFindings
      .mockReturnValueOnce(slowUnfiltered.promise)
      .mockReturnValueOnce(fastFiltered.promise);

    renderWithProviders(
      <Routes>
        <Route path="/scans/:scanId" element={<ScanDetailPage />} />
      </Routes>,
      { initialEntries: ['/scans/7'] },
    );

    // The unfiltered fetch is issued on load and left hanging.
    await waitFor(() => expect(mockedListFindings).toHaveBeenCalledTimes(1));

    // Selecting a severity fires a second fetch for the narrowed view.
    await user.click(screen.getByRole('textbox', { name: 'Filter findings by severity' }));
    await user.click(await screen.findByRole('option', { name: 'high' }));
    await waitFor(() => expect(mockedListFindings).toHaveBeenCalledTimes(2));
    expect(mockedListFindings).toHaveBeenLastCalledWith(
      7,
      expect.objectContaining({
        severity: 'high',
      }),
    );

    await settle(fastFiltered, FILTERED);
    expect(await screen.findByText('CVE-FILTERED')).toBeInTheDocument();

    // The superseded response lands last and must be discarded.
    await settle(slowUnfiltered, UNFILTERED);

    expect(screen.queryByText('CVE-UNFILTERED')).not.toBeInTheDocument();
    expect(screen.getByText('CVE-FILTERED')).toBeInTheDocument();
  });
});
