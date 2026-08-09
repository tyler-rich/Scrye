import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes, useNavigate } from 'react-router-dom';

import { ScanDetailPage } from './ScanDetailPage';
import { act, renderWithProviders, screen, userEvent, waitFor } from '../test/render';

vi.mock('../api/scans', async () => {
  const actual = await vi.importActual<typeof import('../api/scans')>('../api/scans');
  return {
    ...actual,
    getScan: vi.fn(),
    listArtifacts: vi.fn(),
    listFindings: vi.fn(),
    setScanTags: vi.fn(),
    cancelScan: vi.fn(),
    deleteScan: vi.fn(),
  };
});
vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({ user: { role: 'admin' } }),
}));

import {
  getScan,
  listArtifacts,
  listFindings,
  type Artifact,
  type Finding,
  type FindingsPage,
  type Scan,
} from '../api/scans';

const mockedGetScan = vi.mocked(getScan);
const mockedListArtifacts = vi.mocked(listArtifacts);
const mockedListFindings = vi.mocked(listFindings);

/** Two finished scans whose every visible field differs, so nothing that
 * survives the navigation can be mistaken for the new scan's own data. */
function scan(id: number, target: string, tags: string[]): Scan {
  return {
    id,
    scanner: 'trivy',
    target_type: 'image',
    target,
    status: 'succeeded',
    severity_counts: { high: 1 },
    highest_severity: 'high',
    findings_count: 1,
    scanner_version: '0.58.0',
    has_error: false,
    created_by_username: 'admin',
    tags,
    created_at: '2026-07-24T00:00:00Z',
    started_at: '2026-07-24T00:00:00Z',
    finished_at: '2026-07-24T00:00:10Z',
    options: {},
    error: null,
  };
}

const SCAN_1 = scan(1, 'alpine:3.19', ['scan-one-tag']);
const SCAN_2 = scan(2, 'debian:bookworm', ['scan-two-tag']);

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

function artifact(id: number, filename: string): Artifact {
  return {
    id,
    kind: 'raw',
    filename,
    content_type: 'application/json',
    size_bytes: 2048,
    sha256: 'a'.repeat(64),
    created_at: '2026-07-24T00:00:10Z',
  };
}

const FINDINGS_1: FindingsPage = { total: 1, items: [finding(11, 'CVE-SCAN-ONE')] };
const ARTIFACTS_1 = [artifact(21, 'scan-one-raw.json')];

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** Renders the route plus a control that navigates between the two scans, so
 * the test exercises a real `:scanId` change on a reused component instance —
 * which is the condition the reset effect exists for. */
function NavigateTo({ to }: { to: string }) {
  const navigate = useNavigate();
  return <button onClick={() => void navigate(to)}>go to {to}</button>;
}

describe('ScanDetailPage — L17 / P2-2 per-scan state reset on :scanId change', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('drops the previous scan’s header, findings, artifacts and tag draft on navigation', async () => {
    const user = userEvent.setup();
    // Scan 2's fetch is held open so the assertions land in the window the
    // reset effect protects: after the id changes, before the new data lands.
    const pendingScan2 = deferred<Scan>();
    mockedGetScan.mockImplementation((id: number) =>
      id === 1 ? Promise.resolve(SCAN_1) : pendingScan2.promise,
    );
    mockedListArtifacts.mockImplementation((id: number) =>
      Promise.resolve(id === 1 ? ARTIFACTS_1 : []),
    );
    mockedListFindings.mockImplementation((id: number) =>
      Promise.resolve(id === 1 ? FINDINGS_1 : { total: 0, items: [] }),
    );

    renderWithProviders(
      <>
        <NavigateTo to="/scans/2" />
        <Routes>
          <Route path="/scans/:scanId" element={<ScanDetailPage />} />
        </Routes>
      </>,
      { initialEntries: ['/scans/1'] },
    );

    // Scan 1 fully rendered: header, findings, artifacts.
    expect(await screen.findByText('Scan #1')).toBeInTheDocument();
    expect(screen.getByText('alpine:3.19')).toBeInTheDocument();
    expect(await screen.findByText('CVE-SCAN-ONE')).toBeInTheDocument();
    expect(await screen.findByText(/scan-one-raw\.json/)).toBeInTheDocument();

    // Edit the tag draft away from the server value, so it is state the poll
    // sync deliberately preserves (L16 / P2-1) and only the reset clears.
    const tagsInput = screen.getByRole('textbox', { name: 'Scan tags' });
    await user.click(tagsInput);
    await user.keyboard('draft-only-tag{Enter}');
    expect(await screen.findByText('draft-only-tag')).toBeInTheDocument();

    // Navigate. React Router reuses the component instance across this change.
    await user.click(screen.getByRole('button', { name: 'go to /scans/2' }));
    await waitFor(() => expect(mockedGetScan).toHaveBeenCalledWith(2));

    // While scan 2 is still in flight, nothing of scan 1 may remain on screen.
    expect(await screen.findByText('Loading scan')).toBeInTheDocument();
    expect(screen.queryByText('Scan #1')).not.toBeInTheDocument();
    expect(screen.queryByText('alpine:3.19')).not.toBeInTheDocument();
    expect(screen.queryByText('CVE-SCAN-ONE')).not.toBeInTheDocument();
    expect(screen.queryByText(/scan-one-raw\.json/)).not.toBeInTheDocument();
    expect(screen.queryByText('draft-only-tag')).not.toBeInTheDocument();

    // And once scan 2 lands, the stale draft must not reappear: `loadScan`
    // keeps a draft that diverges from the last synced tags, so an unreset
    // draft would survive the load as well as the navigation.
    await act(async () => {
      pendingScan2.resolve(SCAN_2);
      await pendingScan2.promise;
    });

    expect(await screen.findByText('Scan #2')).toBeInTheDocument();
    expect(screen.getByText('debian:bookworm')).toBeInTheDocument();
    expect(screen.getByText('scan-two-tag')).toBeInTheDocument();
    expect(screen.queryByText('draft-only-tag')).not.toBeInTheDocument();
    expect(screen.queryByText('scan-one-tag')).not.toBeInTheDocument();
    expect(screen.queryByText('CVE-SCAN-ONE')).not.toBeInTheDocument();
    expect(screen.queryByText(/scan-one-raw\.json/)).not.toBeInTheDocument();
  });
});
