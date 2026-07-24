import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ScansPage } from './ScansPage';
import { renderWithProviders, screen, userEvent, waitFor } from '../test/render';
import type { ScanSummary } from '../api/scans';

vi.mock('../api/scans', async () => {
  const actual = await vi.importActual<typeof import('../api/scans')>('../api/scans');
  return {
    ...actual,
    listHistory: vi.fn(),
    getFilterOptions: vi.fn(),
  };
});
vi.mock('../api/presets', () => ({
  listPresets: vi.fn().mockResolvedValue([]),
  createPreset: vi.fn(),
  deletePreset: vi.fn(),
}));

import { getFilterOptions, listHistory } from '../api/scans';

const mockedListHistory = vi.mocked(listHistory);
const mockedFilterOptions = vi.mocked(getFilterOptions);

/** A minimal ScanSummary row; the two rows share scanner/target so a compare is
 * valid, which keeps the tests focused on the selection-reconcile behavior. */
function row(id: number): ScanSummary {
  return {
    id,
    scanner: 'trivy',
    target_type: 'image',
    target: 'nginx:latest',
    status: 'succeeded',
    severity_counts: {},
    highest_severity: null,
    findings_count: 0,
    scanner_version: null,
    has_error: false,
    created_by_username: 'admin',
    tags: [],
    created_at: '2026-07-01T00:00:00Z',
    started_at: null,
    finished_at: null,
  };
}

describe('ScansPage — P3-2 compare selection reconciliation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedFilterOptions.mockResolvedValue({ initiators: [], tags: [] });
  });

  it('drops a selection that filters/pages out of the visible rows', async () => {
    const user = userEvent.setup();
    mockedListHistory.mockResolvedValue({ total: 2, items: [row(1), row(2)] });

    renderWithProviders(<ScansPage />, { initialEntries: ['/scans'] });

    await user.click(await screen.findByLabelText('Select scan 1 to compare'));
    // Compare bar (and its action button) appear once a row is selected.
    expect(screen.getByRole('button', { name: /Compare scans/i })).toBeInTheDocument();

    // A reload where scan 1 is no longer in the results must clear the now
    // unreachable selection rather than leave a phantom "1/2 selected".
    mockedListHistory.mockResolvedValue({ total: 1, items: [row(2)] });
    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /Compare scans/i })).not.toBeInTheDocument(),
    );
  });

  it('drops a selected scan that was deleted, keeping the still-present one', async () => {
    const user = userEvent.setup();
    mockedListHistory.mockResolvedValue({ total: 2, items: [row(1), row(2)] });

    renderWithProviders(<ScansPage />, { initialEntries: ['/scans'] });

    await user.click(await screen.findByLabelText('Select scan 1 to compare'));
    await user.click(screen.getByLabelText('Select scan 2 to compare'));
    expect(screen.getByRole('button', { name: /Compare scans/i })).toBeInTheDocument();

    // Scan 1 was deleted elsewhere: the next reload returns only scan 2.
    mockedListHistory.mockResolvedValue({ total: 1, items: [row(2)] });
    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    // The deleted row (and its selection) is gone; scan 2 stays selected, so a
    // diff can never be launched against the 404'ing deleted scan.
    await waitFor(() =>
      expect(screen.queryByLabelText('Select scan 1 to compare')).not.toBeInTheDocument(),
    );
    expect(screen.getByLabelText('Select scan 2 to compare')).toBeChecked();
    expect(screen.getByRole('button', { name: /Compare scans/i })).toBeInTheDocument();
  });
});
