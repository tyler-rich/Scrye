import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ScansPage } from './ScansPage';
import { act, fireEvent, renderWithProviders, screen, waitFor } from '../test/render';

// Keep the pure helpers real; stub only the two network calls the page makes.
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

import { getFilterOptions, listHistory, type ScanSummary } from '../api/scans';

const mockedListHistory = vi.mocked(listHistory);
const mockedFilterOptions = vi.mocked(getFilterOptions);

type HistoryPage = { total: number; items: ScanSummary[] };

function row(id: number, target: string): ScanSummary {
  return {
    id,
    scanner: 'trivy',
    target_type: 'image',
    target,
    status: 'succeeded',
    severity_counts: {},
    highest_severity: null,
    findings_count: 0,
    scanner_version: null,
    has_error: false,
    created_by_username: 'admin',
    tags: [],
    created_at: '2026-07-24T00:00:00Z',
    started_at: '2026-07-24T00:00:00Z',
    finished_at: '2026-07-24T00:00:10Z',
  };
}

/** Rows for the unfiltered view (the request that will resolve *last*). */
const UNFILTERED: HistoryPage = { total: 1, items: [row(1, 'unfiltered-result')] };
/** Rows for the filtered view (the request that resolves *first*). */
const FILTERED: HistoryPage = { total: 1, items: [row(2, 'filtered-result')] };

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

describe('ScansPage — M21 / P1-4 latest-wins on history fetches', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedFilterOptions.mockResolvedValue({ initiators: [], tags: [] });
  });

  it('does not let a slow earlier response overwrite the current filter’s rows', async () => {
    // The debounce delays *sending* but never cancels an in-flight request, so
    // the unfiltered request stays outstanding while the filtered one is made.
    const slowUnfiltered = deferred<HistoryPage>();
    const fastFiltered = deferred<HistoryPage>();
    mockedListHistory
      .mockReturnValueOnce(slowUnfiltered.promise)
      .mockReturnValueOnce(fastFiltered.promise);

    renderWithProviders(<ScansPage />, { initialEntries: ['/scans'] });

    // The initial (unfiltered) request is issued and left hanging.
    await waitFor(() => expect(mockedListHistory).toHaveBeenCalledTimes(1));

    // The operator narrows the view; a second request goes out for that filter.
    fireEvent.change(screen.getByLabelText('Target search'), { target: { value: 'nginx' } });
    await waitFor(() => expect(mockedListHistory).toHaveBeenCalledTimes(2));
    expect(mockedListHistory).toHaveBeenLastCalledWith(expect.objectContaining({ q: 'nginx' }));

    // The newer request answers first and renders.
    await settle(fastFiltered, FILTERED);
    expect(await screen.findByText('filtered-result')).toBeInTheDocument();

    // Only now does the superseded request land. It must be discarded: rendering
    // it would show rows that contradict the filter still in the search box.
    await settle(slowUnfiltered, UNFILTERED);

    expect(screen.queryByText('unfiltered-result')).not.toBeInTheDocument();
    expect(screen.getByText('filtered-result')).toBeInTheDocument();
    expect(screen.getByLabelText('Target search')).toHaveValue('nginx');
  });

  it('still renders a response that is the latest when it resolves', async () => {
    mockedListHistory.mockResolvedValue(UNFILTERED);

    renderWithProviders(<ScansPage />, { initialEntries: ['/scans'] });

    expect(await screen.findByText('unfiltered-result')).toBeInTheDocument();
  });
});
