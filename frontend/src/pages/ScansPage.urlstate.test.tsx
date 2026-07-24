import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useLocation } from 'react-router-dom';

import { ScansPage } from './ScansPage';
import { renderWithProviders, screen, userEvent, waitFor } from '../test/render';

// Keep the pure helpers (historyFilterParams, SEVERITY_ORDER, …) real — only the
// two network calls the page makes on mount are stubbed.
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

/** Renders the live router location so a test can assert the URL query string. */
function LocationProbe() {
  const location = useLocation();
  return <div data-testid="loc">{location.search}</div>;
}

describe('ScansPage — P3-1 URL-mirrored history view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedListHistory.mockResolvedValue({ total: 0, items: [] });
    mockedFilterOptions.mockResolvedValue({ initiators: [], tags: [] });
  });

  it('mirrors an entered filter into the URL query string', async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <>
        <ScansPage />
        <LocationProbe />
      </>,
      { initialEntries: ['/scans'] },
    );

    await user.type(screen.getByLabelText('Target search'), 'nginx');

    await waitFor(() => expect(screen.getByTestId('loc').textContent).toContain('q=nginx'));
  });

  it('restores filters, sort, and page from the URL on a fresh render', async () => {
    renderWithProviders(<ScansPage />, {
      initialEntries: ['/scans?q=nginx&scanner=grype&status=failed&sort=target&order=asc&page=3'],
    });

    // The text control reflects the restored view…
    expect(screen.getByLabelText('Target search')).toHaveValue('nginx');

    // …and the first fetch is issued for that exact view (scanner/status/sort
    // restored, page 3 → offset 50).
    await waitFor(() =>
      expect(mockedListHistory).toHaveBeenCalledWith(
        expect.objectContaining({
          q: 'nginx',
          scanner: 'grype',
          status: 'failed',
          sort: 'target',
          order: 'asc',
          limit: 25,
          offset: 50,
        }),
      ),
    );
  });
});
