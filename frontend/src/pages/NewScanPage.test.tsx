import { beforeEach, describe, expect, it, vi } from 'vitest';

import { NewScanPage } from './NewScanPage';
import { renderWithProviders, screen, userEvent, waitFor } from '../test/render';

// Mock the API modules the page loads on mount. The registry/git-credential
// option fetches drive the P3-3 "couldn't load saved credentials" path; the
// scanner-settings prefill is stubbed to a benign resolve so it stays out of the
// way of the assertion.
vi.mock('../api/targets', () => ({
  listRegistryOptions: vi.fn(),
  listGitCredentialOptions: vi.fn(),
}));
vi.mock('../api/settings', () => ({
  getScannerSettings: vi.fn().mockResolvedValue({
    default_severities: ['HIGH', 'CRITICAL'],
    default_ignore_unfixed: false,
  }),
}));
// Give the page an operator so the form (and the credential fetch it guards) is
// enabled; the real AuthProvider does network work we don't want in a unit test.
vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({ user: { role: 'admin' } }),
}));

import { listGitCredentialOptions, listRegistryOptions } from '../api/targets';

const mockedRegistryOptions = vi.mocked(listRegistryOptions);
const mockedGitOptions = vi.mocked(listGitCredentialOptions);

describe('NewScanPage — P3-3 credential-load failure surfacing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows a retry warning when the credential-option fetch fails, and clears it on a successful retry', async () => {
    const user = userEvent.setup();

    // First load: both option fetches fail → the page must warn rather than
    // silently present empty pickers (which would read as "no credentials
    // configured" and invite an anonymous scan of a private target).
    mockedRegistryOptions.mockRejectedValueOnce(new Error('network down'));
    mockedGitOptions.mockRejectedValueOnce(new Error('network down'));

    renderWithProviders(<NewScanPage />);

    const warning = await screen.findByText(/Couldn't load saved credentials/i);
    expect(warning).toBeInTheDocument();

    // Retry: the fetches now succeed, so the warning must disappear.
    mockedRegistryOptions.mockResolvedValueOnce([]);
    mockedGitOptions.mockResolvedValueOnce([]);

    await user.click(screen.getByRole('button', { name: /retry/i }));

    await waitFor(() =>
      expect(screen.queryByText(/Couldn't load saved credentials/i)).not.toBeInTheDocument(),
    );
    expect(mockedRegistryOptions).toHaveBeenCalledTimes(2);
  });
});
