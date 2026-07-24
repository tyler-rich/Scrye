import { beforeEach, describe, expect, it, vi } from 'vitest';

import { NewScanPage } from './NewScanPage';
import { act, renderWithProviders, screen, userEvent, waitFor } from '../test/render';

vi.mock('../api/targets', () => ({
  listRegistryOptions: vi.fn().mockResolvedValue([]),
  listGitCredentialOptions: vi.fn().mockResolvedValue([]),
}));
vi.mock('../api/settings', () => ({
  getScannerSettings: vi.fn(),
}));
vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({ user: { role: 'admin' } }),
}));

import { getScannerSettings, type ScannerSettings } from '../api/settings';

const mockedScannerSettings = vi.mocked(getScannerSettings);

/** Instance defaults, distinct from the form's built-in values (all severities
 *  selected, ignore-unfixed off) so a clobber is visible. */
const INSTANCE_DEFAULTS: ScannerSettings = {
  default_severities: ['CRITICAL'],
  default_ignore_unfixed: true,
  trivyignore: '',
  grype_ignore: '',
  auto_update_db: true,
  db_update_interval_hours: 24,
};

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

/**
 * The severity values currently *selected* in the MultiSelect. Mantine keeps
 * every dropdown option mounted, so the selected pills are isolated by dropping
 * anything that sits inside an `option`.
 */
function selectedSeverities(): string[] {
  return screen
    .getAllByText(/^(UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL)$/)
    .filter((el) => el.closest('[role="option"]') === null)
    .map((el) => el.textContent ?? '');
}

/**
 * Unlike the settings panels, this form's inputs are *not* gated on the
 * prefill fetch — the operator can start composing a scan immediately. That
 * makes the dirty-form half of M19 / P1-2 reachable here: a slow
 * `getScannerSettings` must not silently revert edits already made.
 */
describe('NewScanPage — M19 / P1-2 prefill does not clobber a dirty form', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('leaves an edited form alone when the scanner-defaults prefill lands late', async () => {
    const user = userEvent.setup();
    const pending = deferred<ScannerSettings>();
    mockedScannerSettings.mockReturnValue(pending.promise);

    renderWithProviders(<NewScanPage />);

    const ignoreUnfixed = screen.getByLabelText('Ignore unfixed vulnerabilities');
    expect(ignoreUnfixed).not.toBeChecked();

    // The operator starts filling the form while the prefill is still in flight.
    await user.type(screen.getByLabelText('Image reference'), 'alpine:3.19');
    // Explicitly opt *out* of a setting the instance default would turn on.
    expect(ignoreUnfixed).not.toBeChecked();

    await settle(pending, INSTANCE_DEFAULTS);

    // The late prefill must not overwrite the dirty form.
    expect(screen.getByLabelText('Image reference')).toHaveValue('alpine:3.19');
    expect(screen.getByLabelText('Ignore unfixed vulnerabilities')).not.toBeChecked();
    expect(selectedSeverities()).toEqual(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
  });

  it('applies the prefill to a form the operator has not touched', async () => {
    const pending = deferred<ScannerSettings>();
    mockedScannerSettings.mockReturnValue(pending.promise);

    renderWithProviders(<NewScanPage />);

    await settle(pending, INSTANCE_DEFAULTS);

    await waitFor(() =>
      expect(screen.getByLabelText('Ignore unfixed vulnerabilities')).toBeChecked(),
    );
    // Only the instance default severity remains selected.
    expect(selectedSeverities()).toEqual(['CRITICAL']);
  });
});
