import { beforeEach, describe, expect, it, vi } from 'vitest';

import { RetentionPanel } from './RetentionPanel';
import { act, fireEvent, renderWithProviders, screen, waitFor } from '../../test/render';

// The panel's only network calls are the policy GET and the save PUT; mocking
// the module lets each test hold the GET open and control exactly when it
// resolves relative to a Save attempt.
vi.mock('../../api/settings', () => ({
  getRetentionSettings: vi.fn(),
  updateRetentionSettings: vi.fn(),
}));

import {
  getRetentionSettings,
  updateRetentionSettings,
  type RetentionSettings,
} from '../../api/settings';

const mockedGet = vi.mocked(getRetentionSettings);
const mockedUpdate = vi.mocked(updateRetentionSettings);

/** The live policy — deliberately different from the built-in form defaults
 *  (`{enabled: false, max_age_days: 90}`) so a clobber is visible. */
const LIVE_POLICY: RetentionSettings = { enabled: true, max_age_days: 30 };

/** A promise whose resolution the test drives, standing in for a slow request. */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** Settle the pending request and let React apply the resulting state. */
async function settle<T>(pending: { promise: Promise<T>; resolve: (value: T) => void }, value: T) {
  await act(async () => {
    pending.resolve(value);
    await pending.promise;
  });
}

describe('RetentionPanel — M19 / P1-2 settings-form clobber guard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedUpdate.mockResolvedValue(LIVE_POLICY);
  });

  it('is not editable or savable until the live policy loads', async () => {
    const pending = deferred<RetentionSettings>();
    mockedGet.mockReturnValue(pending.promise);

    renderWithProviders(<RetentionPanel />);

    // While the GET is in flight the form still shows the built-in defaults, so
    // every control that could commit them must be inert.
    const save = screen.getByRole('button', { name: 'Save' });
    expect(save).toBeDisabled();
    expect(screen.getByLabelText('Prune old raw artifacts')).toBeDisabled();
    expect(screen.getByLabelText('Maximum age (days)')).toBeDisabled();

    // The core invariant: a Save attempt before the policy lands must not write
    // the defaults over the live configuration.
    fireEvent.click(save);
    expect(mockedUpdate).not.toHaveBeenCalled();

    await settle(pending, LIVE_POLICY);

    // Once loaded the form is live and carries the fetched policy, not defaults.
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled());
    expect(screen.getByLabelText('Prune old raw artifacts')).toBeChecked();
    expect(screen.getByLabelText('Maximum age (days)')).toHaveValue('30');
  });

  it('saves the fetched policy — not the defaults — once loaded', async () => {
    mockedGet.mockResolvedValue(LIVE_POLICY);

    renderWithProviders(<RetentionPanel />);

    await waitFor(() => expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(mockedUpdate).toHaveBeenCalledWith(LIVE_POLICY));
  });

  // Note on the "dirty form is not clobbered" half of M19: in this panel the
  // inputs are themselves gated on `loaded`, so there is no user-reachable path
  // to dirty the form before the GET resolves — the disabled gate subsumes it.
  // The dirty-guard path is exercised where it *is* reachable: `NewScanPage`
  // (ungated fields, `NewScanPage.prefill.test.tsx`) and `BackupsPanel` (the
  // post-mutation reload, `BackupsPanel.test.tsx`).
});
