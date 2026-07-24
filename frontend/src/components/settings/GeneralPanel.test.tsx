import { beforeEach, describe, expect, it, vi } from 'vitest';

import { GeneralPanel } from './GeneralPanel';
import { act, fireEvent, renderWithProviders, screen, waitFor } from '../../test/render';

vi.mock('../../api/settings', () => ({
  getGeneralSettings: vi.fn(),
  updateGeneralSettings: vi.fn(),
}));
// The panel gates its controls on the admin role; the real AuthProvider does
// network work that is irrelevant to the clobber guard.
vi.mock('../../auth/AuthContext', () => ({
  useAuth: () => ({ user: { role: 'admin' } }),
}));

import {
  getGeneralSettings,
  updateGeneralSettings,
  type GeneralSettings,
} from '../../api/settings';

const mockedGet = vi.mocked(getGeneralSettings);
const mockedUpdate = vi.mocked(updateGeneralSettings);

/** Live settings, distinct from the built-in defaults (`Scrye` / empty note). */
const LIVE_SETTINGS: GeneralSettings = {
  instance_name: 'Production Scrye',
  admin_note: 'prod cluster',
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

describe('GeneralPanel — M19 / P1-2 settings-form clobber guard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedUpdate.mockResolvedValue(LIVE_SETTINGS);
  });

  it('is not editable or savable until the live settings load', async () => {
    const pending = deferred<GeneralSettings>();
    mockedGet.mockReturnValue(pending.promise);

    renderWithProviders(<GeneralPanel />);

    const save = screen.getByRole('button', { name: 'Save' });
    expect(save).toBeDisabled();
    expect(screen.getByLabelText('Instance name')).toBeDisabled();
    expect(screen.getByLabelText('Admin note')).toBeDisabled();

    // A Save before the GET lands would otherwise PUT the built-in defaults
    // ("Scrye" / empty note) over whatever the instance is actually named.
    fireEvent.click(save);
    expect(mockedUpdate).not.toHaveBeenCalled();

    await settle(pending, LIVE_SETTINGS);

    await waitFor(() => expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled());
    expect(screen.getByLabelText('Instance name')).toHaveValue('Production Scrye');
    expect(screen.getByLabelText('Admin note')).toHaveValue('prod cluster');
  });

  it('saves the fetched settings — not the defaults — once loaded', async () => {
    mockedGet.mockResolvedValue(LIVE_SETTINGS);

    renderWithProviders(<GeneralPanel />);

    await waitFor(() => expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(mockedUpdate).toHaveBeenCalledWith(LIVE_SETTINGS));
  });
});
