import { beforeEach, describe, expect, it, vi } from 'vitest';

import { BackupsPanel } from './BackupsPanel';
import { act, fireEvent, renderWithProviders, screen, userEvent, waitFor } from '../../test/render';

vi.mock('../../api/backups', () => ({
  listBackups: vi.fn(),
  createBackup: vi.fn(),
  deleteBackup: vi.fn(),
  restoreBackup: vi.fn(),
  getBackupSchedule: vi.fn(),
  updateBackupSchedule: vi.fn(),
  backupDownloadUrl: (id: number) => `/api/backups/${id}/download`,
}));

import {
  deleteBackup,
  getBackupSchedule,
  listBackups,
  updateBackupSchedule,
  type BackupInfo,
  type BackupSchedule,
} from '../../api/backups';

const mockedList = vi.mocked(listBackups);
const mockedGetSchedule = vi.mocked(getBackupSchedule);
const mockedUpdateSchedule = vi.mocked(updateBackupSchedule);
const mockedDelete = vi.mocked(deleteBackup);

/** The stored schedule — distinct from the built-in form defaults
 *  (`{enabled: false, interval_hours: 24, retention_count: 7}`). */
const LIVE_SCHEDULE: BackupSchedule = {
  enabled: true,
  interval_hours: 12,
  retention_count: 30,
  passphrase: { is_set: true, value: '••••', updated_at: '2026-07-01T00:00:00Z' },
  last_run_at: null,
  last_status: null,
};

const BACKUP: BackupInfo = {
  id: 1,
  filename: 'scrye-20260724.scryebak',
  size_bytes: 2048,
  checksum_sha256: 'abc',
  kind: 'manual',
  app_version: '0.1.0',
  created_at: '2026-07-24T00:00:00Z',
  created_by_username: 'admin',
  note: null,
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

const saveScheduleButton = () => screen.getByRole('button', { name: 'Save schedule' });

describe('BackupsPanel — M19 / P1-2 schedule-form clobber guard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedList.mockResolvedValue([BACKUP]);
    mockedDelete.mockResolvedValue(undefined);
    mockedUpdateSchedule.mockResolvedValue(LIVE_SCHEDULE);
  });

  it('is not editable or savable until the stored schedule loads', async () => {
    const pending = deferred<BackupSchedule>();
    mockedGetSchedule.mockReturnValue(pending.promise);

    renderWithProviders(<BackupsPanel />);

    const save = saveScheduleButton();
    expect(save).toBeDisabled();
    expect(screen.getByLabelText('Enable scheduled backups')).toBeDisabled();
    expect(screen.getByLabelText('Interval (hours)')).toBeDisabled();
    expect(screen.getByLabelText('Keep last N')).toBeDisabled();

    // Saving here would PUT the built-in defaults (24h / keep 7) over a stored
    // 12h / keep-30 schedule.
    fireEvent.click(save);
    expect(mockedUpdateSchedule).not.toHaveBeenCalled();

    await settle(pending, LIVE_SCHEDULE);

    await waitFor(() => expect(saveScheduleButton()).toBeEnabled());
    expect(screen.getByLabelText('Enable scheduled backups')).toBeChecked();
    expect(screen.getByLabelText('Interval (hours)')).toHaveValue('12');
    expect(screen.getByLabelText('Keep last N')).toHaveValue('30');
  });

  it('does not clobber an in-progress schedule edit when the backups list reloads', async () => {
    const user = userEvent.setup();
    mockedGetSchedule.mockResolvedValue(LIVE_SCHEDULE);

    renderWithProviders(<BackupsPanel />);

    await waitFor(() => expect(saveScheduleButton()).toBeEnabled());

    // The admin starts editing the schedule…
    const interval = screen.getByLabelText('Interval (hours)');
    await user.clear(interval);
    await user.type(interval, '6');
    expect(interval).toHaveValue('6');

    // …then performs an unrelated list mutation. `load()` re-fetches the
    // schedule for the *display* fields, and must not rehydrate the form.
    await user.click(screen.getByRole('button', { name: /delete/i }));
    await waitFor(() => expect(mockedDelete).toHaveBeenCalledWith(BACKUP.id));
    await waitFor(() => expect(mockedGetSchedule.mock.calls.length).toBeGreaterThan(1));

    expect(interval).toHaveValue('6');
    fireEvent.click(saveScheduleButton());
    await waitFor(() =>
      expect(mockedUpdateSchedule).toHaveBeenCalledWith(
        expect.objectContaining({ interval_hours: 6 }),
      ),
    );
  });
});
