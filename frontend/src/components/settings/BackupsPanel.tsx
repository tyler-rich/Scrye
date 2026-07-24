import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Divider,
  FileButton,
  Group,
  NumberInput,
  PasswordInput,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconCheck, IconDownload, IconTrash } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import { formatWhen } from '../../lib/dates';
import {
  backupDownloadUrl,
  createBackup,
  deleteBackup,
  getBackupSchedule,
  listBackups,
  restoreBackup,
  updateBackupSchedule,
  type BackupInfo,
  type BackupSchedule,
} from '../../api/backups';

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Backup & restore: create/download/delete bundles, restore, and schedule. */
export function BackupsPanel() {
  const [items, setItems] = useState<BackupInfo[]>([]);
  const [schedule, setSchedule] = useState<BackupSchedule | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Gate the schedule form until its values load, so it can't be saved with the
  // built-in defaults before the GET resolves (M19 / P1-2).
  const [scheduleLoaded, setScheduleLoaded] = useState(false);
  // State (not a ref) so the selected file name re-renders on the destructive
  // restore flow — a ref assignment would leave the label stale (FE-4).
  const [restoreFile, setRestoreFile] = useState<File | null>(null);

  const createForm = useForm({ initialValues: { passphrase: '', note: '' } });
  const restoreForm = useForm({ initialValues: { passphrase: '' } });
  const scheduleForm = useForm({
    initialValues: { enabled: false, interval_hours: 24, retention_count: 7, passphrase: '' },
  });

  // Refresh the backups list and the schedule *display* object. Deliberately
  // does NOT rehydrate the schedule form — this re-runs after every list
  // mutation (create/delete/restore), and rehydrating here would silently
  // reset an admin's in-progress schedule edits (M19 / P1-2).
  const load = useCallback(async () => {
    try {
      setItems(await listBackups());
      setSchedule(await getBackupSchedule());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load backups.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Hydrate the schedule form once on mount, separate from load() so list
  // mutations never clobber it. Only seeds a pristine form.
  useEffect(() => {
    void getBackupSchedule()
      .then((s) => {
        if (!scheduleForm.isDirty()) {
          scheduleForm.setValues({
            enabled: s.enabled,
            interval_hours: s.interval_hours,
            retention_count: s.retention_count,
            passphrase: '',
          });
        }
        setScheduleLoaded(true);
      })
      .catch(() => {
        // The load-error surface above already reports a failed fetch.
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onCreate = createForm.onSubmit(async (values) => {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await createBackup(values.passphrase, values.note || undefined);
      createForm.reset();
      setNotice('Backup created.');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create backup.');
    } finally {
      setBusy(false);
    }
  });

  const onDelete = async (id: number) => {
    setError(null);
    try {
      await deleteBackup(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete backup.');
    }
  };

  const onRestore = restoreForm.onSubmit(async (values) => {
    if (!restoreFile) {
      setError('Choose a backup file to restore.');
      return;
    }
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const result = await restoreBackup(restoreFile, values.passphrase);
      setNotice(
        `Restored ${result.rows} rows across ${result.tables} tables. You may need to sign in again.`,
      );
      restoreForm.reset();
      setRestoreFile(null);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Restore failed.');
    } finally {
      setBusy(false);
    }
  });

  const onSaveSchedule = scheduleForm.onSubmit(async (values) => {
    setError(null);
    setNotice(null);
    try {
      await updateBackupSchedule({
        enabled: values.enabled,
        interval_hours: values.interval_hours,
        retention_count: values.retention_count,
        ...(values.passphrase ? { passphrase: values.passphrase } : {}),
      });
      scheduleForm.setFieldValue('passphrase', '');
      setNotice('Schedule saved.');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save schedule.');
    }
  });

  return (
    <Stack gap="xl">
      {error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
          {error}
        </Alert>
      )}
      {notice && (
        <Alert color="teal" icon={<IconCheck size={16} />} variant="light">
          {notice}
        </Alert>
      )}

      <form onSubmit={onCreate}>
        <Stack gap="sm" maw={520}>
          <Title order={5}>Create backup</Title>
          <Text size="sm" c="dimmed">
            The passphrase protects the bundle and re-wraps every stored secret so it can be
            restored on any host. Keep it safe — it cannot be recovered.
          </Text>
          <PasswordInput
            label="Backup passphrase"
            required
            {...createForm.getInputProps('passphrase')}
          />
          <TextInput label="Note (optional)" {...createForm.getInputProps('note')} />
          <Group>
            <Button type="submit" loading={busy} disabled={createForm.values.passphrase.length < 8}>
              Create backup
            </Button>
          </Group>
        </Stack>
      </form>

      <div>
        <Title order={5} mb="xs">
          Stored backups
        </Title>
        <Table.ScrollContainer minWidth={640}>
          <Table verticalSpacing="sm" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Created</Table.Th>
                <Table.Th>Kind</Table.Th>
                <Table.Th>Size</Table.Th>
                <Table.Th>Note</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((b) => (
                <Table.Tr key={b.id}>
                  <Table.Td>{formatWhen(b.created_at)}</Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={b.kind === 'scheduled' ? 'blue' : 'teal'}>
                      {b.kind}
                    </Badge>
                  </Table.Td>
                  <Table.Td>{humanSize(b.size_bytes)}</Table.Td>
                  <Table.Td>{b.note ?? '—'}</Table.Td>
                  <Table.Td>
                    <Group gap="xs" justify="flex-end">
                      <Button
                        size="xs"
                        variant="subtle"
                        component="a"
                        href={backupDownloadUrl(b.id)}
                        leftSection={<IconDownload size={14} />}
                      >
                        Download
                      </Button>
                      <Button
                        size="xs"
                        variant="subtle"
                        color="red"
                        leftSection={<IconTrash size={14} />}
                        onClick={() => void onDelete(b.id)}
                      >
                        Delete
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
              {items.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={5}>
                    <Text c="dimmed" ta="center" py="md">
                      No backups yet.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </div>

      <Divider />

      <form onSubmit={onRestore}>
        <Stack gap="sm" maw={520}>
          <Title order={5}>Restore</Title>
          <Alert color="orange" variant="light" icon={<IconAlertCircle size={16} />}>
            Restoring replaces all current data. You will likely be signed out afterwards.
          </Alert>
          <Group>
            <FileButton onChange={setRestoreFile} accept=".scryebak">
              {(props) => (
                <Button variant="default" {...props}>
                  Choose file
                </Button>
              )}
            </FileButton>
            <Text size="sm" c="dimmed">
              {restoreFile?.name ?? 'No file selected'}
            </Text>
          </Group>
          <PasswordInput
            label="Backup passphrase"
            required
            {...restoreForm.getInputProps('passphrase')}
          />
          <Group>
            <Button type="submit" color="orange" loading={busy}>
              Restore (destructive)
            </Button>
          </Group>
        </Stack>
      </form>

      <Divider />

      <form onSubmit={onSaveSchedule}>
        <Stack gap="sm" maw={520}>
          <Title order={5}>Scheduled backups</Title>
          <Switch
            label="Enable scheduled backups"
            disabled={!scheduleLoaded}
            {...scheduleForm.getInputProps('enabled', { type: 'checkbox' })}
          />
          <Group grow>
            <NumberInput
              label="Interval (hours)"
              min={1}
              max={720}
              disabled={!scheduleLoaded}
              {...scheduleForm.getInputProps('interval_hours')}
            />
            <NumberInput
              label="Keep last N"
              min={1}
              max={365}
              disabled={!scheduleLoaded}
              {...scheduleForm.getInputProps('retention_count')}
            />
          </Group>
          <PasswordInput
            label="Schedule passphrase"
            description={
              schedule?.passphrase.is_set
                ? 'A passphrase is stored. Leave blank to keep it.'
                : 'Required to enable scheduled backups.'
            }
            placeholder={schedule?.passphrase.is_set ? '••••••••' : ''}
            disabled={!scheduleLoaded}
            {...scheduleForm.getInputProps('passphrase')}
          />
          {schedule?.last_run_at && (
            <Text size="sm" c="dimmed">
              Last run {formatWhen(schedule.last_run_at)} — {schedule.last_status}
            </Text>
          )}
          <Group>
            <Button type="submit" loading={!scheduleLoaded} disabled={!scheduleLoaded}>
              Save schedule
            </Button>
          </Group>
        </Stack>
      </form>
    </Stack>
  );
}
