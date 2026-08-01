import { useCallback, useEffect, useState } from 'react';
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconPlayerPlay, IconTrash } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import { formatWhen } from '../../lib/dates';
import {
  createSchedule,
  deleteSchedule,
  listSchedules,
  runScheduleNow,
  type ScanSchedule,
} from '../../api/schedules';
import type { Scanner, TargetType } from '../../api/scans';
import { useAuth } from '../../auth/AuthContext';

const SCANNER_LABELS: Record<Scanner, string> = { trivy: 'Trivy', grype: 'Grype' };

const TARGET_TYPES: { value: TargetType; label: string }[] = [
  { value: 'image', label: 'Container image' },
  { value: 'repository', label: 'Git repository' },
  { value: 'filesystem', label: 'Filesystem' },
];

// Which scanners can run each schedulable target type — the backend rejects
// invalid combos (scan_schedules.py), so mirror it here to keep the form valid
// up front rather than 400-ing after the whole form is filled (FE-5).
// Typed as a non-empty tuple so `SCANNERS_FOR[t][0]` is a `Scanner`, not
// `Scanner | undefined` — every target type has at least one scanner, and the
// "reset to the first allowed scanner" effect below depends on that.
const SCANNERS_FOR: Record<TargetType, readonly [Scanner, ...Scanner[]]> = {
  image: ['trivy', 'grype'],
  repository: ['trivy'],
  filesystem: ['grype'],
  sbom: ['grype'], // not schedulable (no upload), listed for completeness
};

interface FormValues {
  name: string;
  cron: string;
  scanner: Scanner;
  target_type: TargetType;
  target: string;
  ignore_unfixed: boolean;
  enabled: boolean;
}

/** Scheduled/recurring scans on a cron cadence (docs/ARCHIVE.md §4.6). */
export function ScheduledScansPanel() {
  const { user } = useAuth();
  const canOperate = !!user && user.role !== 'viewer';
  const [items, setItems] = useState<ScanSchedule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  // Which row action is in flight, so it can't double-fire (a double-clicked
  // "Run now" queues duplicate scans) (L19 / P2-4).
  const [rowBusy, setRowBusy] = useState<{ id: number; action: 'run' | 'delete' } | null>(null);
  const [opened, { open, close }] = useDisclosure(false);

  const load = useCallback(async () => {
    try {
      setItems(await listSchedules());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load schedules.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const form = useForm<FormValues>({
    initialValues: {
      name: '',
      cron: '0 2 * * *',
      scanner: 'trivy',
      target_type: 'image',
      target: '',
      ignore_unfixed: false,
      enabled: true,
    },
    validate: {
      name: (v) => (v.trim() ? null : 'Required'),
      cron: (v) => (v.trim().split(/\s+/).length === 5 ? null : 'Cron must have 5 fields'),
      target: (v) => (v.trim() ? null : 'Required'),
    },
  });

  // Keep the scanner valid for the chosen target type (FE-5).
  const targetType = form.values.target_type;
  const scanner = form.values.scanner;
  useEffect(() => {
    const allowed = SCANNERS_FOR[targetType];
    if (!allowed.includes(scanner)) form.setFieldValue('scanner', allowed[0]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetType, scanner]);

  const submit = form.onSubmit(async (values) => {
    if (creating) return;
    setError(null);
    setCreating(true);
    try {
      await createSchedule({
        name: values.name.trim(),
        cron: values.cron.trim(),
        scanner: values.scanner,
        target_type: values.target_type,
        target: values.target.trim(),
        ignore_unfixed: values.ignore_unfixed,
        enabled: values.enabled,
      });
      form.reset();
      close();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create schedule.');
    } finally {
      setCreating(false);
    }
  });

  const onDelete = async (id: number) => {
    if (rowBusy !== null) return;
    setError(null);
    setRowBusy({ id, action: 'delete' });
    try {
      await deleteSchedule(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete schedule.');
    } finally {
      setRowBusy(null);
    }
  };

  const onRun = async (id: number) => {
    if (rowBusy !== null) return;
    setError(null);
    setRowBusy({ id, action: 'run' });
    try {
      await runScheduleNow(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to run schedule.');
    } finally {
      setRowBusy(null);
    }
  };

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text c="dimmed" size="sm">
          Recurring scans on a cron cadence. Due schedules launch automatically; SBOM uploads cannot
          be scheduled.
        </Text>
        {canOperate && <Button onClick={open}>Add schedule</Button>}
      </Group>

      {error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
          {error}
        </Alert>
      )}

      <Table.ScrollContainer minWidth={720}>
        <Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Cron</Table.Th>
              <Table.Th>Target</Table.Th>
              <Table.Th>Last run</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((s) => (
              <Table.Tr key={s.id}>
                <Table.Td>
                  <Group gap="xs">
                    {s.name}
                    {!s.enabled && (
                      <Badge color="gray" variant="light" size="sm">
                        disabled
                      </Badge>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {s.cron}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" style={{ wordBreak: 'break-all' }}>
                    {s.scanner} · {s.target}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" c="dimmed">
                    {s.last_run_at ? `${formatWhen(s.last_run_at)} (${s.last_status})` : 'never'}
                  </Text>
                </Table.Td>
                <Table.Td>
                  {canOperate && (
                    <Group gap="xs" justify="flex-end">
                      <ActionIcon
                        variant="subtle"
                        aria-label="Run now"
                        loading={rowBusy?.id === s.id && rowBusy.action === 'run'}
                        disabled={rowBusy !== null}
                        onClick={() => void onRun(s.id)}
                      >
                        <IconPlayerPlay size={16} />
                      </ActionIcon>
                      <ActionIcon
                        variant="subtle"
                        color="red"
                        aria-label="Delete schedule"
                        loading={rowBusy?.id === s.id && rowBusy.action === 'delete'}
                        disabled={rowBusy !== null}
                        onClick={() => void onDelete(s.id)}
                      >
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Group>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
            {items.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={5}>
                  <Text c="dimmed" ta="center" py="md">
                    No scheduled scans configured.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={opened} onClose={close} title="Add scan schedule" centered>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <TextInput label="Name" {...form.getInputProps('name')} />
            <TextInput
              label="Cron expression"
              description="5 fields: minute hour day-of-month month day-of-week"
              placeholder="0 2 * * *"
              {...form.getInputProps('cron')}
            />
            <Group grow>
              <Select
                label="Scanner"
                data={SCANNERS_FOR[targetType].map((s) => ({
                  value: s,
                  label: SCANNER_LABELS[s],
                }))}
                allowDeselect={false}
                disabled={SCANNERS_FOR[targetType].length === 1}
                {...form.getInputProps('scanner')}
              />
              <Select
                label="Target type"
                data={TARGET_TYPES}
                allowDeselect={false}
                {...form.getInputProps('target_type')}
              />
            </Group>
            <TextInput
              label="Target"
              description="Image ref, repository URL, or filesystem path"
              {...form.getInputProps('target')}
            />
            {form.values.scanner === 'trivy' && (
              <Switch
                label="Ignore unfixed vulnerabilities"
                {...form.getInputProps('ignore_unfixed', { type: 'checkbox' })}
              />
            )}
            <Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />
            <Group justify="flex-end">
              <Button variant="default" onClick={close} disabled={creating}>
                Cancel
              </Button>
              <Button type="submit" loading={creating}>
                Create
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
