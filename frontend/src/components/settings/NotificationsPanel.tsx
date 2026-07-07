import { useCallback, useEffect, useState } from 'react';
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconPlugConnected, IconTrash } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import {
  createChannel,
  deleteChannel,
  EVENT_LABELS,
  listChannels,
  testChannel,
  type NotificationChannel,
  type NotificationEvent,
  type NotificationTestResult,
  type NotificationType,
} from '../../api/notifications';

const TYPES: { value: NotificationType; label: string }[] = [
  { value: 'webhook', label: 'Generic webhook' },
  { value: 'discord', label: 'Discord webhook' },
  { value: 'smtp', label: 'SMTP email' },
  { value: 'matrix', label: 'Matrix room' },
];

const EVENT_OPTIONS = (Object.keys(EVENT_LABELS) as NotificationEvent[]).map((value) => ({
  value,
  label: EVENT_LABELS[value],
}));

interface FormValues {
  name: string;
  type: NotificationType;
  url: string;
  host: string;
  port: number | '';
  from: string;
  to: string;
  username: string;
  homeserver: string;
  room_id: string;
  events: NotificationEvent[];
  secret: string;
  enabled: boolean;
}

function buildConfig(v: FormValues): Record<string, unknown> {
  switch (v.type) {
    case 'webhook':
    case 'discord':
      return { url: v.url.trim() };
    case 'smtp':
      return {
        host: v.host.trim(),
        port: v.port === '' ? 587 : Number(v.port),
        from: v.from.trim(),
        to: v.to.trim(),
        username: v.username.trim() || undefined,
      };
    case 'matrix':
      return { homeserver: v.homeserver.trim(), room_id: v.room_id.trim() };
  }
}

/** Notification channels: webhook / Discord / SMTP / Matrix, with a test action. */
export function NotificationsPanel() {
  const [items, setItems] = useState<NotificationChannel[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [tests, setTests] = useState<Record<number, NotificationTestResult>>({});
  const [opened, { open, close }] = useDisclosure(false);

  const load = useCallback(async () => {
    try {
      setItems(await listChannels());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load channels.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const form = useForm<FormValues>({
    initialValues: {
      name: '',
      type: 'webhook',
      url: '',
      host: '',
      port: 587,
      from: '',
      to: '',
      username: '',
      homeserver: '',
      room_id: '',
      events: [],
      secret: '',
      enabled: true,
    },
    validate: { name: (v) => (v.trim() ? null : 'Required') },
  });

  const submit = form.onSubmit(async (values) => {
    setError(null);
    try {
      await createChannel({
        name: values.name.trim(),
        type: values.type,
        config: buildConfig(values),
        events: values.events,
        secret: values.secret || null,
        enabled: values.enabled,
      });
      form.reset();
      close();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create channel.');
    }
  });

  const onDelete = async (id: number) => {
    setError(null);
    try {
      await deleteChannel(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete channel.');
    }
  };

  const onTest = async (id: number) => {
    try {
      const result = await testChannel(id);
      setTests((prev) => ({ ...prev, [id]: result }));
    } catch (err) {
      setTests((prev) => ({
        ...prev,
        [id]: { ok: false, detail: err instanceof ApiError ? err.message : 'Test failed.' },
      }));
    }
  };

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text c="dimmed" size="sm">
          Destinations for notifications. Secrets are write-only and encrypted at rest.
        </Text>
        <Button onClick={open}>Add channel</Button>
      </Group>

      {error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
          {error}
        </Alert>
      )}

      <Table.ScrollContainer minWidth={640}>
        <Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Type</Table.Th>
              <Table.Th>Notify on</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((c) => (
              <Table.Tr key={c.id}>
                <Table.Td>{c.name}</Table.Td>
                <Table.Td>{c.type}</Table.Td>
                <Table.Td>
                  {c.events.length > 0 ? (
                    <Group gap={4}>
                      {c.events.map((e) => (
                        <Badge key={e} variant="outline" size="sm">
                          {EVENT_LABELS[e]}
                        </Badge>
                      ))}
                    </Group>
                  ) : (
                    <Text size="sm" c="dimmed">
                      —
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  {tests[c.id] ? (
                    <Badge color={tests[c.id].ok ? 'teal' : 'red'} variant="light">
                      {tests[c.id].detail}
                    </Badge>
                  ) : c.enabled ? (
                    <Badge variant="light">enabled</Badge>
                  ) : (
                    <Badge color="gray" variant="light">
                      disabled
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  <Group gap="xs" justify="flex-end">
                    <ActionIcon
                      variant="subtle"
                      aria-label="Test channel"
                      onClick={() => onTest(c.id)}
                    >
                      <IconPlugConnected size={16} />
                    </ActionIcon>
                    <ActionIcon
                      variant="subtle"
                      color="red"
                      aria-label="Delete channel"
                      onClick={() => onDelete(c.id)}
                    >
                      <IconTrash size={16} />
                    </ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
            {items.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={5}>
                  <Text c="dimmed" ta="center" py="md">
                    No notification channels configured.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={opened} onClose={close} title="Add notification channel" centered>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <TextInput label="Name" {...form.getInputProps('name')} />
            <Select
              label="Type"
              data={TYPES}
              allowDeselect={false}
              {...form.getInputProps('type')}
            />

            {(form.values.type === 'webhook' || form.values.type === 'discord') && (
              <PasswordInput
                label="Webhook URL"
                description="The URL is the credential — stored encrypted, masked on read."
                placeholder="https://…"
                {...form.getInputProps('url')}
              />
            )}

            {form.values.type === 'smtp' && (
              <>
                <Group grow>
                  <TextInput label="SMTP host" {...form.getInputProps('host')} />
                  <NumberInput label="Port" min={1} max={65535} {...form.getInputProps('port')} />
                </Group>
                <TextInput label="From address" {...form.getInputProps('from')} />
                <TextInput label="To address" {...form.getInputProps('to')} />
                <TextInput
                  label="Username"
                  description="Defaults to the From address."
                  {...form.getInputProps('username')}
                />
              </>
            )}

            {form.values.type === 'matrix' && (
              <>
                <TextInput
                  label="Homeserver"
                  placeholder="https://matrix.example.com"
                  {...form.getInputProps('homeserver')}
                />
                <TextInput
                  label="Room ID"
                  placeholder="!room:example.com"
                  {...form.getInputProps('room_id')}
                />
              </>
            )}

            {(form.values.type === 'smtp' || form.values.type === 'matrix') && (
              <PasswordInput
                label={form.values.type === 'smtp' ? 'SMTP password' : 'Access token'}
                {...form.getInputProps('secret')}
              />
            )}
            <MultiSelect
              label="Notify on"
              description="Events that dispatch a message to this channel."
              data={EVENT_OPTIONS}
              {...form.getInputProps('events')}
            />
            <Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />
            <Group justify="flex-end">
              <Button variant="default" onClick={close}>
                Cancel
              </Button>
              <Button type="submit">Create</Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
