import { useCallback, useEffect, useState } from 'react';
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Group,
  Modal,
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
  createRegistry,
  deleteRegistry,
  listRegistries,
  type RegistryAuthType,
  type RegistryTestResult,
  SECRET_BEARING_AUTH_TYPES,
  testRegistry,
  type Registry,
} from '../../api/targets';
import { useAuth } from '../../auth/AuthContext';

const AUTH_TYPES: { value: RegistryAuthType; label: string }[] = [
  { value: 'username_password', label: 'Username & password' },
  { value: 'token', label: 'Token' },
  { value: 'aws_ecr', label: 'AWS ECR (credential helper)' },
  { value: 'google_gcr', label: 'Google GCR (credential helper)' },
  { value: 'azure_acr', label: 'Azure ACR (credential helper)' },
];

/** Manage container-registry credentials (admin) and test connectivity. */
export function RegistriesPanel() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin';
  const [items, setItems] = useState<Registry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [tests, setTests] = useState<Record<number, RegistryTestResult>>({});
  const [opened, { open, close }] = useDisclosure(false);

  const load = useCallback(async () => {
    try {
      setItems(await listRegistries());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load registries.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const form = useForm({
    initialValues: {
      name: '',
      registry_host: '',
      auth_type: 'username_password' as RegistryAuthType,
      username: '',
      secret: '',
      enabled: true,
    },
    validate: {
      name: (v) => (v.trim() ? null : 'Required'),
      registry_host: (v) => (v.trim() ? null : 'Required'),
      secret: (v, values) =>
        SECRET_BEARING_AUTH_TYPES.includes(values.auth_type) && !v ? 'Required' : null,
      username: (v, values) =>
        values.auth_type === 'username_password' && !v.trim() ? 'Required' : null,
    },
  });

  const needsSecret = SECRET_BEARING_AUTH_TYPES.includes(form.values.auth_type);

  const submit = form.onSubmit(async (values) => {
    setError(null);
    try {
      await createRegistry({
        name: values.name.trim(),
        registry_host: values.registry_host.trim(),
        auth_type: values.auth_type,
        username: values.username.trim() || null,
        secret: needsSecret ? values.secret : null,
        enabled: values.enabled,
      });
      form.reset();
      close();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create registry.');
    }
  });

  const onDelete = async (id: number) => {
    setError(null);
    try {
      await deleteRegistry(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete registry.');
    }
  };

  const onTest = async (id: number) => {
    try {
      const result = await testRegistry(id);
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
          Credentials for private container registries. Secrets are write-only and encrypted at
          rest.
        </Text>
        {canManage && <Button onClick={open}>Add registry</Button>}
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
              <Table.Th>Host</Table.Th>
              <Table.Th>Auth</Table.Th>
              <Table.Th>Secret</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>{r.name}</Table.Td>
                <Table.Td>{r.registry_host}</Table.Td>
                <Table.Td>{r.auth_type}</Table.Td>
                <Table.Td>
                  {r.secret.is_set ? <Text c="dimmed">{r.secret.value}</Text> : '—'}
                </Table.Td>
                <Table.Td>
                  {tests[r.id] ? (
                    <Badge color={tests[r.id].ok ? 'teal' : 'red'} variant="light">
                      {tests[r.id].detail}
                    </Badge>
                  ) : r.enabled ? (
                    <Badge variant="light">enabled</Badge>
                  ) : (
                    <Badge color="gray" variant="light">
                      disabled
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  {canManage && (
                    <Group gap="xs" justify="flex-end">
                      <ActionIcon
                        variant="subtle"
                        aria-label="Test registry"
                        onClick={() => onTest(r.id)}
                      >
                        <IconPlugConnected size={16} />
                      </ActionIcon>
                      <ActionIcon
                        variant="subtle"
                        color="red"
                        aria-label="Delete registry"
                        onClick={() => onDelete(r.id)}
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
                <Table.Td colSpan={6}>
                  <Text c="dimmed" ta="center" py="md">
                    No registries configured.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={opened} onClose={close} title="Add registry" centered>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <TextInput label="Name" {...form.getInputProps('name')} />
            <TextInput
              label="Registry host"
              placeholder="ghcr.io"
              {...form.getInputProps('registry_host')}
            />
            <Select
              label="Auth type"
              data={AUTH_TYPES}
              allowDeselect={false}
              {...form.getInputProps('auth_type')}
            />
            {needsSecret && (
              <>
                <TextInput label="Username" {...form.getInputProps('username')} />
                <PasswordInput label="Password / token" {...form.getInputProps('secret')} />
              </>
            )}
            {!needsSecret && (
              <Text size="sm" c="dimmed">
                This auth type uses a credential helper at scan time; no secret is stored.
              </Text>
            )}
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
