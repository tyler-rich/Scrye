import { useCallback, useEffect, useState } from 'react';
import {
  ActionIcon,
  Alert,
  Button,
  Group,
  Modal,
  PasswordInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconTrash } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import {
  createGitCredential,
  deleteGitCredential,
  type GitCredential,
  type GitProvider,
  listGitCredentials,
} from '../../api/targets';
import { useAuth } from '../../auth/AuthContext';

const PROVIDERS: { value: GitProvider; label: string }[] = [
  { value: 'github', label: 'GitHub (GITHUB_TOKEN)' },
  { value: 'gitlab', label: 'GitLab (GITLAB_TOKEN)' },
  { value: 'generic', label: 'Generic (HTTPS user:token)' },
];

/** Manage git-provider access tokens (admin) for private repository scans. */
export function GitCredentialsPanel() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin';
  const [items, setItems] = useState<GitCredential[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [opened, { open, close }] = useDisclosure(false);

  const load = useCallback(async () => {
    try {
      setItems(await listGitCredentials());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load git credentials.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const form = useForm({
    initialValues: {
      name: '',
      provider: 'github' as GitProvider,
      host: '',
      username: '',
      token: '',
    },
    validate: {
      name: (v) => (v.trim() ? null : 'Required'),
      token: (v) => (v ? null : 'Required'),
    },
  });

  const submit = form.onSubmit(async (values) => {
    setError(null);
    try {
      await createGitCredential({
        name: values.name.trim(),
        provider: values.provider,
        host: values.host.trim() || null,
        username: values.username.trim() || null,
        token: values.token,
      });
      form.reset();
      close();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create credential.');
    }
  });

  const onDelete = async (id: number) => {
    setError(null);
    try {
      await deleteGitCredential(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete credential.');
    }
  };

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text c="dimmed" size="sm">
          Access tokens for cloning private repositories with Trivy. Tokens are write-only and
          encrypted at rest.
        </Text>
        {canManage && <Button onClick={open}>Add credential</Button>}
      </Group>

      {error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
          {error}
        </Alert>
      )}

      <Table.ScrollContainer minWidth={560}>
        <Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Provider</Table.Th>
              <Table.Th>Host</Table.Th>
              <Table.Th>Token</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((c) => (
              <Table.Tr key={c.id}>
                <Table.Td>{c.name}</Table.Td>
                <Table.Td>{c.provider}</Table.Td>
                <Table.Td>{c.host ?? '—'}</Table.Td>
                <Table.Td>
                  <Text c="dimmed">{c.token.value}</Text>
                </Table.Td>
                <Table.Td>
                  {canManage && (
                    <Group justify="flex-end">
                      <ActionIcon
                        variant="subtle"
                        color="red"
                        aria-label="Delete credential"
                        onClick={() => void onDelete(c.id)}
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
                    No git credentials configured.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={opened} onClose={close} title="Add git credential" centered>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <TextInput label="Name" {...form.getInputProps('name')} />
            <Select
              label="Provider"
              data={PROVIDERS}
              allowDeselect={false}
              {...form.getInputProps('provider')}
            />
            <TextInput
              label="Host (optional)"
              placeholder="git.example.com"
              {...form.getInputProps('host')}
            />
            <TextInput
              label="Username (optional)"
              placeholder="used for generic HTTPS auth"
              {...form.getInputProps('username')}
            />
            <PasswordInput label="Access token" {...form.getInputProps('token')} />
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
