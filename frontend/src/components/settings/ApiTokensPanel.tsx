import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Code,
  CopyButton,
  Group,
  Modal,
  NumberInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconCopy, IconTrash } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import type { Role } from '../../api/auth';
import {
  createApiToken,
  listApiTokens,
  revokeApiToken,
  type ApiTokenInfo,
} from '../../api/apiTokens';
import { useAuth } from '../../auth/AuthContext';

const ROLE_ORDER: Role[] = ['viewer', 'operator', 'admin'];

/** Personal API tokens: mint (shown once), list, and revoke. */
export function ApiTokensPanel() {
  const { user } = useAuth();
  const [tokens, setTokens] = useState<ApiTokenInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [opened, { open, close }] = useDisclosure(false);

  const allowedRoles = ROLE_ORDER.slice(0, ROLE_ORDER.indexOf(user?.role ?? 'viewer') + 1);

  const load = useCallback(async () => {
    try {
      setTokens(await listApiTokens());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load tokens.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const form = useForm({
    initialValues: {
      name: '',
      role: (user?.role ?? 'viewer') as Role,
      expires_in_days: '' as number | '',
    },
    validate: { name: (v) => (v.trim() ? null : 'Required') },
  });

  const submit = form.onSubmit(async (values) => {
    setError(null);
    try {
      const created = await createApiToken({
        name: values.name.trim(),
        role: values.role,
        expires_in_days: values.expires_in_days === '' ? null : Number(values.expires_in_days),
      });
      setPlaintext(created.token);
      form.reset();
      close();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create token.');
    }
  });

  const onRevoke = async (id: number) => {
    setError(null);
    try {
      await revokeApiToken(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to revoke token.');
    }
  };

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text c="dimmed" size="sm">
          Bearer tokens for API access. The token value is shown once at creation.
        </Text>
        <Button onClick={open}>Create token</Button>
      </Group>

      {error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
          {error}
        </Alert>
      )}

      {plaintext && (
        <Alert color="teal" variant="light" title="New token — copy it now">
          <Group>
            <Code>{plaintext}</Code>
            <CopyButton value={plaintext}>
              {({ copied, copy }) => (
                <Button
                  size="xs"
                  variant="light"
                  leftSection={<IconCopy size={14} />}
                  onClick={copy}
                >
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              )}
            </CopyButton>
            <Button size="xs" variant="subtle" onClick={() => setPlaintext(null)}>
              Dismiss
            </Button>
          </Group>
        </Alert>
      )}

      <Table.ScrollContainer minWidth={640}>
        <Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Prefix</Table.Th>
              <Table.Th>Role</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tokens.map((t) => (
              <Table.Tr key={t.id}>
                <Table.Td>{t.name}</Table.Td>
                <Table.Td>
                  <Code>{t.token_prefix}…</Code>
                </Table.Td>
                <Table.Td>{t.role}</Table.Td>
                <Table.Td>
                  {t.revoked_at ? (
                    <Badge color="red" variant="light">
                      revoked
                    </Badge>
                  ) : (
                    <Badge color="teal" variant="light">
                      active
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  {!t.revoked_at && (
                    <Group justify="flex-end">
                      <Button
                        size="xs"
                        variant="subtle"
                        color="red"
                        leftSection={<IconTrash size={14} />}
                        onClick={() => onRevoke(t.id)}
                      >
                        Revoke
                      </Button>
                    </Group>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
            {tokens.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={5}>
                  <Text c="dimmed" ta="center" py="md">
                    No API tokens yet.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={opened} onClose={close} title="Create API token" centered>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <TextInput label="Name" {...form.getInputProps('name')} />
            <Select
              label="Role"
              data={allowedRoles}
              allowDeselect={false}
              {...form.getInputProps('role')}
            />
            <NumberInput
              label="Expires in (days)"
              description="Leave blank for a token that never expires."
              min={1}
              max={3650}
              {...form.getInputProps('expires_in_days')}
            />
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
