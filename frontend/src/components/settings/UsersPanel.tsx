import { useCallback, useEffect, useState } from 'react';
import {
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
import { IconAlertCircle } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import type { Role, UserInfo } from '../../api/auth';
import { createUser, listUsers, updateUser } from '../../api/users';
import { useAuth } from '../../auth/AuthContext';

const ROLES: Role[] = ['viewer', 'operator', 'admin'];

/** Admin user management: create, change role, activate/deactivate, reset password. */
export function UsersPanel() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [opened, { open, close }] = useDisclosure(false);

  const load = useCallback(async () => {
    try {
      setUsers(await listUsers());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load users.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const form = useForm({
    initialValues: { username: '', password: '', role: 'viewer' as Role },
    validate: {
      username: (v) => (v.trim().length >= 3 ? null : 'At least 3 characters'),
      password: (v) => (v.length >= 12 ? null : 'At least 12 characters'),
    },
  });

  const submit = form.onSubmit(async (values) => {
    setError(null);
    try {
      await createUser({ ...values, username: values.username.trim() });
      form.reset();
      close();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create user.');
    }
  });

  const changeRole = async (u: UserInfo, role: Role) => {
    setError(null);
    try {
      await updateUser(u.id, { role });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update role.');
    }
  };

  const toggleActive = async (u: UserInfo) => {
    setError(null);
    try {
      await updateUser(u.id, { is_active: !u.is_active });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update user.');
    }
  };

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text c="dimmed" size="sm">
          Manage accounts and roles. You cannot change your own role or deactivate yourself.
        </Text>
        <Button onClick={open}>Add user</Button>
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
              <Table.Th>Username</Table.Th>
              <Table.Th>Role</Table.Th>
              <Table.Th>MFA</Table.Th>
              <Table.Th>Active</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {users.map((u) => {
              const isSelf = u.id === me?.id;
              return (
                <Table.Tr key={u.id}>
                  <Table.Td>{u.username}</Table.Td>
                  <Table.Td>
                    <Select
                      data={ROLES}
                      value={u.role}
                      disabled={isSelf}
                      allowDeselect={false}
                      onChange={(v) => v && changeRole(u, v as Role)}
                      w={130}
                    />
                  </Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={u.mfa_enabled ? 'teal' : 'gray'}>
                      {u.mfa_enabled ? 'on' : 'off'}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Switch
                      checked={u.is_active}
                      disabled={isSelf}
                      onChange={() => toggleActive(u)}
                    />
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={opened} onClose={close} title="Add user" centered>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <TextInput label="Username" {...form.getInputProps('username')} />
            <PasswordInput label="Password" {...form.getInputProps('password')} />
            <Select
              label="Role"
              data={ROLES}
              allowDeselect={false}
              {...form.getInputProps('role')}
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
