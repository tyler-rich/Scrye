import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Divider,
  Group,
  PasswordInput,
  PinInput,
  Stack,
  Table,
  Text,
  Title,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconCheck } from '@tabler/icons-react';

import { ApiError } from '../api/client';
import {
  activateMfa,
  changePassword,
  disableMfa,
  enrollMfa,
  listSessions,
  revokeSession,
  type MfaEnrollment,
  type SessionInfo,
} from '../api/account';
import { useAuth } from '../auth/AuthContext';

function PasswordSection() {
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);
  const form = useForm({
    initialValues: { current_password: '', new_password: '' },
    validate: { new_password: (v) => (v.length >= 12 ? null : 'At least 12 characters') },
  });

  const submit = form.onSubmit(async (values) => {
    setStatus(null);
    try {
      await changePassword(values.current_password, values.new_password);
      form.reset();
      setStatus({ ok: true, msg: 'Password changed. Other sessions were signed out.' });
    } catch (err) {
      setStatus({ ok: false, msg: err instanceof ApiError ? err.message : 'Failed to change.' });
    }
  });

  return (
    <form onSubmit={submit}>
      <Stack gap="sm" maw={420}>
        <Title order={5}>Password</Title>
        {status && (
          <Alert
            color={status.ok ? 'teal' : 'red'}
            icon={status.ok ? <IconCheck size={16} /> : <IconAlertCircle size={16} />}
            variant="light"
          >
            {status.msg}
          </Alert>
        )}
        <PasswordInput
          label="Current password"
          autoComplete="current-password"
          {...form.getInputProps('current_password')}
        />
        <PasswordInput
          label="New password"
          autoComplete="new-password"
          {...form.getInputProps('new_password')}
        />
        <Group>
          <Button type="submit">Change password</Button>
        </Group>
      </Stack>
    </form>
  );
}

function MfaSection() {
  const { user, refresh } = useAuth();
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  // Re-enrolling over an existing (even pending, not-yet-activated) secret needs
  // the current password; surface a field to re-auth if the server asks for it.
  const [reauthRequired, setReauthRequired] = useState(false);
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);

  const startEnroll = async (currentPassword?: string) => {
    setStatus(null);
    try {
      setEnrollment(await enrollMfa(currentPassword));
      setReauthRequired(false);
      setPassword('');
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        // A prior, un-activated secret exists: ask for the password and retry.
        setReauthRequired(true);
        setStatus({ ok: false, msg: err.message });
        return;
      }
      setStatus({ ok: false, msg: err instanceof ApiError ? err.message : 'Failed.' });
    }
  };

  const confirm = async () => {
    setStatus(null);
    try {
      await activateMfa(code);
      setEnrollment(null);
      setCode('');
      await refresh();
      setStatus({ ok: true, msg: 'MFA enabled.' });
    } catch (err) {
      setStatus({ ok: false, msg: err instanceof ApiError ? err.message : 'Invalid code.' });
    }
  };

  const disable = async () => {
    setStatus(null);
    try {
      await disableMfa(password);
      setPassword('');
      await refresh();
      setStatus({ ok: true, msg: 'MFA disabled.' });
    } catch (err) {
      setStatus({ ok: false, msg: err instanceof ApiError ? err.message : 'Failed.' });
    }
  };

  return (
    <Stack gap="sm" maw={420}>
      <Group>
        <Title order={5}>Two-factor authentication</Title>
        <Badge variant="light" color={user?.mfa_enabled ? 'teal' : 'gray'}>
          {user?.mfa_enabled ? 'enabled' : 'disabled'}
        </Badge>
      </Group>
      {status && (
        <Alert
          color={status.ok ? 'teal' : 'red'}
          icon={status.ok ? <IconCheck size={16} /> : <IconAlertCircle size={16} />}
          variant="light"
        >
          {status.msg}
        </Alert>
      )}

      {user?.mfa_enabled ? (
        <>
          <Text size="sm" c="dimmed">
            Enter your password to turn off two-factor authentication.
          </Text>
          <PasswordInput
            label="Current password"
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
          <Group>
            <Button color="red" variant="light" onClick={disable} disabled={!password}>
              Disable MFA
            </Button>
          </Group>
        </>
      ) : enrollment ? (
        <Card withBorder padding="md" radius="md">
          <Stack gap="sm">
            <Text size="sm">
              Add this key to your authenticator app, then enter a code to confirm.
            </Text>
            <Text size="sm">
              Manual key: <Code>{enrollment.secret}</Code>
            </Text>
            <Text size="xs" c="dimmed" style={{ wordBreak: 'break-all' }}>
              {enrollment.otpauth_uri}
            </Text>
            <PinInput length={6} type="number" value={code} onChange={setCode} oneTimeCode />
            <Group>
              <Button onClick={confirm} disabled={code.length < 6}>
                Confirm & enable
              </Button>
              <Button variant="subtle" onClick={() => setEnrollment(null)}>
                Cancel
              </Button>
            </Group>
          </Stack>
        </Card>
      ) : (
        <>
          <Text size="sm" c="dimmed">
            Protect your account with a time-based one-time code from an authenticator app.
          </Text>
          {reauthRequired && (
            <PasswordInput
              label="Current password"
              description="Required to replace your existing two-factor secret."
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
          )}
          <Group>
            <Button
              onClick={() => startEnroll(reauthRequired ? password : undefined)}
              disabled={reauthRequired && !password}
            >
              Enable MFA
            </Button>
          </Group>
        </>
      )}
    </Stack>
  );
}

function SessionsSection() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setSessions(await listSessions());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load sessions.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const onRevoke = async (id: number) => {
    try {
      await revokeSession(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to revoke.');
    }
  };

  return (
    <Stack gap="sm">
      <Title order={5}>Active sessions</Title>
      {error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
          {error}
        </Alert>
      )}
      <Table.ScrollContainer minWidth={560}>
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Last seen</Table.Th>
              <Table.Th>IP</Table.Th>
              <Table.Th>Client</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {sessions.map((s) => (
              <Table.Tr key={s.id}>
                <Table.Td>{new Date(s.last_seen_at).toLocaleString()}</Table.Td>
                <Table.Td>{s.ip ?? '—'}</Table.Td>
                <Table.Td style={{ maxWidth: 280 }}>
                  <Text size="xs" truncate>
                    {s.user_agent ?? '—'}
                  </Text>
                </Table.Td>
                <Table.Td>
                  {s.current ? (
                    <Badge variant="light">this session</Badge>
                  ) : (
                    <Button size="xs" variant="subtle" color="red" onClick={() => onRevoke(s.id)}>
                      Revoke
                    </Button>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Stack>
  );
}

/** Self-service account page: password, MFA, and active sessions. */
export function AccountPage() {
  return (
    <Stack gap="xl" maw={760}>
      <div>
        <Title order={2}>Account</Title>
        <Text c="dimmed">Manage your password, two-factor authentication, and sessions.</Text>
      </div>
      <PasswordSection />
      <Divider />
      <MfaSection />
      <Divider />
      <SessionsSection />
    </Stack>
  );
}
