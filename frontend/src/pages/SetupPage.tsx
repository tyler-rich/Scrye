import { useState } from 'react';
import {
  Alert,
  Button,
  Center,
  Paper,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle } from '@tabler/icons-react';

import { ApiError } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { InsecureTransportAlert } from '../components/InsecureTransportAlert';

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,64}$/;
const PASSWORD_MIN = 12;

/** First-run bootstrap: create the initial admin account. */
export function SetupPage() {
  const { setup, insecureTransport } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const form = useForm({
    initialValues: { username: '', password: '', confirm: '' },
    validate: {
      username: (v) =>
        USERNAME_RE.test(v.trim()) ? null : '3–64 characters: letters, digits, . _ -',
      password: (v) =>
        v.length >= PASSWORD_MIN ? null : `Use at least ${PASSWORD_MIN} characters`,
      confirm: (v, values) => (v === values.password ? null : 'Passwords do not match'),
    },
  });

  const submit = form.onSubmit(async ({ username, password }) => {
    setSubmitting(true);
    setError(null);
    try {
      await setup(username.trim(), password);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Setup failed — is the server reachable?');
    } finally {
      setSubmitting(false);
    }
  });

  return (
    <Center mih="100vh" p="md">
      <Paper withBorder radius="md" p="xl" w={insecureTransport ? 480 : 420}>
        <form onSubmit={submit}>
          <Stack gap="md">
            <div>
              <Title order={2} c="teal">
                Welcome to Scrye
              </Title>
              <Text c="dimmed" size="sm">
                Create the first administrator account. This screen is only available while no
                accounts exist.
              </Text>
            </div>
            {insecureTransport && <InsecureTransportAlert />}
            {error && (
              <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
                {error}
              </Alert>
            )}
            <TextInput
              label="Admin username"
              autoComplete="username"
              autoFocus
              {...form.getInputProps('username')}
            />
            <PasswordInput
              label="Password"
              description={`At least ${PASSWORD_MIN} characters`}
              autoComplete="new-password"
              {...form.getInputProps('password')}
            />
            <PasswordInput
              label="Confirm password"
              autoComplete="new-password"
              {...form.getInputProps('confirm')}
            />
            <Button type="submit" loading={submitting} fullWidth>
              Create admin account
            </Button>
          </Stack>
        </form>
      </Paper>
    </Center>
  );
}
