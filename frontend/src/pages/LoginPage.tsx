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

/** Local-account login form. */
export function LoginPage() {
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const form = useForm({
    initialValues: { username: '', password: '' },
    validate: {
      username: (v) => (v.trim().length >= 3 ? null : 'Enter your username'),
      password: (v) => (v.length > 0 ? null : 'Enter your password'),
    },
  });

  const submit = form.onSubmit(async ({ username, password }) => {
    setSubmitting(true);
    setError(null);
    try {
      await login(username.trim(), password);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Login failed — is the server reachable?');
    } finally {
      setSubmitting(false);
    }
  });

  return (
    <Center mih="100vh" p="md">
      <Paper withBorder radius="md" p="xl" w={380}>
        <form onSubmit={submit}>
          <Stack gap="md">
            <div>
              <Title order={2} c="teal">
                Scrye
              </Title>
              <Text c="dimmed" size="sm">
                Sign in to continue
              </Text>
            </div>
            {error && (
              <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
                {error}
              </Alert>
            )}
            <TextInput
              label="Username"
              autoComplete="username"
              autoFocus
              {...form.getInputProps('username')}
            />
            <PasswordInput
              label="Password"
              autoComplete="current-password"
              {...form.getInputProps('password')}
            />
            <Button type="submit" loading={submitting} fullWidth>
              Sign in
            </Button>
          </Stack>
        </form>
      </Paper>
    </Center>
  );
}
