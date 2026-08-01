import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Center,
  Divider,
  Paper,
  PasswordInput,
  PinInput,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconLogin2 } from '@tabler/icons-react';

import { OIDC_LOGIN_PATH } from '../api/oidc';
import { ApiError } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import { InsecureTransportAlert } from '../components/InsecureTransportAlert';

const OIDC_ERRORS: Record<string, string> = {
  disabled: 'OIDC sign-in is not enabled.',
  discovery: 'Could not reach the identity provider.',
  provider: 'The identity provider reported an error.',
  invalid_response: 'The sign-in response was invalid.',
  expired: 'The sign-in attempt expired; please try again.',
  validation: 'The identity provider response failed validation.',
  not_provisioned: 'No account is linked to that identity.',
  inactive: 'Your account is inactive.',
  config: 'OIDC is misconfigured; contact an administrator.',
  insecure_transport:
    'Sign-in requires HTTPS: this server marks its session cookie Secure, so a browser will not keep it on an http:// page. See the banner above.',
};

/** Local-account login form, with optional OIDC sign-in and MFA challenge. */
export function LoginPage() {
  const { login, verifyMfa, refresh, oidc, insecureTransport } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [enroll, setEnroll] = useState<{ secret: string; uri: string | null } | null>(null);
  const [code, setCode] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const oidcError = params.get('oidc_error');
    if (oidcError) {
      setError(OIDC_ERRORS[oidcError] ?? 'OIDC sign-in failed.');
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

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
      const result = await login(username.trim(), password);
      if (result.mfa_required && result.mfa_token) {
        setMfaToken(result.mfa_token);
        if (result.enrollment_required && result.mfa_secret) {
          setEnroll({ secret: result.mfa_secret, uri: result.otpauth_uri ?? null });
        }
      }
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Login failed — is the server reachable?');
    } finally {
      setSubmitting(false);
    }
  });

  const submitMfa = async () => {
    if (!mfaToken) return;
    setSubmitting(true);
    setError(null);
    try {
      await verifyMfa(mfaToken, code);
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Verification failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Center mih="100vh" p="md">
      <Paper withBorder radius="md" p="xl" w={insecureTransport ? 460 : 380}>
        <Stack gap="md">
          <div>
            <Title order={2} c="teal">
              Scrye
            </Title>
            <Text c="dimmed" size="sm">
              {mfaToken ? 'Enter your authentication code' : 'Sign in to continue'}
            </Text>
          </div>
          {insecureTransport && <InsecureTransportAlert />}
          {error && (
            <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
              {error}
            </Alert>
          )}

          {mfaToken ? (
            <Stack gap="md">
              {enroll ? (
                <Stack gap="xs">
                  <Text size="sm">
                    This account requires multi-factor authentication. Add the key below to your
                    authenticator app, then enter the 6-digit code to finish signing in.
                  </Text>
                  <Text size="xs" c="dimmed">
                    Manual key
                  </Text>
                  <Text size="sm" ff="monospace" style={{ wordBreak: 'break-all' }}>
                    {enroll.secret}
                  </Text>
                </Stack>
              ) : (
                <Text size="sm">
                  Enter the 6-digit code from your authenticator app to finish signing in.
                </Text>
              )}
              <PinInput
                length={6}
                oneTimeCode
                type="number"
                value={code}
                onChange={setCode}
                aria-label="Authentication code"
              />
              <Button
                onClick={() => void submitMfa()}
                loading={submitting}
                disabled={code.length < 6}
                fullWidth
              >
                Verify
              </Button>
              <Button
                variant="subtle"
                onClick={() => {
                  setMfaToken(null);
                  setEnroll(null);
                  setCode('');
                }}
              >
                Back
              </Button>
            </Stack>
          ) : (
            <form onSubmit={submit}>
              <Stack gap="md">
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
          )}

          {!mfaToken && oidc.enabled && (
            <>
              <Divider label="or" labelPosition="center" />
              <Button
                component="a"
                href={OIDC_LOGIN_PATH}
                variant="light"
                leftSection={<IconLogin2 size={16} />}
                fullWidth
              >
                Sign in with {oidc.display_name}
              </Button>
            </>
          )}
        </Stack>
      </Paper>
    </Center>
  );
}
