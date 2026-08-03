import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Group,
  Paper,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import {
  IconAlertCircle,
  IconCheck,
  IconLink,
  IconShieldLock,
  IconUnlink,
} from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import {
  getOidcLinkStatus,
  startOidcLink,
  unlinkOidcIdentity,
  type OidcLinkStatus,
} from '../../api/oidc';
import { formatWhen } from '../../lib/dates';

/**
 * Outcome codes the backend's link callback redirects back with. It always
 * returns to this fixed settings path — there is no `return_to` parameter
 * anywhere in the flow, so no open-redirect surface.
 */
const LINK_ERRORS: Record<string, string> = {
  session_mismatch:
    'The sign-in did not complete under the account that started it. Sign in again in this browser, then retry.',
  identity_in_use: 'That identity provider account is already linked to a different Scrye user.',
  issuer_already_linked:
    'Your account already has an identity linked for this provider. Unlink it first, then link again.',
  expired: 'The link attempt expired or was completed in a different browser; please try again.',
  disabled: 'OIDC sign-in is not enabled.',
  provider: 'The identity provider reported an error.',
  invalid_response: 'The response from the identity provider was invalid.',
  validation: 'The identity provider response failed validation.',
  config: 'OIDC is misconfigured; check the provider settings above.',
};

const LINK_SUCCESS: Record<string, string> = {
  success: 'Your account is now linked. You can sign in with either method from now on.',
  unchanged: 'That identity was already linked to your account — nothing changed.',
};

/**
 * Link the signed-in admin's *own* account to an OIDC identity, and unlink it.
 *
 * This exists because an existing local account cannot otherwise acquire an OIDC
 * identity: signing in with OIDC either mints a duplicate account or dead-ends,
 * and the manual alternative needs the provider's opaque subject, which several
 * providers never display. Running the handshake while signed in retrieves it
 * automatically — nobody ever types or sees a subject.
 *
 * Both actions re-verify the current password (and a TOTP code when enrolled),
 * because each one changes how the account can be signed into.
 */
export function OidcLinkCard({ enabled }: { enabled: boolean }) {
  const [status, setStatus] = useState<OidcLinkStatus | null>(null);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(() => {
    void getOidcLinkStatus()
      .then(setStatus)
      .catch(() => setError('Failed to load your OIDC link status.'));
  }, []);

  useEffect(load, [load, enabled]);

  // The callback returns the browser here with the outcome in the query string;
  // read it once, then strip it so a refresh doesn't replay a stale banner.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ok = params.get('oidc_link');
    const failed = params.get('oidc_link_error');
    if (!ok && !failed) return;
    if (ok) setNotice(LINK_SUCCESS[ok] ?? 'Linking finished.');
    if (failed) setError(LINK_ERRORS[failed] ?? 'Linking failed.');
    window.history.replaceState({}, '', window.location.pathname);
  }, []);

  const reauth = () => ({
    current_password: password,
    ...(status?.mfa_enrolled ? { totp_code: code.trim() } : {}),
  });

  const clearCredentials = () => {
    setPassword('');
    setCode('');
  };

  const link = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const { authorization_url } = await startOidcLink(reauth());
      clearCredentials();
      // Full navigation, not fetch: the provider owns the next page.
      window.location.assign(authorization_url);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not start linking.');
      setBusy(false);
    }
  };

  const unlink = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await unlinkOidcIdentity(reauth());
      clearCredentials();
      setNotice('Your OIDC identity has been unlinked.');
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not unlink.');
    } finally {
      setBusy(false);
    }
  };

  if (!status) return null;

  const canSubmit = password.length > 0 && (!status.mfa_enrolled || code.trim().length >= 6);

  return (
    <Paper withBorder radius="md" p="md" maw={520}>
      <Stack gap="md">
        <Group justify="space-between" align="center">
          <Title order={5}>Your linked identity</Title>
          <Badge color={status.linked ? 'teal' : 'gray'} variant="light">
            {status.linked ? 'Linked' : 'Not linked'}
          </Badge>
        </Group>

        {notice && (
          <Alert color="teal" icon={<IconCheck size={16} />} variant="light">
            {notice}
          </Alert>
        )}
        {error && (
          <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
            {error}
          </Alert>
        )}

        {status.linked ? (
          <Stack gap={2}>
            <Text size="sm">
              Signing in with {status.display_name} will use your existing Scrye account.
            </Text>
            <Text size="xs" c="dimmed">
              Provider: {status.issuer}
              {status.email ? ` · ${status.email}` : ''}
            </Text>
            <Text size="xs" c="dimmed">
              Linked {formatWhen(status.linked_at)} · last used{' '}
              {status.last_login_at ? formatWhen(status.last_login_at) : 'never'}
            </Text>
            {!status.last_login_at && (
              <Text size="xs" c="dimmed">
                If signing in with {status.display_name} stops matching this account, the provider
                may have re-issued your identity. See the re-link runbook in the README: unlink
                here, then link again.
              </Text>
            )}
          </Stack>
        ) : (
          <Text size="sm">
            Link your account to sign in with {status.display_name} without creating a second,
            separate Scrye account. You will be sent to the provider to sign in once; Scrye reads
            your identity from the response automatically.
          </Text>
        )}

        {!status.provider_ready && !status.linked && (
          <Alert color="gray" variant="light">
            Enable and save an OIDC provider above before linking your account.
          </Alert>
        )}

        {status.mfa_delegation_warning && !status.linked && (
          <Alert color="yellow" icon={<IconShieldLock size={16} />} variant="light">
            Signing in with {status.display_name} will not ask for your Scrye MFA code — your
            identity provider&apos;s MFA (if configured) applies instead. Make sure the provider
            enforces a second factor before linking.
          </Alert>
        )}

        <Stack gap="xs">
          <Text size="xs" c="dimmed">
            {status.linked ? 'Unlinking' : 'Linking'} changes how you can sign in, so it needs your
            credentials again — a session alone is not enough.
          </Text>
          <PasswordInput
            label="Current password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
          {status.mfa_enrolled && (
            <TextInput
              label="Authentication code"
              placeholder="123456"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(event) => setCode(event.currentTarget.value)}
            />
          )}
        </Stack>

        <Group>
          {status.linked ? (
            <Button
              color="red"
              variant="light"
              leftSection={<IconUnlink size={16} />}
              loading={busy}
              disabled={!canSubmit}
              onClick={() => void unlink()}
            >
              Unlink
            </Button>
          ) : (
            <Button
              leftSection={<IconLink size={16} />}
              loading={busy}
              disabled={!canSubmit || !status.provider_ready}
              onClick={() => void link()}
            >
              Link my account
            </Button>
          )}
        </Group>
      </Stack>
    </Paper>
  );
}
