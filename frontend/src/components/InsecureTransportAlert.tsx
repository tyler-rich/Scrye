import { Alert, Code, List, Stack, Text } from '@mantine/core';
import { IconLockOff } from '@tabler/icons-react';

/**
 * Login/setup banner for the one failure mode that otherwise looks like bad
 * credentials: the server marks its session cookie `Secure`, but this page was
 * loaded over plain HTTP, so the browser will refuse to store it and sign-in
 * cannot complete.
 *
 * Shown from `/auth/status` (`https_enforced && !transport_secure`) — i.e.
 * *before* anything is typed and regardless of whether the credentials that get
 * submitted are right. It describes the transport only and never reflects any
 * credential state, so it gives an attacker nothing to distinguish a valid
 * account from an invalid one.
 */
export function InsecureTransportAlert() {
  return (
    <Alert
      color="orange"
      variant="light"
      icon={<IconLockOff size={16} />}
      title="Sign-in requires HTTPS"
    >
      <Stack gap="xs">
        <Text size="sm">
          You are viewing Scrye over plain <Code>http://</Code>. This server marks its session
          cookie <Code>Secure</Code>, so your browser will discard it and the sign-in cannot take
          effect. This is a server configuration issue — not a problem with your username or
          password.
        </Text>
        <Text size="sm">An administrator can fix it in one of three ways:</Text>
        <List size="sm" spacing={4}>
          <List.Item>
            Reach Scrye over <Code>https://</Code>.
          </List.Item>
          <List.Item>
            If a reverse proxy terminates TLS, have it send <Code>X-Forwarded-Proto: https</Code>{' '}
            and set <Code>SCRYE_FORWARDED_ALLOW_IPS</Code> to the address that proxy connects from.
          </List.Item>
          <List.Item>
            For a deliberate plain-HTTP deployment (LAN or evaluation), set{' '}
            <Code>SCRYE_SESSION_COOKIE_SECURE=false</Code> and restart — the session cookie then
            travels unencrypted.
          </List.Item>
        </List>
      </Stack>
    </Alert>
  );
}
