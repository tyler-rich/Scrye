import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Code,
  Divider,
  Group,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconCheck } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import { getAuthSettings, updateAuthSettings, type MfaPolicy } from '../../api/settings';
import { getOidcConfig, updateOidcConfig, type OidcConfig } from '../../api/oidc';
import { OidcLinkCard } from './OidcLinkCard';

const MFA_POLICIES: { value: MfaPolicy; label: string }[] = [
  { value: 'optional', label: 'Optional (users choose)' },
  { value: 'required_admin', label: 'Required for admins' },
  { value: 'required_all', label: 'Required for everyone' },
];

/** Authentication policy (local login, MFA policy) and OIDC configuration. */
export function AuthenticationPanel() {
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [oidc, setOidc] = useState<OidcConfig | null>(null);

  const policyForm = useForm<{ local_login_enabled: boolean; mfa_policy: MfaPolicy }>({
    initialValues: { local_login_enabled: true, mfa_policy: 'optional' },
  });

  const oidcForm = useForm({
    initialValues: {
      enabled: false,
      display_name: 'OIDC',
      issuer: '',
      client_id: '',
      client_secret: '',
      scopes: 'openid profile email',
      username_claim: 'preferred_username',
      email_claim: 'email',
      groups_claim: '',
      admin_group: '',
      auto_provision: true,
      default_role: 'viewer' as OidcConfig['default_role'],
    },
  });

  useEffect(() => {
    void getAuthSettings()
      .then((v) => policyForm.setValues(v))
      .catch(() => setError('Failed to load authentication settings.'));
    void getOidcConfig()
      .then((cfg) => {
        setOidc(cfg);
        oidcForm.setValues({
          enabled: cfg.enabled,
          display_name: cfg.display_name,
          issuer: cfg.issuer ?? '',
          client_id: cfg.client_id ?? '',
          client_secret: '',
          scopes: cfg.scopes,
          username_claim: cfg.username_claim,
          email_claim: cfg.email_claim,
          groups_claim: cfg.groups_claim ?? '',
          admin_group: cfg.admin_group ?? '',
          auto_provision: cfg.auto_provision,
          default_role: cfg.default_role,
        });
      })
      .catch(() => setError('Failed to load OIDC configuration.'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const savePolicy = policyForm.onSubmit(async (values) => {
    setError(null);
    setSaved(null);
    try {
      await updateAuthSettings(values);
      setSaved('policy');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save policy.');
    }
  });

  const saveOidc = oidcForm.onSubmit(async (values) => {
    setError(null);
    setSaved(null);
    try {
      const body = {
        ...values,
        groups_claim: values.groups_claim || null,
        admin_group: values.admin_group || null,
        // Only send the secret when the admin typed a new one.
        ...(values.client_secret ? { client_secret: values.client_secret } : {}),
      };
      if (!values.client_secret) delete (body as { client_secret?: string }).client_secret;
      const updated = await updateOidcConfig(body);
      setOidc(updated);
      oidcForm.setFieldValue('client_secret', '');
      setSaved('oidc');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save OIDC configuration.');
    }
  });

  return (
    <Stack gap="xl">
      {error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
          {error}
        </Alert>
      )}

      <form onSubmit={savePolicy}>
        <Stack gap="md" maw={520}>
          <Title order={5}>Sign-in policy</Title>
          {saved === 'policy' && (
            <Alert color="teal" icon={<IconCheck size={16} />} variant="light">
              Policy saved.
            </Alert>
          )}
          <Switch
            label="Allow username / password login"
            description="Requires OIDC to be enabled before it can be turned off."
            {...policyForm.getInputProps('local_login_enabled', { type: 'checkbox' })}
          />
          <Select
            label="MFA policy"
            data={MFA_POLICIES}
            allowDeselect={false}
            {...policyForm.getInputProps('mfa_policy')}
          />
          <Group>
            <Button type="submit">Save policy</Button>
          </Group>
        </Stack>
      </form>

      <Divider />

      <form onSubmit={saveOidc}>
        <Stack gap="md" maw={520}>
          <Title order={5}>OIDC provider</Title>
          {saved === 'oidc' && (
            <Alert color="teal" icon={<IconCheck size={16} />} variant="light">
              OIDC configuration saved.
              {oidc?.enabled && (
                <>
                  {' '}
                  Link <strong>your</strong> account below so you can sign in with{' '}
                  {oidc.display_name} — otherwise your first OIDC sign-in creates a second, separate
                  account.
                </>
              )}
            </Alert>
          )}
          <Switch
            label="Enable OIDC sign-in"
            {...oidcForm.getInputProps('enabled', { type: 'checkbox' })}
          />
          <TextInput
            label="Button label"
            placeholder="Pocket ID"
            {...oidcForm.getInputProps('display_name')}
          />
          <TextInput
            label="Issuer URL"
            placeholder="https://pocket-id.example.com"
            {...oidcForm.getInputProps('issuer')}
          />
          <TextInput label="Client ID" {...oidcForm.getInputProps('client_id')} />
          <PasswordInput
            label="Client secret"
            description={
              oidc?.client_secret.is_set
                ? 'A secret is stored. Leave blank to keep it.'
                : 'Set the client secret (public clients with PKCE may leave this blank).'
            }
            placeholder={oidc?.client_secret.is_set ? '••••••••' : ''}
            {...oidcForm.getInputProps('client_secret')}
          />
          <TextInput label="Scopes" {...oidcForm.getInputProps('scopes')} />
          <Group grow>
            <TextInput label="Username claim" {...oidcForm.getInputProps('username_claim')} />
            <TextInput label="Email claim" {...oidcForm.getInputProps('email_claim')} />
          </Group>
          <Group grow>
            <TextInput
              label="Groups claim"
              placeholder="groups"
              {...oidcForm.getInputProps('groups_claim')}
            />
            <TextInput
              label="Admin group"
              placeholder="scrye-admins"
              {...oidcForm.getInputProps('admin_group')}
            />
          </Group>
          <Switch
            label="Auto-provision new users on first login"
            {...oidcForm.getInputProps('auto_provision', { type: 'checkbox' })}
          />
          <Select
            label="Default role for provisioned users"
            data={['viewer', 'operator', 'admin']}
            allowDeselect={false}
            {...oidcForm.getInputProps('default_role')}
          />
          {oidc && (
            <Text size="sm" c="dimmed">
              Redirect URI to register at the provider: <Code>{oidc.callback_path}</Code>
            </Text>
          )}
          <Group>
            <Button type="submit">Save OIDC</Button>
          </Group>
        </Stack>
      </form>

      <Divider />

      <OidcLinkCard enabled={Boolean(oidc?.enabled)} />
    </Stack>
  );
}
