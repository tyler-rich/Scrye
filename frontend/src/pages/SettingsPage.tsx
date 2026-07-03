import { Stack, Tabs, Text, Title } from '@mantine/core';
import { IconBrandDocker, IconGitBranch, IconServer2 } from '@tabler/icons-react';

import { DockerEnvironmentsPanel } from '../components/settings/DockerEnvironmentsPanel';
import { GitCredentialsPanel } from '../components/settings/GitCredentialsPanel';
import { RegistriesPanel } from '../components/settings/RegistriesPanel';
import { useAuth } from '../auth/AuthContext';

/** Settings area: registries, git credentials, and Docker environments. */
export function SettingsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  return (
    <Stack gap="md">
      <div>
        <Title order={2}>Settings</Title>
        <Text c="dimmed">
          {isAdmin
            ? 'Manage credentials and scan targets.'
            : 'View configured credentials and targets (admin required to edit).'}
        </Text>
      </div>

      <Tabs defaultValue="registries" keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="registries" leftSection={<IconServer2 size={16} />}>
            Registries
          </Tabs.Tab>
          <Tabs.Tab value="git" leftSection={<IconGitBranch size={16} />}>
            Git providers
          </Tabs.Tab>
          <Tabs.Tab value="docker" leftSection={<IconBrandDocker size={16} />}>
            Docker environments
          </Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="registries" pt="md">
          <RegistriesPanel />
        </Tabs.Panel>
        <Tabs.Panel value="git" pt="md">
          <GitCredentialsPanel />
        </Tabs.Panel>
        <Tabs.Panel value="docker" pt="md">
          <DockerEnvironmentsPanel />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
