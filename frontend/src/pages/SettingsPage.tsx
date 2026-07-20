import { Stack, Tabs, Text, Title } from '@mantine/core';
import {
  IconAdjustments,
  IconBell,
  IconBrandDocker,
  IconCalendarClock,
  IconDatabaseExport,
  IconGitBranch,
  IconInfoCircle,
  IconKey,
  IconLock,
  IconServer2,
  IconSettings,
  IconShieldCheck,
  IconTrashX,
  IconUsers,
} from '@tabler/icons-react';

import { AboutPanel } from '../components/settings/AboutPanel';
import { ApiTokensPanel } from '../components/settings/ApiTokensPanel';
import { AuthenticationPanel } from '../components/settings/AuthenticationPanel';
import { BackupsPanel } from '../components/settings/BackupsPanel';
import { DockerEnvironmentsPanel } from '../components/settings/DockerEnvironmentsPanel';
import { GeneralPanel } from '../components/settings/GeneralPanel';
import { GitCredentialsPanel } from '../components/settings/GitCredentialsPanel';
import { NotificationsPanel } from '../components/settings/NotificationsPanel';
import { RegistriesPanel } from '../components/settings/RegistriesPanel';
import { RetentionPanel } from '../components/settings/RetentionPanel';
import { ScannersPanel } from '../components/settings/ScannersPanel';
import { ScheduledScansPanel } from '../components/settings/ScheduledScansPanel';
import { TrivyPolicyPanel } from '../components/settings/TrivyPolicyPanel';
import { UsersPanel } from '../components/settings/UsersPanel';
import { useAuth } from '../auth/AuthContext';

/** Full settings area (docs/ARCHIVE.md §4.5). Admin tabs are gated by role. */
export function SettingsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  return (
    <Stack gap="md">
      <div>
        <Title order={2}>Settings</Title>
        <Text c="dimmed">
          {isAdmin
            ? 'Configure the instance, authentication, credentials, and backups.'
            : 'View instance configuration and manage your API tokens.'}
        </Text>
      </div>

      <Tabs
        defaultValue={isAdmin ? 'general' : 'scanners'}
        keepMounted={false}
        orientation="vertical"
      >
        <Tabs.List>
          {isAdmin && (
            <>
              <Tabs.Tab value="general" leftSection={<IconSettings size={16} />}>
                General
              </Tabs.Tab>
              <Tabs.Tab value="authentication" leftSection={<IconLock size={16} />}>
                Authentication
              </Tabs.Tab>
              <Tabs.Tab value="users" leftSection={<IconUsers size={16} />}>
                Users &amp; roles
              </Tabs.Tab>
            </>
          )}
          <Tabs.Tab value="scanners" leftSection={<IconAdjustments size={16} />}>
            Scanners
          </Tabs.Tab>
          <Tabs.Tab value="schedules" leftSection={<IconCalendarClock size={16} />}>
            Scheduled scans
          </Tabs.Tab>
          {isAdmin && (
            <>
              <Tabs.Tab value="trivy-policy" leftSection={<IconShieldCheck size={16} />}>
                Trivy policy
              </Tabs.Tab>
              <Tabs.Tab value="registries" leftSection={<IconServer2 size={16} />}>
                Registries
              </Tabs.Tab>
              <Tabs.Tab value="git" leftSection={<IconGitBranch size={16} />}>
                Git providers
              </Tabs.Tab>
              <Tabs.Tab value="docker" leftSection={<IconBrandDocker size={16} />}>
                Docker environments
              </Tabs.Tab>
              <Tabs.Tab value="notifications" leftSection={<IconBell size={16} />}>
                Notifications
              </Tabs.Tab>
              <Tabs.Tab value="retention" leftSection={<IconTrashX size={16} />}>
                Retention
              </Tabs.Tab>
            </>
          )}
          <Tabs.Tab value="tokens" leftSection={<IconKey size={16} />}>
            API tokens
          </Tabs.Tab>
          {isAdmin && (
            <Tabs.Tab value="backups" leftSection={<IconDatabaseExport size={16} />}>
              Backup &amp; restore
            </Tabs.Tab>
          )}
          <Tabs.Tab value="about" leftSection={<IconInfoCircle size={16} />}>
            About
          </Tabs.Tab>
        </Tabs.List>

        {isAdmin && (
          <>
            <Tabs.Panel value="general" pl="lg">
              <GeneralPanel />
            </Tabs.Panel>
            <Tabs.Panel value="authentication" pl="lg">
              <AuthenticationPanel />
            </Tabs.Panel>
            <Tabs.Panel value="users" pl="lg">
              <UsersPanel />
            </Tabs.Panel>
          </>
        )}
        <Tabs.Panel value="scanners" pl="lg">
          <ScannersPanel />
        </Tabs.Panel>
        <Tabs.Panel value="schedules" pl="lg">
          <ScheduledScansPanel />
        </Tabs.Panel>
        {isAdmin && (
          <>
            <Tabs.Panel value="trivy-policy" pl="lg">
              <TrivyPolicyPanel />
            </Tabs.Panel>
            <Tabs.Panel value="registries" pl="lg">
              <RegistriesPanel />
            </Tabs.Panel>
            <Tabs.Panel value="git" pl="lg">
              <GitCredentialsPanel />
            </Tabs.Panel>
            <Tabs.Panel value="docker" pl="lg">
              <DockerEnvironmentsPanel />
            </Tabs.Panel>
            <Tabs.Panel value="notifications" pl="lg">
              <NotificationsPanel />
            </Tabs.Panel>
            <Tabs.Panel value="retention" pl="lg">
              <RetentionPanel />
            </Tabs.Panel>
          </>
        )}
        <Tabs.Panel value="tokens" pl="lg">
          <ApiTokensPanel />
        </Tabs.Panel>
        {isAdmin && (
          <Tabs.Panel value="backups" pl="lg">
            <BackupsPanel />
          </Tabs.Panel>
        )}
        <Tabs.Panel value="about" pl="lg">
          <AboutPanel />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
