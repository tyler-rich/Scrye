import { AppShell, Group, Text, Title } from '@mantine/core';

import { ColorSchemeToggle } from './components/ColorSchemeToggle';
import { Dashboard } from './pages/Dashboard';

/**
 * Application shell for the Phase 0 skeleton: a header with the brand and the
 * light/dark toggle, plus the placeholder dashboard. Routing and the full
 * navigation arrive in later phases.
 */
export function App() {
  return (
    <AppShell header={{ height: 56 }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group gap="xs">
            <Title order={3} c="teal">
              Scrye
            </Title>
            <Text size="sm" c="dimmed" visibleFrom="sm">
              Trivy + Grype, unified
            </Text>
          </Group>
          <ColorSchemeToggle />
        </Group>
      </AppShell.Header>

      <AppShell.Main>
        <Dashboard />
      </AppShell.Main>
    </AppShell>
  );
}
