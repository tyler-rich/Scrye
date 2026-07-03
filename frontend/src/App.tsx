import { AppShell, Center, Group, Loader, Text, Title } from '@mantine/core';

import { ColorSchemeToggle } from './components/ColorSchemeToggle';
import { UserMenu } from './components/UserMenu';
import { useAuth } from './auth/AuthContext';
import { Dashboard } from './pages/Dashboard';
import { LoginPage } from './pages/LoginPage';
import { SetupPage } from './pages/SetupPage';

/**
 * Application shell. Renders the bootstrap/setup screen on a fresh install,
 * the login screen when signed out, and the app (header + dashboard) once
 * authenticated. Routing and full navigation arrive in later phases.
 */
export function App() {
  const { loading, needsSetup, user } = useAuth();

  if (loading) {
    return (
      <Center mih="100vh">
        <Loader color="teal" />
      </Center>
    );
  }
  if (needsSetup) {
    return <SetupPage />;
  }
  if (!user) {
    return <LoginPage />;
  }

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
          <Group gap="sm">
            <ColorSchemeToggle />
            <UserMenu />
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Main>
        <Dashboard />
      </AppShell.Main>
    </AppShell>
  );
}
