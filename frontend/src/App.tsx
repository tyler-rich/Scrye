import { AppShell, Button, Center, Group, Loader, Text, Title } from '@mantine/core';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { ColorSchemeToggle } from './components/ColorSchemeToggle';
import { UserMenu } from './components/UserMenu';
import { useAuth } from './auth/AuthContext';
import { AccountPage } from './pages/AccountPage';
import { Dashboard } from './pages/Dashboard';
import { LoginPage } from './pages/LoginPage';
import { NewScanPage } from './pages/NewScanPage';
import { ScanDetailPage } from './pages/ScanDetailPage';
import { ScanDiffPage } from './pages/ScanDiffPage';
import { ScansPage } from './pages/ScansPage';
import { SettingsPage } from './pages/SettingsPage';
import { SetupPage } from './pages/SetupPage';

const BASE_NAV_LINKS = [
  { to: '/', label: 'Dashboard' },
  { to: '/scans', label: 'Scans' },
  { to: '/scans/new', label: 'New scan' },
];

/** Header navigation links, highlighting the active section. */
function NavLinks() {
  const { pathname } = useLocation();
  const { user } = useAuth();
  const isActive = (to: string) => (to === '/' ? pathname === '/' : pathname.startsWith(to));
  const links =
    user && user.role !== 'viewer'
      ? [...BASE_NAV_LINKS, { to: '/settings', label: 'Settings' }]
      : BASE_NAV_LINKS;
  return (
    <Group gap="xs" visibleFrom="sm">
      {links.map((link) => (
        <Button
          key={link.to}
          component={Link}
          to={link.to}
          variant={isActive(link.to) ? 'light' : 'subtle'}
          size="compact-md"
        >
          {link.label}
        </Button>
      ))}
    </Group>
  );
}

/**
 * Application shell. Renders the bootstrap/setup screen on a fresh install, the
 * login screen when signed out, and the routed app once authenticated.
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
          <Group gap="lg">
            <Group gap="xs">
              <Title order={3} c="teal">
                Scrye
              </Title>
              <Text size="sm" c="dimmed" visibleFrom="md">
                Trivy + Grype, unified
              </Text>
            </Group>
            <NavLinks />
          </Group>
          <Group gap="sm">
            <ColorSchemeToggle />
            <UserMenu />
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Main>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="/scans/new" element={<NewScanPage />} />
          <Route path="/scans/diff/:baseId/:compareId" element={<ScanDiffPage />} />
          <Route path="/scans/:scanId" element={<ScanDetailPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/account" element={<AccountPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell.Main>
    </AppShell>
  );
}
