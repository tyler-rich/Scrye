import { AppShell, Burger, Button, Center, Drawer, Group, Stack, Text, Title } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { ColorSchemeToggle } from './components/ColorSchemeToggle';
import { StatusLoader } from './components/StatusLoader';
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

/** Resolve the visible nav links and the currently-active one for this user. */
function useNavItems() {
  const { pathname } = useLocation();
  const { user } = useAuth();
  const links =
    user && user.role !== 'viewer'
      ? [...BASE_NAV_LINKS, { to: '/settings', label: 'Settings' }]
      : BASE_NAV_LINKS;

  // A nav item matches its own route and any child route ("/scans" also covers
  // "/scans/123"), but not a sibling. To keep "/scans/new" from also lighting
  // up "Scans", we pick the *longest* matching path — the most specific nav
  // item wins — rather than highlighting every prefix match (FE nav bug).
  const matches = (to: string) =>
    to === '/' ? pathname === '/' : pathname === to || pathname.startsWith(`${to}/`);
  const activeTo = links
    .filter((link) => matches(link.to))
    .reduce((best, link) => (link.to.length > best.length ? link.to : best), '');

  return { links, activeTo };
}

/**
 * Navigation links, highlighting the active section. Renders horizontally in
 * the header from `sm` up; the vertical variant fills the mobile drawer
 * (L22 / P2-7).
 */
function NavLinks({
  orientation = 'horizontal',
  onNavigate,
}: {
  orientation?: 'horizontal' | 'vertical';
  onNavigate?: () => void;
}) {
  const { links, activeTo } = useNavItems();
  const vertical = orientation === 'vertical';
  const items = links.map((link) => (
    <Button
      key={link.to}
      component={Link}
      to={link.to}
      onClick={onNavigate}
      variant={link.to === activeTo ? 'light' : 'subtle'}
      size="compact-md"
      justify={vertical ? 'flex-start' : undefined}
      fullWidth={vertical}
    >
      {link.label}
    </Button>
  ));

  return vertical ? (
    <Stack gap="xs">{items}</Stack>
  ) : (
    <Group gap="xs" visibleFrom="sm">
      {items}
    </Group>
  );
}

/**
 * Application shell. Renders the bootstrap/setup screen on a fresh install, the
 * login screen when signed out, and the routed app once authenticated.
 */
export function App() {
  const { loading, needsSetup, user } = useAuth();
  const [mobileNavOpened, { toggle: toggleMobileNav, close: closeMobileNav }] =
    useDisclosure(false);

  if (loading) {
    return (
      <Center mih="100vh">
        <StatusLoader color="teal" />
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
            <Burger
              opened={mobileNavOpened}
              onClick={toggleMobileNav}
              hiddenFrom="sm"
              size="sm"
              aria-label="Toggle navigation"
            />
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

      <Drawer
        opened={mobileNavOpened}
        onClose={closeMobileNav}
        hiddenFrom="sm"
        size="xs"
        title="Navigation"
      >
        <NavLinks orientation="vertical" onNavigate={closeMobileNav} />
      </Drawer>

      <AppShell.Main>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="/scans/new" element={<NewScanPage />} />
          <Route path="/scans/diff/:baseId/:compareId" element={<ScanDiffPage />} />
          <Route path="/scans/:scanId" element={<ScanDetailPage />} />
          <Route
            path="/settings"
            element={user.role !== 'viewer' ? <SettingsPage /> : <Navigate to="/" replace />}
          />
          <Route path="/account" element={<AccountPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell.Main>
    </AppShell>
  );
}
