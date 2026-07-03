import { useEffect, useState } from 'react';
import { Badge, Card, Group, Stack, Text, Title } from '@mantine/core';

import { fetchHealth, type HealthStatus } from '../api/health';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ok'; health: HealthStatus }
  | { kind: 'error'; message: string };

/**
 * Placeholder landing page for the Phase 0 skeleton. It exercises the API by
 * showing live backend health; real dashboard widgets arrive in Phase 6.
 */
export function Dashboard() {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    fetchHealth()
      .then((health) => {
        if (!cancelled) setState({ kind: 'ok', health });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Unknown error',
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <Stack gap="md">
      <div>
        <Title order={2}>Welcome to Scrye</Title>
        <Text c="dimmed">A unified, self-hosted web UI for the Trivy and Grype scanners.</Text>
      </div>

      <Card withBorder radius="md" padding="lg" maw={420}>
        <Title order={4} mb="sm">
          Backend health
        </Title>
        {state.kind === 'loading' && <Text c="dimmed">Checking…</Text>}
        {state.kind === 'error' && (
          <Group gap="xs">
            <Badge color="red">unreachable</Badge>
            <Text size="sm" c="dimmed">
              {state.message}
            </Text>
          </Group>
        )}
        {state.kind === 'ok' && (
          <Stack gap="xs">
            <Group gap="xs">
              <Text size="sm" fw={500}>
                Status
              </Text>
              <Badge color={state.health.status === 'healthy' ? 'teal' : 'yellow'}>
                {state.health.status}
              </Badge>
            </Group>
            <Group gap="xs">
              <Text size="sm" fw={500}>
                Database
              </Text>
              <Badge color={state.health.database === 'ok' ? 'teal' : 'red'} variant="light">
                {state.health.database}
              </Badge>
            </Group>
            <Text size="sm" c="dimmed">
              Version {state.health.version}
            </Text>
          </Stack>
        )}
      </Card>
    </Stack>
  );
}
