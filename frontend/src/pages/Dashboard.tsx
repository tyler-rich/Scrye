import { useEffect, useState } from 'react';
import {
  Alert,
  Anchor,
  Badge,
  Card,
  Group,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Title,
  Tooltip,
} from '@mantine/core';
import { IconAlertTriangle } from '@tabler/icons-react';
import { Link } from 'react-router-dom';

import { ApiError } from '../api/client';
import { getDashboard, type Dashboard as DashboardData } from '../api/dashboard';
import { ScanStatusBadge } from '../components/ScanStatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ok'; data: DashboardData }
  | { kind: 'error'; message: string };

/** A single headline metric tile. */
function StatCard({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <Card withBorder radius="md" padding="lg">
      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
        {label}
      </Text>
      <Text size="2rem" fw={700} c={color}>
        {value}
      </Text>
    </Card>
  );
}

/** A compact, accessible bar strip of daily scan counts (last 30 days). */
function ScansOverTime({ data }: { data: DashboardData['scans_over_time'] }) {
  const max = Math.max(1, ...data.map((p) => p.count));
  return (
    <Card withBorder radius="md" padding="lg">
      <Title order={4} mb="md">
        Scans over time (30 days)
      </Title>
      <Group gap={3} align="flex-end" h={80} wrap="nowrap">
        {data.map((point) => (
          <Tooltip key={point.date} label={`${point.date}: ${point.count}`} withArrow>
            <div
              style={{
                flex: 1,
                minWidth: 2,
                height: `${Math.round((point.count / max) * 100)}%`,
                minHeight: 2,
                borderRadius: 2,
                background: 'var(--mantine-color-teal-6)',
                opacity: point.count === 0 ? 0.15 : 1,
              }}
              aria-label={`${point.date}: ${point.count} scans`}
            />
          </Tooltip>
        ))}
      </Group>
    </Card>
  );
}

/** Scanner vulnerability-DB freshness cards. */
function ScannerDbCard({ data }: { data: DashboardData['scanner_db'] }) {
  return (
    <Card withBorder radius="md" padding="lg">
      <Title order={4} mb="md">
        Scanner DB freshness
      </Title>
      <Stack gap="sm">
        {data.map((info) => (
          <Group key={info.name} justify="space-between">
            <Group gap="xs">
              <Text fw={500} tt="capitalize">
                {info.name}
              </Text>
              <Badge color={info.available ? 'teal' : 'gray'} variant="light">
                {info.available ? 'ready' : 'unknown'}
              </Badge>
            </Group>
            <Text size="sm" c="dimmed">
              {info.updated_at ? `updated ${info.updated_at}` : (info.detail ?? 'no data')}
            </Text>
          </Group>
        ))}
      </Stack>
    </Card>
  );
}

/** Aggregate dashboard (docs/ARCHIVE.md §4.6). */
export function Dashboard() {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    getDashboard()
      .then((data) => {
        if (!cancelled) setState({ kind: 'ok', data });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            kind: 'error',
            message: err instanceof ApiError ? err.message : 'Failed to load dashboard.',
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
        <Title order={2}>Dashboard</Title>
        <Text c="dimmed">Your scanning posture at a glance.</Text>
      </div>

      {state.kind === 'loading' && <Text c="dimmed">Loading…</Text>}
      {state.kind === 'error' && (
        <Alert color="red" variant="light">
          {state.message}
        </Alert>
      )}

      {state.kind === 'ok' && (
        <Stack gap="md">
          <SimpleGrid cols={{ base: 2, sm: 4 }}>
            <StatCard label="Total scans" value={state.data.total_scans} />
            <StatCard label="Open critical" value={state.data.open_critical} color="red" />
            <StatCard label="Open high" value={state.data.open_high} color="orange" />
            <StatCard label="Active schedules" value={state.data.schedules_enabled} />
          </SimpleGrid>

          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <ScansOverTime data={state.data.scans_over_time} />
            <ScannerDbCard data={state.data.scanner_db} />
          </SimpleGrid>

          {state.data.failed_alerts.length > 0 && (
            <Alert
              color="red"
              variant="light"
              icon={<IconAlertTriangle size={16} />}
              title={`${state.data.failed_alerts.length} recent failed scan(s)`}
            >
              <Stack gap={4}>
                {state.data.failed_alerts.slice(0, 5).map((a) => (
                  <Text key={a.id} size="sm">
                    <Anchor component={Link} to={`/scans/${a.id}`}>
                      #{a.id}
                    </Anchor>{' '}
                    {a.target} — {a.error ?? 'unknown error'}
                  </Text>
                ))}
              </Stack>
            </Alert>
          )}

          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <Card withBorder radius="md" padding="lg">
              <Title order={4} mb="md">
                Top vulnerable targets
              </Title>
              <Table verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Target</Table.Th>
                    <Table.Th>Critical</Table.Th>
                    <Table.Th>High</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {state.data.top_vulnerable_targets.map((t) => (
                    <Table.Tr key={`${t.scanner}:${t.target_type}:${t.target}`}>
                      <Table.Td>
                        <Text size="sm" style={{ wordBreak: 'break-all' }}>
                          {t.target}
                        </Text>
                        <Text size="xs" c="dimmed">
                          {t.scanner} · {t.target_type}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text c="red" fw={600}>
                          {t.critical}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text c="orange" fw={600}>
                          {t.high}
                        </Text>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                  {state.data.top_vulnerable_targets.length === 0 && (
                    <Table.Tr>
                      <Table.Td colSpan={3}>
                        <Text c="dimmed" ta="center" py="sm">
                          No open critical/high findings.
                        </Text>
                      </Table.Td>
                    </Table.Tr>
                  )}
                </Table.Tbody>
              </Table>
            </Card>

            <Card withBorder radius="md" padding="lg">
              <Title order={4} mb="md">
                Recent scans
              </Title>
              <Table verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Target</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>Highest</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {state.data.recent_scans.map((s) => (
                    <Table.Tr key={s.id}>
                      <Table.Td>
                        <Anchor component={Link} to={`/scans/${s.id}`} size="sm">
                          {s.target}
                        </Anchor>
                        <Text size="xs" c="dimmed">
                          {s.scanner}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <ScanStatusBadge status={s.status} />
                      </Table.Td>
                      <Table.Td>
                        {s.highest_severity ? (
                          <SeverityBadge severity={s.highest_severity} />
                        ) : (
                          <Text size="sm" c="dimmed">
                            —
                          </Text>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                  {state.data.recent_scans.length === 0 && (
                    <Table.Tr>
                      <Table.Td colSpan={3}>
                        <Text c="dimmed" ta="center" py="sm">
                          No scans yet.{' '}
                          <Anchor component={Link} to="/scans/new">
                            Run one.
                          </Anchor>
                        </Text>
                      </Table.Td>
                    </Table.Tr>
                  )}
                </Table.Tbody>
              </Table>
            </Card>
          </SimpleGrid>
        </Stack>
      )}
    </Stack>
  );
}
