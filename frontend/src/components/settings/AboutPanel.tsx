import { useEffect, useState } from 'react';
import { Alert, Badge, Card, Group, SimpleGrid, Stack, Table, Text, Title } from '@mantine/core';
import { IconAlertCircle } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import { getAbout, type AboutInfo } from '../../api/settings';

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <Card withBorder padding="sm" radius="md">
      <Text size="xs" c="dimmed" tt="uppercase">
        {label}
      </Text>
      <Text fw={600} size="lg">
        {value}
      </Text>
    </Card>
  );
}

/** About & health: app/scanner versions and basic instance facts. */
export function AboutPanel() {
  const [about, setAbout] = useState<AboutInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void getAbout()
      .then(setAbout)
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load.'));
  }, []);

  if (error) {
    return (
      <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
        {error}
      </Alert>
    );
  }
  if (!about) return <Text c="dimmed">Loading…</Text>;

  return (
    <Stack gap="lg">
      <SimpleGrid cols={{ base: 2, sm: 4 }}>
        <Stat label="Version" value={about.version} />
        <Stat label="Status" value={about.status === 'healthy' ? 'Healthy' : about.status} />
        <Stat label="Users" value={about.user_count} />
        <Stat label="Scans" value={about.scan_count} />
      </SimpleGrid>

      <div>
        <Title order={5} mb="xs">
          Scanners
        </Title>
        <Table withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Scanner</Table.Th>
              <Table.Th>Version</Table.Th>
              <Table.Th>Status</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {about.scanners.map((s) => (
              <Table.Tr key={s.name}>
                <Table.Td tt="capitalize">{s.name}</Table.Td>
                <Table.Td>{s.version ?? '—'}</Table.Td>
                <Table.Td>
                  <Badge color={s.available ? 'teal' : 'red'} variant="light">
                    {s.available ? 'available' : 'unavailable'}
                  </Badge>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </div>

      <Group gap="xl">
        <Text size="sm" c="dimmed">
          Database: {about.database}
        </Text>
        <Text size="sm" c="dimmed">
          Python {about.python_version}
        </Text>
        <Text size="sm" c="dimmed">
          {about.platform}
        </Text>
        <Text size="sm" c="dimmed">
          OIDC {about.oidc_enabled ? 'enabled' : 'disabled'}
        </Text>
      </Group>
    </Stack>
  );
}
