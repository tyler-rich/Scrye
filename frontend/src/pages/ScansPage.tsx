import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ActionIcon,
  Badge,
  Button,
  Center,
  Group,
  Loader,
  Stack,
  Table,
  Text,
  Title,
  Tooltip,
} from '@mantine/core';
import { IconPlus, IconRefresh } from '@tabler/icons-react';

import { isActive, listScans, type Scan } from '../api/scans';
import { ScanStatusBadge } from '../components/ScanStatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';

function formatWhen(iso: string): string {
  return new Date(`${iso}Z`).toLocaleString();
}

/** Recent-scans table. Full filtering and history arrive in Phase 4. */
export function ScansPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      const rows = await listScans();
      setScans(rows);
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load scans.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Auto-refresh while any scan is still active.
  useEffect(() => {
    const hasActive = scans?.some((s) => isActive(s.status)) ?? false;
    if (!hasActive) return;
    timer.current = window.setInterval(() => void load(), 3000);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [scans, load]);

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={2}>Scans</Title>
        <Group gap="xs">
          <Tooltip label="Refresh">
            <ActionIcon variant="default" onClick={() => void load()} aria-label="Refresh scans">
              <IconRefresh size={16} />
            </ActionIcon>
          </Tooltip>
          <Button leftSection={<IconPlus size={16} />} onClick={() => navigate('/scans/new')}>
            New scan
          </Button>
        </Group>
      </Group>

      {error && <Text c="red">{error}</Text>}

      {scans === null ? (
        <Center mih={160}>
          <Loader color="teal" />
        </Center>
      ) : scans.length === 0 ? (
        <Text c="dimmed">No scans yet. Launch one to get started.</Text>
      ) : (
        <Table.ScrollContainer minWidth={720}>
          <Table highlightOnHover striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Scanner</Table.Th>
                <Table.Th>Target</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Highest</Table.Th>
                <Table.Th>Findings</Table.Th>
                <Table.Th>Started by</Table.Th>
                <Table.Th>Created</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {scans.map((scan) => (
                <Table.Tr
                  key={scan.id}
                  style={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/scans/${scan.id}`)}
                >
                  <Table.Td>
                    <Badge variant="light" color="teal">
                      {scan.scanner}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" style={{ wordBreak: 'break-all' }}>
                      {scan.target}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <ScanStatusBadge status={scan.status} />
                  </Table.Td>
                  <Table.Td>
                    {scan.highest_severity ? (
                      <SeverityBadge severity={scan.highest_severity} />
                    ) : (
                      <Text size="sm" c="dimmed">
                        —
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>{scan.findings_count}</Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {scan.created_by_username ?? '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {formatWhen(scan.created_at)}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Stack>
  );
}
