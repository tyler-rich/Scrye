import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Alert,
  Badge,
  Button,
  Card,
  Center,
  Group,
  Stack,
  Table,
  Text,
  Title,
} from '@mantine/core';
import { IconAlertCircle, IconArrowLeft } from '@tabler/icons-react';

import { ApiError } from '../api/client';
import { getScanDiff, SEVERITY_ORDER, type DiffFinding, type ScanDiff } from '../api/scans';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusLoader } from '../components/StatusLoader';

function DiffTable({
  title,
  findings,
  empty,
}: {
  title: string;
  findings: DiffFinding[];
  empty: string;
}) {
  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="sm">
        <Title order={4}>
          {title} ({findings.length})
        </Title>
        {findings.length === 0 ? (
          <Text c="dimmed" size="sm">
            {empty}
          </Text>
        ) : (
          <Table.ScrollContainer minWidth={640}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Severity</Table.Th>
                  <Table.Th>ID</Table.Th>
                  <Table.Th>Package</Table.Th>
                  <Table.Th>Installed</Table.Th>
                  <Table.Th>Fixed</Table.Th>
                  <Table.Th>Title</Table.Th>
                  <Table.Th>Location</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {findings.map((f, i) => (
                  <Table.Tr key={`${f.vuln_id ?? f.title ?? 'f'}-${f.location ?? ''}-${i}`}>
                    <Table.Td>
                      <SeverityBadge severity={f.severity} />
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{f.vuln_id ?? '—'}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{f.pkg_name ?? '—'}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{f.installed_version ?? '—'}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c={f.fixed_version ? 'teal' : 'dimmed'}>
                        {f.fixed_version ?? '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" lineClamp={2} maw={320}>
                        {f.title ?? '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" lineClamp={2} maw={280}>
                        {f.location ?? '—'}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Stack>
    </Card>
  );
}

/** Compare two scans of the same target: new vs. fixed findings (docs/ARCHIVE.md §4.4). */
export function ScanDiffPage() {
  const { baseId, compareId } = useParams();
  const navigate = useNavigate();
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const base = Number(baseId);
    const compare = Number(compareId);
    getScanDiff(base, compare)
      .then(setDiff)
      .catch((err: unknown) =>
        setError(err instanceof ApiError ? err.message : 'Failed to load diff.'),
      );
  }, [baseId, compareId]);

  if (error) {
    return (
      <Stack gap="md">
        <Button
          variant="subtle"
          size="compact-sm"
          leftSection={<IconArrowLeft size={14} />}
          onClick={() => void navigate('/scans')}
        >
          Back to history
        </Button>
        <Alert color="red" icon={<IconAlertCircle size={16} />} title="Cannot diff these scans">
          {error}
        </Alert>
      </Stack>
    );
  }

  if (!diff) {
    return (
      <Center mih={200}>
        <StatusLoader color="teal" label="Loading diff" />
      </Center>
    );
  }

  return (
    <Stack gap="lg">
      <div>
        <Button
          variant="subtle"
          size="compact-sm"
          leftSection={<IconArrowLeft size={14} />}
          onClick={() => void navigate('/scans')}
          mb="xs"
        >
          Back to history
        </Button>
        <Group gap="sm">
          <Title order={2}>Scan diff</Title>
          <Badge variant="light" color="teal">
            {diff.scanner}
          </Badge>
        </Group>
        <Text c="dimmed" mt={4} style={{ wordBreak: 'break-all' }}>
          {diff.target}
        </Text>
      </div>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Group gap="xl">
            <Text size="sm">
              <Text span c="dimmed">
                Base scan:{' '}
              </Text>
              #{diff.base_scan_id}
            </Text>
            <Text size="sm">
              <Text span c="dimmed">
                Compared scan:{' '}
              </Text>
              #{diff.compare_scan_id}
            </Text>
            <Text size="sm" c="red">
              +{diff.added_count} new
            </Text>
            <Text size="sm" c="teal">
              −{diff.removed_count} fixed
            </Text>
            <Text size="sm" c="dimmed">
              {diff.unchanged_count} unchanged
            </Text>
          </Group>
          <Group gap="xs">
            {SEVERITY_ORDER.map((sev) => {
              const delta = diff.severity_delta[sev];
              if (!delta) return null;
              return (
                <Badge key={sev} variant="light" color={delta > 0 ? 'red' : 'teal'}>
                  {sev}: {delta > 0 ? `+${delta}` : delta}
                </Badge>
              );
            })}
          </Group>
        </Stack>
      </Card>

      <DiffTable
        title="New findings"
        findings={diff.added}
        empty="No new findings in the compared scan."
      />
      <DiffTable
        title="Fixed findings"
        findings={diff.removed}
        empty="No findings were fixed since the base scan."
      />
    </Stack>
  );
}
