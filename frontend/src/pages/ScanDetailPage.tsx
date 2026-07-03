import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Center,
  Group,
  Loader,
  Select,
  Stack,
  Table,
  Text,
  Title,
} from '@mantine/core';
import { IconAlertCircle, IconArrowLeft, IconDownload } from '@tabler/icons-react';

import { ApiError } from '../api/client';
import {
  artifactDownloadUrl,
  cancelScan,
  getScan,
  isActive,
  listArtifacts,
  listFindings,
  SEVERITY_ORDER,
  type Artifact,
  type Finding,
  type FindingClass,
  type Scan,
  type Severity,
} from '../api/scans';
import { ScanStatusBadge } from '../components/ScanStatusBadge';
import { SEVERITY_COLOR, SeverityBadge } from '../components/SeverityBadge';
import { useAuth } from '../auth/AuthContext';

const FINDINGS_LIMIT = 500;
const FINDING_CLASSES: FindingClass[] = ['vulnerability', 'misconfiguration', 'secret', 'license'];

function formatWhen(iso: string | null): string {
  return iso ? new Date(`${iso}Z`).toLocaleString() : '—';
}

function SeveritySummary({ counts }: { counts: Record<string, number> }) {
  const shown = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0);
  if (shown.length === 0) {
    return (
      <Text size="sm" c="dimmed">
        No findings.
      </Text>
    );
  }
  return (
    <Group gap="xs">
      {shown.map((s) => (
        <Badge key={s} color={SEVERITY_COLOR[s]} variant="light" radius="sm">
          {s}: {counts[s]}
        </Badge>
      ))}
    </Group>
  );
}

/** Detail view for a single scan: status, summary, artifacts, findings. */
export function ScanDetailPage() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const navigate = useNavigate();
  const { user } = useAuth();
  const canOperate = user?.role === 'operator' || user?.role === 'admin';

  const [scan, setScan] = useState<Scan | null>(null);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  const [classFilter, setClassFilter] = useState<FindingClass | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadScan = useCallback(async () => {
    try {
      const s = await getScan(id);
      setScan(s);
      setError(null);
      return s;
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Failed to load scan.');
      return null;
    }
  }, [id]);

  const loadFindings = useCallback(async () => {
    try {
      const page = await listFindings(id, {
        severity: severityFilter ?? undefined,
        finding_class: classFilter ?? undefined,
        limit: FINDINGS_LIMIT,
      });
      setFindings(page.items);
      setFindingsTotal(page.total);
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Failed to load findings.');
    }
  }, [id, severityFilter, classFilter]);

  useEffect(() => {
    void loadScan();
  }, [loadScan]);

  // Poll while the scan is active; stop once it reaches a terminal state.
  useEffect(() => {
    if (!scan || !isActive(scan.status)) return;
    const interval = window.setInterval(() => void loadScan(), 2500);
    return () => window.clearInterval(interval);
  }, [scan, loadScan]);

  // Load artifacts once the scan has succeeded (surfacing any fetch error).
  useEffect(() => {
    if (scan?.status !== 'succeeded') return;
    listArtifacts(id)
      .then(setArtifacts)
      .catch((err: unknown) =>
        setError(err instanceof ApiError ? err.message : 'Failed to load artifacts.'),
      );
  }, [scan?.status, id]);

  // Load findings once succeeded, and whenever the filters change.
  useEffect(() => {
    if (scan?.status !== 'succeeded') return;
    void loadFindings();
  }, [scan?.status, loadFindings]);

  const cancel = async () => {
    try {
      await cancelScan(id);
      await loadScan();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Failed to cancel scan.');
    }
  };

  if (!scan) {
    return (
      <Center mih={200}>{error ? <Text c="red">{error}</Text> : <Loader color="teal" />}</Center>
    );
  }

  return (
    <Stack gap="lg">
      <div>
        <Button
          variant="subtle"
          size="compact-sm"
          leftSection={<IconArrowLeft size={14} />}
          onClick={() => navigate('/scans')}
          mb="xs"
        >
          Back to scans
        </Button>
        <Group justify="space-between" align="flex-start">
          <div>
            <Group gap="sm">
              <Title order={2}>Scan #{scan.id}</Title>
              <ScanStatusBadge status={scan.status} />
              <Badge variant="light" color="teal">
                {scan.scanner}
              </Badge>
            </Group>
            <Text c="dimmed" mt={4} style={{ wordBreak: 'break-all' }}>
              {scan.target}
            </Text>
          </div>
          {scan.status === 'queued' && canOperate && (
            <Button variant="light" color="red" onClick={() => void cancel()}>
              Cancel
            </Button>
          )}
        </Group>
      </div>

      {error && <Text c="red">{error}</Text>}

      {scan.status === 'failed' && scan.error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} title="Scan failed">
          {scan.error}
        </Alert>
      )}

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Title order={4}>Summary</Title>
          <SeveritySummary counts={scan.severity_counts} />
          <Group gap="xl">
            <Text size="sm">
              <Text span c="dimmed">
                Findings:{' '}
              </Text>
              {scan.findings_count}
            </Text>
            <Text size="sm">
              <Text span c="dimmed">
                Started:{' '}
              </Text>
              {formatWhen(scan.started_at)}
            </Text>
            <Text size="sm">
              <Text span c="dimmed">
                Finished:{' '}
              </Text>
              {formatWhen(scan.finished_at)}
            </Text>
            <Text size="sm">
              <Text span c="dimmed">
                By:{' '}
              </Text>
              {scan.created_by_username ?? '—'}
            </Text>
            {scan.scanner_version && (
              <Text size="sm">
                <Text span c="dimmed">
                  Version:{' '}
                </Text>
                {scan.scanner_version}
              </Text>
            )}
          </Group>
        </Stack>
      </Card>

      {artifacts.length > 0 && (
        <Card withBorder radius="md" padding="lg">
          <Stack gap="sm">
            <Title order={4}>Raw artifacts</Title>
            <Text size="sm" c="dimmed">
              The scanner&apos;s original JSON output, stored as the source of truth.
            </Text>
            <Group gap="sm">
              {artifacts.map((a) => (
                <Button
                  key={a.id}
                  component="a"
                  href={artifactDownloadUrl(id, a.id)}
                  variant="default"
                  size="sm"
                  leftSection={<IconDownload size={14} />}
                >
                  {a.filename} ({(a.size_bytes / 1024).toFixed(1)} KB)
                </Button>
              ))}
            </Group>
          </Stack>
        </Card>
      )}

      {scan.status === 'succeeded' && (
        <Card withBorder radius="md" padding="lg">
          <Stack gap="sm">
            <Group justify="space-between">
              <Title order={4}>Findings</Title>
              <Group gap="sm">
                <Select
                  placeholder="All severities"
                  clearable
                  size="xs"
                  data={SEVERITY_ORDER.map((s) => ({ value: s, label: s }))}
                  value={severityFilter}
                  onChange={(v) => setSeverityFilter(v as Severity | null)}
                />
                <Select
                  placeholder="All classes"
                  clearable
                  size="xs"
                  data={FINDING_CLASSES.map((c) => ({ value: c, label: c }))}
                  value={classFilter}
                  onChange={(v) => setClassFilter(v as FindingClass | null)}
                />
              </Group>
            </Group>

            {findings.length === 0 ? (
              <Text c="dimmed" size="sm">
                No findings match the current filters.
              </Text>
            ) : (
              <>
                <Table.ScrollContainer minWidth={820}>
                  <Table striped highlightOnHover>
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Severity</Table.Th>
                        <Table.Th>ID</Table.Th>
                        <Table.Th>Class</Table.Th>
                        <Table.Th>Package</Table.Th>
                        <Table.Th>Installed</Table.Th>
                        <Table.Th>Fixed</Table.Th>
                        <Table.Th>Title</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {findings.map((f) => (
                        <Table.Tr key={f.id}>
                          <Table.Td>
                            <SeverityBadge severity={f.severity} />
                          </Table.Td>
                          <Table.Td>
                            {f.primary_url && f.vuln_id ? (
                              <Anchor href={f.primary_url} target="_blank" size="sm">
                                {f.vuln_id}
                              </Anchor>
                            ) : (
                              <Text size="sm">{f.vuln_id ?? '—'}</Text>
                            )}
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm" c="dimmed">
                              {f.finding_class}
                            </Text>
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
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
                {findingsTotal > findings.length && (
                  <Text size="xs" c="dimmed">
                    Showing the first {findings.length} of {findingsTotal} matching findings.
                    Download the raw artifact for the complete set.
                  </Text>
                )}
              </>
            )}
          </Stack>
        </Card>
      )}
    </Stack>
  );
}
