import { useCallback, useEffect, useRef, useState } from 'react';
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
  Menu,
  Modal,
  Select,
  Stack,
  Table,
  TagsInput,
  Text,
  Title,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { IconAlertCircle, IconArrowLeft, IconDownload, IconTrash } from '@tabler/icons-react';

import { ApiError } from '../api/client';
import { sameItems } from '../lib/arrays';
import { formatWhen } from '../lib/dates';
import { MAX_POLL_FAILURES, POLL_BASE_MS, pollBackoffMs } from '../lib/polling';
import { safeHttpUrl } from '../lib/url';
import {
  artifactDownloadUrl,
  cancelScan,
  deleteScan,
  getScan,
  isActive,
  listArtifacts,
  listFindings,
  scanExportUrl,
  setScanTags,
  SEVERITY_ORDER,
  type Artifact,
  type ExportFormat,
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
const EXPORT_FORMATS: { value: ExportFormat; label: string }[] = [
  { value: 'csv', label: 'CSV' },
  { value: 'markdown', label: 'Markdown' },
  { value: 'json', label: 'JSON' },
];

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
  const [tagDraft, setTagDraft] = useState<string[]>([]);
  // The server tags we last synced into the draft. The status poll refreshes
  // the scan every few seconds; syncing the draft only when it still matches
  // this keeps a poll from wiping an operator's in-progress edit (L16 / P2-1).
  const lastSyncedTags = useRef<string[]>([]);
  const [savingTags, setSavingTags] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Non-null once the status poller gives up: 'gone' = the scan 404s (deleted),
  // 'error' = repeated fetch failures. Halts the poll and surfaces the state
  // instead of hammering a failing endpoint behind a stale badge (M20 / P1-3).
  const [pollHalt, setPollHalt] = useState<'error' | 'gone' | null>(null);
  const [confirmOpened, { open: openConfirm, close: closeConfirm }] = useDisclosure(false);
  const [deleting, setDeleting] = useState(false);

  const loadScan = useCallback(async (): Promise<'ok' | 'error' | 'gone'> => {
    try {
      const s = await getScan(id);
      setScan(s);
      // Adopt the server's tags only if the operator hasn't edited the draft
      // away from what we last synced — don't clobber an in-progress edit.
      const prevSynced = lastSyncedTags.current;
      lastSyncedTags.current = s.tags;
      setTagDraft((draft) => (sameItems(draft, prevSynced) ? s.tags : draft));
      setError(null);
      setPollHalt(null);
      return 'ok';
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 404) {
        setError('This scan no longer exists — it may have been deleted.');
        return 'gone';
      }
      setError(err instanceof ApiError ? err.message : 'Failed to load scan.');
      return 'error';
    }
  }, [id]);

  const saveTags = async () => {
    setSavingTags(true);
    try {
      const updated = await setScanTags(id, tagDraft);
      setScan(updated);
      lastSyncedTags.current = updated.tags;
      setTagDraft(updated.tags);
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Failed to update tags.');
    } finally {
      setSavingTags(false);
    }
  };

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

  // Poll while the scan is active. Back off exponentially on fetch errors and
  // halt after a ceiling (or immediately on a 404) so a restarted backend,
  // expired session, or deleted scan doesn't get hammered every 2.5s forever
  // behind a stale "running" badge (M20 / P1-3).
  useEffect(() => {
    if (!scan || !isActive(scan.status) || pollHalt) return;
    let cancelled = false;
    let failures = 0;
    let timer: number;
    const tick = async () => {
      const result = await loadScan();
      if (cancelled) return;
      if (result === 'gone') {
        setPollHalt('gone');
        return;
      }
      if (result === 'error') {
        failures += 1;
        if (failures >= MAX_POLL_FAILURES) {
          setPollHalt('error');
          return;
        }
      } else {
        // A successful poll changes `scan`, restarting this effect fresh.
        failures = 0;
      }
      timer = window.setTimeout(() => void tick(), pollBackoffMs(failures));
    };
    timer = window.setTimeout(() => void tick(), POLL_BASE_MS);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [scan, loadScan, pollHalt]);

  const retryPoll = () => {
    setPollHalt(null);
    setError(null);
    void loadScan();
  };

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

  const remove = async () => {
    setDeleting(true);
    try {
      await deleteScan(id);
      navigate('/scans');
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete scan.');
      setDeleting(false);
      closeConfirm();
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
          <Group gap="xs">
            {scan.status === 'succeeded' && (
              <Menu position="bottom-end" withinPortal>
                <Menu.Target>
                  <Button variant="default" leftSection={<IconDownload size={16} />}>
                    Export
                  </Button>
                </Menu.Target>
                <Menu.Dropdown>
                  <Menu.Label>Export findings</Menu.Label>
                  {EXPORT_FORMATS.map((fmt) => (
                    <Menu.Item key={fmt.value} component="a" href={scanExportUrl(id, fmt.value)}>
                      {fmt.label}
                    </Menu.Item>
                  ))}
                </Menu.Dropdown>
              </Menu>
            )}
            {scan.status === 'queued' && canOperate && (
              <Button variant="light" color="red" onClick={() => void cancel()}>
                Cancel
              </Button>
            )}
            {canOperate && !isActive(scan.status) && (
              <Button
                variant="light"
                color="red"
                leftSection={<IconTrash size={16} />}
                onClick={openConfirm}
              >
                Delete
              </Button>
            )}
          </Group>
        </Group>
      </div>

      <Modal opened={confirmOpened} onClose={closeConfirm} title="Delete scan" centered>
        <Stack gap="md">
          <Text size="sm">
            Permanently delete <strong>scan #{scan.id}</strong> ({scan.scanner} — {scan.target})?
            This removes the scan and all of its findings, stored artifacts, and tags. It cannot be
            undone, and the scan will no longer appear in history or dashboard totals.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={closeConfirm} disabled={deleting}>
              Cancel
            </Button>
            <Button color="red" loading={deleting} onClick={() => void remove()}>
              Delete scan
            </Button>
          </Group>
        </Stack>
      </Modal>

      {error && <Text c="red">{error}</Text>}

      {pollHalt === 'error' && isActive(scan.status) && (
        <Alert
          color="orange"
          icon={<IconAlertCircle size={16} />}
          title="Auto-refresh paused"
          variant="light"
        >
          <Group justify="space-between" align="center">
            <Text size="sm">
              Couldn&apos;t reach the server to refresh this scan&apos;s status.
            </Text>
            <Button size="xs" variant="light" onClick={retryPoll}>
              Retry
            </Button>
          </Group>
        </Alert>
      )}

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

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Title order={4}>Tags</Title>
          {canOperate ? (
            <Group align="flex-end" gap="sm">
              <TagsInput
                flex={1}
                placeholder="Add a tag and press Enter"
                value={tagDraft}
                onChange={setTagDraft}
                clearable
              />
              <Button variant="light" onClick={() => void saveTags()} loading={savingTags}>
                Save tags
              </Button>
            </Group>
          ) : scan.tags.length > 0 ? (
            <Group gap={4}>
              {scan.tags.map((tag) => (
                <Badge key={tag} variant="outline" color="gray">
                  {tag}
                </Badge>
              ))}
            </Group>
          ) : (
            <Text size="sm" c="dimmed">
              No tags.
            </Text>
          )}
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
                      {findings.map((f) => {
                        // primary_url is scanner-derived (attacker-influenceable);
                        // only render it as a link when it's a safe http(s) URL.
                        const findingUrl = safeHttpUrl(f.primary_url);
                        return (
                          <Table.Tr key={f.id}>
                            <Table.Td>
                              <SeverityBadge severity={f.severity} />
                            </Table.Td>
                            <Table.Td>
                              {findingUrl && f.vuln_id ? (
                                <Anchor
                                  href={findingUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  size="sm"
                                >
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
                        );
                      })}
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
