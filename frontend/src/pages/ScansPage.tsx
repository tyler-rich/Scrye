import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ActionIcon,
  Badge,
  Button,
  Card,
  Center,
  Checkbox,
  Group,
  Loader,
  Menu,
  MultiSelect,
  Pagination,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from '@mantine/core';
import {
  IconArrowsDiff,
  IconChevronDown,
  IconChevronUp,
  IconDownload,
  IconPlus,
  IconRefresh,
  IconX,
} from '@tabler/icons-react';

import {
  getFilterOptions,
  historyExportUrl,
  listHistory,
  SEVERITY_ORDER,
  type ExportFormat,
  type FilterOptions,
  type HistoryFilters,
  type HistorySort,
  type Scan,
  type ScanStatus,
  type Severity,
  type SortOrder,
  type TargetType,
} from '../api/scans';
import { createPreset, deletePreset, listPresets, type FilterPreset } from '../api/presets';
import { formatWhen } from '../lib/dates';
import { ScanStatusBadge } from '../components/ScanStatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';

const PAGE_SIZE = 25;
const SCANNERS = ['trivy', 'grype'];
const TARGET_TYPES: TargetType[] = ['image', 'repository', 'filesystem', 'sbom'];
const STATUSES: ScanStatus[] = ['queued', 'running', 'succeeded', 'failed', 'canceled'];
const EXPORT_FORMATS: { value: ExportFormat; label: string }[] = [
  { value: 'csv', label: 'CSV' },
  { value: 'markdown', label: 'Markdown' },
  { value: 'json', label: 'JSON' },
];

/** Build the effective filter object, folding the two date pickers into it. */
function withDates(base: HistoryFilters, from: string, to: string): HistoryFilters {
  return {
    ...base,
    created_from: from ? `${from}T00:00:00` : null,
    created_to: to ? `${to}T23:59:59` : null,
  };
}

const EMPTY_FILTERS: HistoryFilters = {};

/** Full scan-history view: filters, presets, sortable/paginated table, exports. */
export function ScansPage() {
  const navigate = useNavigate();

  const [filters, setFilters] = useState<HistoryFilters>(EMPTY_FILTERS);
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [sort, setSort] = useState<HistorySort>('created_at');
  const [order, setOrder] = useState<SortOrder>('desc');
  const [page, setPage] = useState(1);

  const [data, setData] = useState<{ total: number; items: Scan[] } | null>(null);
  const [options, setOptions] = useState<FilterOptions>({ initiators: [], tags: [] });
  const [presets, setPresets] = useState<FilterPreset[]>([]);
  const [presetName, setPresetName] = useState('');
  const [selectedPreset, setSelectedPreset] = useState<string | null>(null);
  const [compare, setCompare] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);

  const effectiveFilters = useMemo(
    () => withDates(filters, dateFrom, dateTo),
    [filters, dateFrom, dateTo],
  );

  const load = useCallback(async () => {
    try {
      const result = await listHistory({
        ...effectiveFilters,
        sort,
        order,
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      });
      setData(result);
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load history.');
    }
  }, [effectiveFilters, sort, order, page]);

  // Debounce reloads so typing in the search box doesn't fire a request per key.
  useEffect(() => {
    const handle = window.setTimeout(() => void load(), 250);
    return () => window.clearTimeout(handle);
  }, [load]);

  const refreshOptions = useCallback(async () => {
    try {
      const [opts, savedPresets] = await Promise.all([getFilterOptions(), listPresets()]);
      setOptions(opts);
      setPresets(savedPresets);
    } catch {
      // Non-fatal: filter option lists just stay empty.
    }
  }, []);

  useEffect(() => {
    void refreshOptions();
  }, [refreshOptions]);

  const patch = (change: Partial<HistoryFilters>) => {
    setFilters((prev) => ({ ...prev, ...change }));
    setSelectedPreset(null);
    setPage(1);
  };

  const clearFilters = () => {
    setFilters(EMPTY_FILTERS);
    setDateFrom('');
    setDateTo('');
    setSelectedPreset(null);
    setPage(1);
  };

  const toggleSort = (column: HistorySort) => {
    if (sort === column) {
      setOrder((o) => (o === 'asc' ? 'desc' : 'asc'));
    } else {
      setSort(column);
      setOrder('desc');
    }
    setPage(1);
  };

  const applyPreset = (id: string | null) => {
    setSelectedPreset(id);
    if (!id) return;
    const preset = presets.find((p) => String(p.id) === id);
    if (!preset) return;
    const { created_from, created_to, ...rest } = preset.filters;
    setFilters(rest);
    setDateFrom(created_from ? created_from.slice(0, 10) : '');
    setDateTo(created_to ? created_to.slice(0, 10) : '');
    setPage(1);
  };

  const savePreset = async () => {
    const name = presetName.trim();
    if (!name) return;
    try {
      await createPreset(name, effectiveFilters);
      setPresetName('');
      await refreshOptions();
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save preset.');
    }
  };

  const removePreset = async () => {
    if (!selectedPreset) return;
    try {
      await deletePreset(Number(selectedPreset));
      setSelectedPreset(null);
      await refreshOptions();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete preset.');
    }
  };

  const toggleCompare = (scan: Scan, checked: boolean) => {
    setCompare((prev) => {
      if (checked) return [...prev, scan].slice(-2);
      return prev.filter((s) => s.id !== scan.id);
    });
  };

  const canCompare =
    compare.length === 2 &&
    compare[0].scanner === compare[1].scanner &&
    compare[0].target === compare[1].target;

  const runCompare = () => {
    const [a, b] = [...compare].sort(
      (x, y) => new Date(x.created_at).getTime() - new Date(y.created_at).getTime(),
    );
    navigate(`/scans/diff/${a.id}/${b.id}`);
  };

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={2}>Scan history</Title>
        <Group gap="xs">
          <Tooltip label="Refresh">
            <ActionIcon variant="default" onClick={() => void load()} aria-label="Refresh">
              <IconRefresh size={16} />
            </ActionIcon>
          </Tooltip>
          <Menu position="bottom-end" withinPortal>
            <Menu.Target>
              <Button variant="default" leftSection={<IconDownload size={16} />}>
                Export
              </Button>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Label>Export filtered history</Menu.Label>
              {EXPORT_FORMATS.map((fmt) => (
                <Menu.Item
                  key={fmt.value}
                  component="a"
                  href={historyExportUrl(effectiveFilters, fmt.value)}
                >
                  {fmt.label}
                </Menu.Item>
              ))}
            </Menu.Dropdown>
          </Menu>
          <Button leftSection={<IconPlus size={16} />} onClick={() => navigate('/scans/new')}>
            New scan
          </Button>
        </Group>
      </Group>

      <Card withBorder radius="md" padding="md">
        <Stack gap="sm">
          <Group grow align="flex-end">
            <TextInput
              label="Target search"
              placeholder="Full-text on target"
              value={filters.q ?? ''}
              onChange={(e) => patch({ q: e.currentTarget.value || null })}
            />
            <Select
              label="Scanner"
              placeholder="Any"
              clearable
              data={SCANNERS}
              value={filters.scanner ?? null}
              onChange={(v) => patch({ scanner: (v as Scan['scanner']) ?? null })}
            />
            <Select
              label="Target type"
              placeholder="Any"
              clearable
              data={TARGET_TYPES}
              value={filters.target_type ?? null}
              onChange={(v) => patch({ target_type: (v as TargetType) ?? null })}
            />
            <Select
              label="Status"
              placeholder="Any"
              clearable
              data={STATUSES}
              value={filters.status ?? null}
              onChange={(v) => patch({ status: (v as ScanStatus) ?? null })}
            />
          </Group>

          <Group grow align="flex-end">
            <Select
              label="Highest severity"
              placeholder="Any"
              clearable
              data={SEVERITY_ORDER}
              value={filters.highest_severity ?? null}
              onChange={(v) => patch({ highest_severity: (v as Severity) ?? null })}
            />
            <Select
              label="At or above severity"
              placeholder="Any"
              clearable
              data={SEVERITY_ORDER}
              value={filters.min_severity ?? null}
              onChange={(v) => patch({ min_severity: (v as Severity) ?? null })}
            />
            <Select
              label="Initiator"
              placeholder="Anyone"
              clearable
              searchable
              data={options.initiators}
              value={filters.initiator ?? null}
              onChange={(v) => patch({ initiator: v ?? null })}
            />
            <MultiSelect
              label="Tags"
              placeholder="Any"
              clearable
              searchable
              data={options.tags}
              value={filters.tags ?? []}
              onChange={(v) => patch({ tags: v })}
            />
          </Group>

          <Group grow align="flex-end">
            <TextInput
              label="Created from"
              type="date"
              value={dateFrom}
              onChange={(e) => {
                setDateFrom(e.currentTarget.value);
                setSelectedPreset(null);
                setPage(1);
              }}
            />
            <TextInput
              label="Created to"
              type="date"
              value={dateTo}
              onChange={(e) => {
                setDateTo(e.currentTarget.value);
                setSelectedPreset(null);
                setPage(1);
              }}
            />
            <Button variant="light" color="gray" onClick={clearFilters} mt="auto">
              Clear filters
            </Button>
          </Group>

          <Group justify="space-between" align="flex-end">
            <Group gap="xs" align="flex-end">
              <Select
                label="Saved presets"
                placeholder="Load a preset"
                clearable
                w={200}
                data={presets.map((p) => ({ value: String(p.id), label: p.name }))}
                value={selectedPreset}
                onChange={applyPreset}
              />
              {selectedPreset && (
                <Button variant="subtle" color="red" onClick={() => void removePreset()}>
                  Delete preset
                </Button>
              )}
            </Group>
            <Group gap="xs" align="flex-end">
              <TextInput
                label="Save current filters as"
                placeholder="Preset name"
                value={presetName}
                onChange={(e) => setPresetName(e.currentTarget.value)}
                w={220}
              />
              <Button
                variant="light"
                onClick={() => void savePreset()}
                disabled={!presetName.trim()}
              >
                Save preset
              </Button>
            </Group>
          </Group>
        </Stack>
      </Card>

      {compare.length > 0 && (
        <Card withBorder radius="md" padding="sm">
          <Group justify="space-between">
            <Group gap="xs">
              <Text size="sm">
                Comparing {compare.length}/2 selected
                {compare.length === 2 && !canCompare && (
                  <Text span c="red" size="sm">
                    {' '}
                    — must be the same scanner and target
                  </Text>
                )}
              </Text>
              <ActionIcon variant="subtle" onClick={() => setCompare([])} aria-label="Clear">
                <IconX size={14} />
              </ActionIcon>
            </Group>
            <Button
              size="xs"
              leftSection={<IconArrowsDiff size={14} />}
              disabled={!canCompare}
              onClick={runCompare}
            >
              Compare scans
            </Button>
          </Group>
        </Card>
      )}

      {error && <Text c="red">{error}</Text>}

      {data === null ? (
        <Center mih={160}>
          <Loader color="teal" />
        </Center>
      ) : data.items.length === 0 ? (
        <Text c="dimmed">No scans match the current filters.</Text>
      ) : (
        <>
          <Table.ScrollContainer minWidth={860}>
            <Table highlightOnHover striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={36}> </Table.Th>
                  <SortableTh
                    label="Scanner"
                    column="scanner"
                    sort={sort}
                    order={order}
                    onSort={toggleSort}
                  />
                  <SortableTh
                    label="Target"
                    column="target"
                    sort={sort}
                    order={order}
                    onSort={toggleSort}
                  />
                  <SortableTh
                    label="Status"
                    column="status"
                    sort={sort}
                    order={order}
                    onSort={toggleSort}
                  />
                  <SortableTh
                    label="Highest"
                    column="severity"
                    sort={sort}
                    order={order}
                    onSort={toggleSort}
                  />
                  <SortableTh
                    label="Findings"
                    column="findings_count"
                    sort={sort}
                    order={order}
                    onSort={toggleSort}
                  />
                  <Table.Th>Tags</Table.Th>
                  <Table.Th>By</Table.Th>
                  <SortableTh
                    label="Created"
                    column="created_at"
                    sort={sort}
                    order={order}
                    onSort={toggleSort}
                  />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.items.map((scan) => (
                  <Table.Tr key={scan.id}>
                    <Table.Td onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        aria-label={`Select scan ${scan.id} to compare`}
                        checked={compare.some((s) => s.id === scan.id)}
                        onChange={(e) => toggleCompare(scan, e.currentTarget.checked)}
                      />
                    </Table.Td>
                    <Table.Td
                      style={{ cursor: 'pointer' }}
                      onClick={() => navigate(`/scans/${scan.id}`)}
                    >
                      <Badge variant="light" color="teal">
                        {scan.scanner}
                      </Badge>
                    </Table.Td>
                    <Table.Td
                      style={{ cursor: 'pointer' }}
                      onClick={() => navigate(`/scans/${scan.id}`)}
                    >
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
                      <Group gap={4}>
                        {scan.tags.length === 0 ? (
                          <Text size="sm" c="dimmed">
                            —
                          </Text>
                        ) : (
                          scan.tags.map((tag) => (
                            <Badge key={tag} size="sm" variant="outline" color="gray">
                              {tag}
                            </Badge>
                          ))
                        )}
                      </Group>
                    </Table.Td>
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

          <Group justify="space-between">
            <Text size="sm" c="dimmed">
              {data.total} scan{data.total === 1 ? '' : 's'} match
            </Text>
            <Pagination value={page} onChange={setPage} total={totalPages} size="sm" color="teal" />
          </Group>
        </>
      )}
    </Stack>
  );
}

interface SortableThProps {
  label: string;
  column: HistorySort;
  sort: HistorySort;
  order: SortOrder;
  onSort: (column: HistorySort) => void;
}

/** A table header cell that sorts the history by its column when clicked. */
function SortableTh({ label, column, sort, order, onSort }: SortableThProps) {
  const active = sort === column;
  return (
    <Table.Th style={{ cursor: 'pointer' }} onClick={() => onSort(column)}>
      <Group gap={4} wrap="nowrap">
        <Text size="sm" fw={600}>
          {label}
        </Text>
        {active && (order === 'asc' ? <IconChevronUp size={14} /> : <IconChevronDown size={14} />)}
      </Group>
    </Table.Th>
  );
}
