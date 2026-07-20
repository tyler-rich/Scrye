import { useCallback, useEffect, useState } from 'react';
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Divider,
  Group,
  Modal,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  Textarea,
  TextInput,
  Title,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconTrash } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import {
  createIgnoreRule,
  createVexDocument,
  deleteIgnoreRule,
  deleteVexDocument,
  listIgnoreRules,
  listVexDocuments,
  type IgnoreRule,
  type VexDocument,
  type VexFormat,
} from '../../api/trivyPolicy';

const VEX_FORMATS: { value: VexFormat; label: string }[] = [
  { value: 'openvex', label: 'OpenVEX' },
  { value: 'cyclonedx', label: 'CycloneDX VEX' },
  { value: 'csaf', label: 'CSAF' },
];

interface VexForm {
  name: string;
  format: VexFormat;
  content: string;
  enabled: boolean;
}

interface RuleForm {
  vuln_id: string;
  reason: string;
  enabled: boolean;
}

/** Trivy VEX documents and ignore rules (docs/ARCHIVE.md §4.1/§4.5). */
export function TrivyPolicyPanel() {
  const [vex, setVex] = useState<VexDocument[]>([]);
  const [rules, setRules] = useState<IgnoreRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [vexOpen, vexModal] = useDisclosure(false);
  const [ruleOpen, ruleModal] = useDisclosure(false);

  const load = useCallback(async () => {
    try {
      const [v, r] = await Promise.all([listVexDocuments(), listIgnoreRules()]);
      setVex(v);
      setRules(r);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load Trivy policy.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const vexForm = useForm<VexForm>({
    initialValues: { name: '', format: 'openvex', content: '', enabled: true },
    validate: {
      name: (v) => (v.trim() ? null : 'Required'),
      content: (v) => (v.trim() ? null : 'Required'),
    },
  });

  const ruleForm = useForm<RuleForm>({
    initialValues: { vuln_id: '', reason: '', enabled: true },
    validate: { vuln_id: (v) => (v.trim() ? null : 'Required') },
  });

  const submitVex = vexForm.onSubmit(async (values) => {
    setError(null);
    try {
      await createVexDocument({
        name: values.name.trim(),
        format: values.format,
        content: values.content,
        enabled: values.enabled,
      });
      vexForm.reset();
      vexModal.close();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save VEX document.');
    }
  });

  const submitRule = ruleForm.onSubmit(async (values) => {
    setError(null);
    try {
      await createIgnoreRule({
        vuln_id: values.vuln_id.trim(),
        reason: values.reason.trim() || null,
        enabled: values.enabled,
      });
      ruleForm.reset();
      ruleModal.close();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save ignore rule.');
    }
  });

  const removeVex = async (id: number) => {
    try {
      await deleteVexDocument(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete VEX document.');
    }
  };

  const removeRule = async (id: number) => {
    try {
      await deleteIgnoreRule(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete ignore rule.');
    }
  };

  return (
    <Stack gap="lg">
      <Text c="dimmed" size="sm">
        Policy applied to every Trivy scan. VEX documents mark vulnerabilities not-affected; ignore
        rules suppress specific ids. Both apply only when enabled.
      </Text>

      {error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
          {error}
        </Alert>
      )}

      <div>
        <Group justify="space-between" mb="sm">
          <Title order={4}>VEX documents</Title>
          <Button size="xs" onClick={vexModal.open}>
            Add VEX document
          </Button>
        </Group>
        <Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Format</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {vex.map((v) => (
              <Table.Tr key={v.id}>
                <Table.Td>{v.name}</Table.Td>
                <Table.Td>{v.format}</Table.Td>
                <Table.Td>
                  <Badge color={v.enabled ? 'teal' : 'gray'} variant="light">
                    {v.enabled ? 'enabled' : 'disabled'}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Group justify="flex-end">
                    <ActionIcon
                      variant="subtle"
                      color="red"
                      aria-label="Delete VEX document"
                      onClick={() => removeVex(v.id)}
                    >
                      <IconTrash size={16} />
                    </ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
            {vex.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={4}>
                  <Text c="dimmed" ta="center" py="sm">
                    No VEX documents.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </div>

      <Divider />

      <div>
        <Group justify="space-between" mb="sm">
          <Title order={4}>Ignore rules</Title>
          <Button size="xs" onClick={ruleModal.open}>
            Add ignore rule
          </Button>
        </Group>
        <Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Vulnerability ID</Table.Th>
              <Table.Th>Reason</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rules.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {r.vuln_id}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" c="dimmed">
                    {r.reason ?? '—'}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Badge color={r.enabled ? 'teal' : 'gray'} variant="light">
                    {r.enabled ? 'enabled' : 'disabled'}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Group justify="flex-end">
                    <ActionIcon
                      variant="subtle"
                      color="red"
                      aria-label="Delete ignore rule"
                      onClick={() => removeRule(r.id)}
                    >
                      <IconTrash size={16} />
                    </ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
            {rules.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={4}>
                  <Text c="dimmed" ta="center" py="sm">
                    No ignore rules.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </div>

      <Modal opened={vexOpen} onClose={vexModal.close} title="Add VEX document" centered size="lg">
        <form onSubmit={submitVex}>
          <Stack gap="sm">
            <TextInput label="Name" {...vexForm.getInputProps('name')} />
            <Select
              label="Format"
              data={VEX_FORMATS}
              allowDeselect={false}
              {...vexForm.getInputProps('format')}
            />
            <Textarea
              label="Document (JSON)"
              autosize
              minRows={6}
              maxRows={16}
              {...vexForm.getInputProps('content')}
            />
            <Switch label="Enabled" {...vexForm.getInputProps('enabled', { type: 'checkbox' })} />
            <Group justify="flex-end">
              <Button variant="default" onClick={vexModal.close}>
                Cancel
              </Button>
              <Button type="submit">Create</Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      <Modal opened={ruleOpen} onClose={ruleModal.close} title="Add ignore rule" centered>
        <form onSubmit={submitRule}>
          <Stack gap="sm">
            <TextInput
              label="Vulnerability ID"
              placeholder="CVE-2024-12345"
              {...ruleForm.getInputProps('vuln_id')}
            />
            <TextInput
              label="Reason"
              description="Optional justification, rendered as a comment."
              {...ruleForm.getInputProps('reason')}
            />
            <Switch label="Enabled" {...ruleForm.getInputProps('enabled', { type: 'checkbox' })} />
            <Group justify="flex-end">
              <Button variant="default" onClick={ruleModal.close}>
                Cancel
              </Button>
              <Button type="submit">Create</Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
