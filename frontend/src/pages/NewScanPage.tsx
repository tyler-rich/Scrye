import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Alert,
  Button,
  Checkbox,
  FileInput,
  Group,
  MultiSelect,
  Paper,
  SegmentedControl,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconUpload } from '@tabler/icons-react';

import { ApiError } from '../api/client';
import {
  createSbomScan,
  createScan,
  type CreateScanInput,
  type Scanner,
  type SbomFormat,
  type TargetType,
  type TrivyScannerName,
  type TrivySeverity,
} from '../api/scans';
import { getScannerSettings } from '../api/settings';
import {
  listGitCredentialOptions,
  listRegistryOptions,
  type CredentialOption,
} from '../api/targets';
import { useAuth } from '../auth/AuthContext';

const TRIVY_SCANNERS: { value: TrivyScannerName; label: string }[] = [
  { value: 'vuln', label: 'Vulnerabilities' },
  { value: 'misconfig', label: 'Misconfigurations' },
  { value: 'secret', label: 'Secrets' },
  { value: 'license', label: 'Licenses' },
];

const TRIVY_SEVERITIES: TrivySeverity[] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const SBOM_FORMATS: { value: SbomFormat; label: string }[] = [
  { value: 'cyclonedx-json', label: 'CycloneDX JSON' },
  { value: 'spdx-json', label: 'SPDX JSON' },
  { value: 'syft-json', label: 'Syft JSON' },
];

const TARGET_TYPES: { value: TargetType; label: string }[] = [
  { value: 'image', label: 'Image' },
  { value: 'repository', label: 'Repository' },
  { value: 'filesystem', label: 'Filesystem' },
  { value: 'sbom', label: 'SBOM' },
];

/** Scanners permitted per target type (mirrors the backend matrix). */
const SCANNERS_FOR: Record<TargetType, Scanner[]> = {
  image: ['trivy', 'grype'],
  repository: ['trivy'],
  filesystem: ['grype'],
  sbom: ['grype'],
};

const TARGET_LABEL: Record<TargetType, string> = {
  image: 'Image reference',
  repository: 'Repository URL',
  filesystem: 'Filesystem path',
  sbom: 'SBOM file',
};

const TARGET_PLACEHOLDER: Record<TargetType, string> = {
  image: 'e.g. alpine:3.19 or ghcr.io/org/app:tag',
  repository: 'e.g. https://github.com/org/repo.git',
  filesystem: 'e.g. /srv/project (must be within a configured scan root)',
  sbom: '',
};

/** Form to launch a Trivy/Grype scan across image, repo, filesystem, or SBOM targets. */
export function NewScanPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canLaunch = user?.role === 'operator' || user?.role === 'admin';

  const [targetType, setTargetType] = useState<TargetType>('image');
  const [scanner, setScanner] = useState<Scanner>('trivy');
  const [registries, setRegistries] = useState<CredentialOption[]>([]);
  const [gitCredentials, setGitCredentials] = useState<CredentialOption[]>([]);
  const [sbomFile, setSbomFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const loadTargets = useCallback(async () => {
    try {
      const [regs, creds] = await Promise.all([listRegistryOptions(), listGitCredentialOptions()]);
      setRegistries(regs);
      setGitCredentials(creds);
    } catch {
      // Non-fatal: credential pickers stay empty if the lists can't load.
    }
  }, []);

  useEffect(() => {
    if (canLaunch) void loadTargets();
  }, [canLaunch, loadTargets]);

  // Keep the scanner valid for the chosen target type.
  useEffect(() => {
    const allowed = SCANNERS_FOR[targetType];
    if (!allowed.includes(scanner)) setScanner(allowed[0]);
  }, [targetType, scanner]);

  const form = useForm({
    initialValues: {
      target: '',
      trivyScanners: ['vuln', 'misconfig', 'secret', 'license'] as TrivyScannerName[],
      trivySeverity: [...TRIVY_SEVERITIES] as TrivySeverity[],
      ignoreUnfixed: false,
      registryId: '' as string,
      gitCredentialId: '' as string,
      branch: '',
      commit: '',
      tag: '',
      generateSbom: false,
      sbomFormat: 'cyclonedx-json' as SbomFormat,
    },
    validate: {
      target: (v) => (targetType === 'sbom' || v.trim().length > 0 ? null : 'Enter a target'),
      trivyScanners: (v) =>
        scanner === 'trivy' && v.length === 0 ? 'Select at least one scanner' : null,
    },
  });

  // Prefill the severity filter and ignore-unfixed toggle from the instance
  // defaults (Settings → Scanners) so changing those defaults actually affects
  // new scans (FEAT-7). Runs once on mount, before the user edits the form; a
  // fetch failure just leaves the built-in defaults in place.
  useEffect(() => {
    let active = true;
    getScannerSettings()
      .then((s) => {
        if (!active) return;
        const severities = s.default_severities.filter((v): v is TrivySeverity =>
          (TRIVY_SEVERITIES as string[]).includes(v),
        );
        if (severities.length > 0) form.setFieldValue('trivySeverity', severities);
        form.setFieldValue('ignoreUnfixed', s.default_ignore_unfixed);
      })
      .catch(() => {
        /* keep the built-in defaults */
      });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const isTrivy = scanner === 'trivy';
  const canGenerateSbom = targetType === 'image' || targetType === 'filesystem';

  const submit = form.onSubmit(async (values) => {
    setError(null);
    setSubmitting(true);
    try {
      if (targetType === 'sbom') {
        if (!sbomFile) {
          setError('Choose an SBOM file to scan.');
          return;
        }
        const scan = await createSbomScan(sbomFile, 'grype');
        navigate(`/scans/${scan.id}`);
        return;
      }

      const payload: CreateScanInput = {
        scanner,
        target_type: targetType,
        target: values.target.trim(),
      };
      if (isTrivy) {
        payload.trivy_scanners = values.trivyScanners;
        payload.trivy_severity = values.trivySeverity;
        payload.ignore_unfixed = values.ignoreUnfixed;
      }
      if (targetType === 'image') {
        payload.registry_id = values.registryId ? Number(values.registryId) : null;
        payload.generate_sbom = values.generateSbom;
        if (values.generateSbom) payload.sbom_format = values.sbomFormat;
      } else if (targetType === 'repository') {
        payload.git_credential_id = values.gitCredentialId ? Number(values.gitCredentialId) : null;
        payload.branch = values.branch.trim() || null;
        payload.commit = values.commit.trim() || null;
        payload.tag = values.tag.trim() || null;
      } else if (targetType === 'filesystem') {
        payload.generate_sbom = values.generateSbom;
        if (values.generateSbom) payload.sbom_format = values.sbomFormat;
      }

      const scan = await createScan(payload);
      navigate(`/scans/${scan.id}`);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Failed to launch scan.');
    } finally {
      setSubmitting(false);
    }
  });

  return (
    <Stack gap="md" maw={680}>
      <div>
        <Title order={2}>New scan</Title>
        <Text c="dimmed">Scan an image, git repository, filesystem, or SBOM.</Text>
      </div>

      {!canLaunch && (
        <Alert color="yellow" icon={<IconAlertCircle size={16} />} variant="light">
          Your role is read-only. Launching scans requires the operator role.
        </Alert>
      )}

      <Paper withBorder radius="md" p="lg">
        <form onSubmit={submit}>
          <Stack gap="md">
            {error && (
              <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
                {error}
              </Alert>
            )}

            <div>
              <Text size="sm" fw={500} mb={4}>
                Target type
              </Text>
              <SegmentedControl
                value={targetType}
                onChange={(v) => setTargetType(v as TargetType)}
                data={TARGET_TYPES}
                disabled={!canLaunch}
              />
            </div>

            <div>
              <Text size="sm" fw={500} mb={4}>
                Scanner
              </Text>
              <SegmentedControl
                value={scanner}
                onChange={(v) => setScanner(v as Scanner)}
                data={SCANNERS_FOR[targetType].map((s) => ({
                  label: s === 'trivy' ? 'Trivy' : 'Grype',
                  value: s,
                }))}
                disabled={!canLaunch || SCANNERS_FOR[targetType].length === 1}
              />
            </div>

            {targetType === 'sbom' ? (
              <FileInput
                label="SBOM file"
                placeholder="Select a CycloneDX / SPDX / Syft JSON file"
                leftSection={<IconUpload size={16} />}
                accept="application/json,.json"
                value={sbomFile}
                onChange={setSbomFile}
                disabled={!canLaunch}
                clearable
              />
            ) : (
              <TextInput
                label={TARGET_LABEL[targetType]}
                placeholder={TARGET_PLACEHOLDER[targetType]}
                disabled={!canLaunch}
                {...form.getInputProps('target')}
              />
            )}

            {targetType === 'image' && (
              <Select
                label="Registry credential (optional)"
                description="Select a credential to pull from a private registry."
                placeholder="Public / anonymous"
                data={registries.map((r) => ({ value: String(r.id), label: r.name }))}
                clearable
                disabled={!canLaunch}
                {...form.getInputProps('registryId')}
              />
            )}

            {targetType === 'repository' && (
              <>
                <Select
                  label="Git credential (optional)"
                  description="Select a credential to clone a private repository."
                  placeholder="Public repository"
                  data={gitCredentials.map((c) => ({ value: String(c.id), label: c.name }))}
                  clearable
                  disabled={!canLaunch}
                  {...form.getInputProps('gitCredentialId')}
                />
                <Group grow>
                  <TextInput
                    label="Branch"
                    placeholder="optional"
                    disabled={!canLaunch}
                    {...form.getInputProps('branch')}
                  />
                  <TextInput
                    label="Commit"
                    placeholder="optional"
                    disabled={!canLaunch}
                    {...form.getInputProps('commit')}
                  />
                  <TextInput
                    label="Tag"
                    placeholder="optional"
                    disabled={!canLaunch}
                    {...form.getInputProps('tag')}
                  />
                </Group>
                <Text size="xs" c="dimmed">
                  Set at most one of branch / commit / tag.
                </Text>
              </>
            )}

            {isTrivy && (targetType === 'image' || targetType === 'repository') && (
              <>
                <Checkbox.Group
                  label="Scanners"
                  description="Trivy runs the selected scanners in one pass."
                  {...form.getInputProps('trivyScanners')}
                >
                  <Group mt="xs" gap="md">
                    {TRIVY_SCANNERS.map((s) => (
                      <Checkbox
                        key={s.value}
                        value={s.value}
                        label={s.label}
                        disabled={!canLaunch}
                      />
                    ))}
                  </Group>
                </Checkbox.Group>

                <MultiSelect
                  label="Severity filter"
                  data={TRIVY_SEVERITIES.map((s) => ({ value: s, label: s }))}
                  disabled={!canLaunch}
                  {...form.getInputProps('trivySeverity')}
                />

                <Switch
                  label="Ignore unfixed vulnerabilities"
                  disabled={!canLaunch}
                  {...form.getInputProps('ignoreUnfixed', { type: 'checkbox' })}
                />
              </>
            )}

            {!isTrivy && targetType !== 'sbom' && (
              <Text size="sm" c="dimmed">
                Grype scans for vulnerabilities only; no scanner selection applies.
              </Text>
            )}

            {canGenerateSbom && (
              <Group align="flex-end" gap="md">
                <Switch
                  label="Generate SBOM (Syft)"
                  disabled={!canLaunch}
                  {...form.getInputProps('generateSbom', { type: 'checkbox' })}
                />
                {form.values.generateSbom && (
                  <Select
                    label="SBOM format"
                    data={SBOM_FORMATS}
                    allowDeselect={false}
                    disabled={!canLaunch}
                    {...form.getInputProps('sbomFormat')}
                  />
                )}
              </Group>
            )}

            <Group justify="flex-end">
              <Button type="submit" loading={submitting} disabled={!canLaunch}>
                Launch scan
              </Button>
            </Group>
          </Stack>
        </form>
      </Paper>
    </Stack>
  );
}
