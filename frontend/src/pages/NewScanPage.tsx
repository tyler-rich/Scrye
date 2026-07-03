import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Alert,
  Button,
  Checkbox,
  Group,
  MultiSelect,
  Paper,
  SegmentedControl,
  Stack,
  Switch,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle } from '@tabler/icons-react';

import { ApiError } from '../api/client';
import {
  createScan,
  type CreateScanInput,
  type Scanner,
  type TrivyScannerName,
  type TrivySeverity,
} from '../api/scans';
import { useAuth } from '../auth/AuthContext';

const TRIVY_SCANNERS: { value: TrivyScannerName; label: string }[] = [
  { value: 'vuln', label: 'Vulnerabilities' },
  { value: 'misconfig', label: 'Misconfigurations' },
  { value: 'secret', label: 'Secrets' },
  { value: 'license', label: 'Licenses' },
];

const TRIVY_SEVERITIES: TrivySeverity[] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/** Form to launch a Trivy or Grype scan of a container image. */
export function NewScanPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canLaunch = user?.role === 'operator' || user?.role === 'admin';

  const [scanner, setScanner] = useState<Scanner>('trivy');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const form = useForm({
    initialValues: {
      target: '',
      trivyScanners: ['vuln', 'misconfig', 'secret', 'license'] as TrivyScannerName[],
      trivySeverity: [...TRIVY_SEVERITIES] as TrivySeverity[],
      ignoreUnfixed: false,
    },
    validate: {
      target: (v) => (v.trim().length > 0 ? null : 'Enter an image reference'),
      trivyScanners: (v) =>
        scanner === 'trivy' && v.length === 0 ? 'Select at least one scanner' : null,
    },
  });

  const submit = form.onSubmit(async (values) => {
    setSubmitting(true);
    setError(null);
    const payload: CreateScanInput = { scanner, target: values.target.trim() };
    if (scanner === 'trivy') {
      payload.trivy_scanners = values.trivyScanners;
      payload.trivy_severity = values.trivySeverity;
      payload.ignore_unfixed = values.ignoreUnfixed;
    }
    try {
      const scan = await createScan(payload);
      navigate(`/scans/${scan.id}`);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Failed to launch scan.');
    } finally {
      setSubmitting(false);
    }
  });

  return (
    <Stack gap="md" maw={640}>
      <div>
        <Title order={2}>New scan</Title>
        <Text c="dimmed">Scan a container image with Trivy or Grype.</Text>
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
                Scanner
              </Text>
              <SegmentedControl
                value={scanner}
                onChange={(v) => setScanner(v as Scanner)}
                data={[
                  { label: 'Trivy', value: 'trivy' },
                  { label: 'Grype', value: 'grype' },
                ]}
                disabled={!canLaunch}
              />
            </div>

            <TextInput
              label="Image reference"
              placeholder="e.g. alpine:3.19 or ghcr.io/org/app:tag"
              disabled={!canLaunch}
              {...form.getInputProps('target')}
            />

            {scanner === 'trivy' ? (
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
            ) : (
              <Text size="sm" c="dimmed">
                Grype scans for vulnerabilities only; no scanner selection applies.
              </Text>
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
