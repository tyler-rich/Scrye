import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Group,
  MultiSelect,
  NumberInput,
  Stack,
  Switch,
  Textarea,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconCheck } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import { getScannerSettings, updateScannerSettings } from '../../api/settings';
import { useAuth } from '../../auth/AuthContext';

const SEVERITIES = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/** Scanner default options, thresholds, and ignore rules. */
export function ScannersPanel() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin';
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const form = useForm({
    initialValues: {
      default_severities: SEVERITIES,
      default_ignore_unfixed: false,
      trivyignore: '',
      grype_ignore: '',
      auto_update_db: true,
      db_update_interval_hours: 24,
    },
  });

  useEffect(() => {
    void getScannerSettings()
      .then((v) => form.setValues(v))
      .catch(() => setError('Failed to load scanner settings.'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = form.onSubmit(async (values) => {
    setError(null);
    setSaved(false);
    try {
      await updateScannerSettings(values);
      setSaved(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save.');
    }
  });

  return (
    <form onSubmit={submit}>
      <Stack gap="md" maw={620}>
        {error && (
          <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
            {error}
          </Alert>
        )}
        {saved && (
          <Alert color="teal" icon={<IconCheck size={16} />} variant="light">
            Settings saved.
          </Alert>
        )}
        <MultiSelect
          label="Default severities"
          data={SEVERITIES}
          disabled={!canManage}
          {...form.getInputProps('default_severities')}
        />
        <Switch
          label="Ignore unfixed vulnerabilities by default"
          disabled={!canManage}
          {...form.getInputProps('default_ignore_unfixed', { type: 'checkbox' })}
        />
        <Textarea
          label="Global .trivyignore rules"
          description="One CVE id or path per line, applied to Trivy scans."
          disabled={!canManage}
          autosize
          minRows={2}
          {...form.getInputProps('trivyignore')}
        />
        <Textarea
          label="Global Grype ignore rules (YAML)"
          disabled={!canManage}
          autosize
          minRows={2}
          {...form.getInputProps('grype_ignore')}
        />
        <Switch
          label="Automatically update scanner vulnerability databases"
          disabled={!canManage}
          {...form.getInputProps('auto_update_db', { type: 'checkbox' })}
        />
        <NumberInput
          label="DB update interval (hours)"
          min={1}
          max={720}
          disabled={!canManage}
          {...form.getInputProps('db_update_interval_hours')}
        />
        {canManage && (
          <Group>
            <Button type="submit">Save</Button>
          </Group>
        )}
      </Stack>
    </form>
  );
}
