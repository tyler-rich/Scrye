import { useEffect, useState } from 'react';
import { Alert, Button, Group, NumberInput, Stack, Switch, Text } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconCheck } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import { getRetentionSettings, updateRetentionSettings } from '../../api/settings';

/** Result-retention policy for pruning old raw artifacts (docs/ARCHIVE.md §12). */
export function RetentionPanel() {
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  // The form renders the built-in defaults until the live policy loads; gate
  // Save (and the inputs) on this so an admin can't overwrite the live policy
  // with defaults before the GET resolves (M19 / P1-2).
  const [loaded, setLoaded] = useState(false);

  const form = useForm({ initialValues: { enabled: false, max_age_days: 90 } });

  useEffect(() => {
    void getRetentionSettings()
      .then((v) => {
        // Don't clobber edits the admin has already made while the GET was
        // in flight; only seed the fetched policy into a pristine form.
        if (!form.isDirty()) form.setValues(v);
        setLoaded(true);
      })
      .catch(() => setError('Failed to load retention settings.'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = form.onSubmit(async (values) => {
    setError(null);
    setSaved(false);
    try {
      await updateRetentionSettings({
        enabled: values.enabled,
        max_age_days: Number(values.max_age_days),
      });
      setSaved(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save.');
    }
  });

  return (
    <form onSubmit={submit}>
      <Stack gap="md" maw={520}>
        <Text c="dimmed" size="sm">
          When enabled, the raw scanner output and SBOMs of scans older than the retention age are
          pruned to bound disk usage. The scan history and normalized findings are kept.
        </Text>
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
        <Switch
          label="Prune old raw artifacts"
          disabled={!loaded}
          {...form.getInputProps('enabled', { type: 'checkbox' })}
        />
        <NumberInput
          label="Maximum age (days)"
          description="Raw artifacts of scans older than this are removed."
          min={1}
          max={3650}
          disabled={!loaded || !form.values.enabled}
          {...form.getInputProps('max_age_days')}
        />
        <Group>
          <Button type="submit" loading={!loaded} disabled={!loaded}>
            Save
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
