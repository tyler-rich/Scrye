import { useEffect, useState } from 'react';
import { Alert, Button, Group, Stack, Textarea, TextInput } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconCheck } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import { getGeneralSettings, updateGeneralSettings } from '../../api/settings';
import { useAuth } from '../../auth/AuthContext';

/** General instance settings (name, admin note). */
export function GeneralPanel() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin';
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const form = useForm({ initialValues: { instance_name: 'Scrye', admin_note: '' } });

  useEffect(() => {
    void getGeneralSettings()
      .then((v) => form.setValues(v))
      .catch(() => setError('Failed to load general settings.'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = form.onSubmit(async (values) => {
    setError(null);
    setSaved(false);
    try {
      await updateGeneralSettings(values);
      setSaved(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save.');
    }
  });

  return (
    <form onSubmit={submit}>
      <Stack gap="md" maw={520}>
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
        <TextInput
          label="Instance name"
          disabled={!canManage}
          {...form.getInputProps('instance_name')}
        />
        <Textarea
          label="Admin note"
          description="Shown on the About tab (e.g. environment label)."
          disabled={!canManage}
          autosize
          minRows={2}
          {...form.getInputProps('admin_note')}
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
