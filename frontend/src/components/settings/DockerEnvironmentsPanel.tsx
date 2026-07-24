import { useCallback, useEffect, useState } from 'react';
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Code,
  Group,
  List,
  Modal,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconAlertCircle, IconAlertTriangle, IconList, IconTrash } from '@tabler/icons-react';

import { ApiError } from '../../api/client';
import {
  createDockerEnvironment,
  deleteDockerEnvironment,
  type DockerEnvironment,
  type DockerImage,
  enumerateImages,
  listDockerEnvironments,
  updateDockerEnvironment,
} from '../../api/targets';
import { useAuth } from '../../auth/AuthContext';
import { StatusLoader } from '../StatusLoader';

/** Manage read-only Docker socket-proxy environments and enumerate their images. */
export function DockerEnvironmentsPanel() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin';
  const [items, setItems] = useState<DockerEnvironment[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [opened, { open, close }] = useDisclosure(false);

  const [imagesOpened, { open: openImages, close: closeImages }] = useDisclosure(false);
  const [images, setImages] = useState<DockerImage[] | null>(null);
  const [imagesError, setImagesError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setItems(await listDockerEnvironments());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load Docker environments.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const form = useForm({
    initialValues: { name: '', proxy_url: '', risk_acknowledged: false },
    validate: {
      name: (v) => (v.trim() ? null : 'Required'),
      proxy_url: (v) => (v.trim() ? null : 'Required'),
    },
  });

  const submit = form.onSubmit(async (values) => {
    setError(null);
    try {
      await createDockerEnvironment({
        name: values.name.trim(),
        proxy_url: values.proxy_url.trim(),
        risk_acknowledged: values.risk_acknowledged,
      });
      form.reset();
      close();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create environment.');
    }
  });

  const onToggleRisk = async (env: DockerEnvironment) => {
    setError(null);
    try {
      await updateDockerEnvironment(env.id, { risk_acknowledged: !env.risk_acknowledged });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update environment.');
    }
  };

  const onDelete = async (id: number) => {
    setError(null);
    try {
      await deleteDockerEnvironment(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete environment.');
    }
  };

  const onEnumerate = async (id: number) => {
    setImages(null);
    setImagesError(null);
    openImages();
    try {
      setImages(await enumerateImages(id));
    } catch (err) {
      setImagesError(err instanceof ApiError ? err.message : 'Failed to enumerate images.');
    }
  };

  return (
    <Stack gap="md">
      <Alert color="yellow" icon={<IconAlertTriangle size={16} />} variant="light">
        Reaching a Docker daemon — even read-only — is a residual risk. Scrye only lists images via
        a read-only socket proxy and never controls Docker. Enumeration is disabled until the risk
        is acknowledged.
      </Alert>

      <Group justify="space-between">
        <Text c="dimmed" size="sm">
          Read-only docker-socket-proxy endpoints for the &ldquo;scan running images&rdquo; flow.
        </Text>
        {canManage && <Button onClick={open}>Add environment</Button>}
      </Group>

      {error && (
        <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
          {error}
        </Alert>
      )}

      <Table.ScrollContainer minWidth={640}>
        <Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Proxy URL</Table.Th>
              <Table.Th>Risk acknowledged</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((e) => (
              <Table.Tr key={e.id}>
                <Table.Td>{e.name}</Table.Td>
                <Table.Td>
                  <Code>{e.proxy_url}</Code>
                </Table.Td>
                <Table.Td>
                  {canManage ? (
                    <Switch
                      checked={e.risk_acknowledged}
                      onChange={() => onToggleRisk(e)}
                      aria-label="Acknowledge residual risk"
                    />
                  ) : (
                    <Badge color={e.risk_acknowledged ? 'teal' : 'gray'} variant="light">
                      {e.risk_acknowledged ? 'yes' : 'no'}
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  <Group gap="xs" justify="flex-end">
                    <ActionIcon
                      variant="subtle"
                      aria-label="Enumerate images"
                      disabled={!e.enabled || !e.risk_acknowledged}
                      onClick={() => onEnumerate(e.id)}
                    >
                      <IconList size={16} />
                    </ActionIcon>
                    {canManage && (
                      <ActionIcon
                        variant="subtle"
                        color="red"
                        aria-label="Delete environment"
                        onClick={() => onDelete(e.id)}
                      >
                        <IconTrash size={16} />
                      </ActionIcon>
                    )}
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
            {items.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={4}>
                  <Text c="dimmed" ta="center" py="md">
                    No Docker environments configured.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={opened} onClose={close} title="Add Docker environment" centered>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <TextInput label="Name" {...form.getInputProps('name')} />
            <TextInput
              label="Proxy URL"
              placeholder="http://docker-socket-proxy:2375"
              {...form.getInputProps('proxy_url')}
            />
            <Switch
              label="I acknowledge the residual risk of read-only Docker access"
              {...form.getInputProps('risk_acknowledged', { type: 'checkbox' })}
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={close}>
                Cancel
              </Button>
              <Button type="submit">Create</Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      <Modal opened={imagesOpened} onClose={closeImages} title="Images" centered size="lg">
        {imagesError ? (
          <Alert color="red" icon={<IconAlertCircle size={16} />} variant="light">
            {imagesError}
          </Alert>
        ) : images === null ? (
          <Group justify="center" py="lg">
            <StatusLoader color="teal" label="Loading images" />
          </Group>
        ) : images.length === 0 ? (
          <Text c="dimmed">No tagged images visible to this environment.</Text>
        ) : (
          <Stack gap="xs">
            <Text size="sm" c="dimmed">
              Use any of these references as an image target in a new scan.
            </Text>
            <List spacing="xs">
              {images.flatMap((img) =>
                img.tags.map((tag) => (
                  <List.Item key={`${img.id}-${tag}`}>
                    <Code>{tag}</Code>
                  </List.Item>
                )),
              )}
            </List>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
