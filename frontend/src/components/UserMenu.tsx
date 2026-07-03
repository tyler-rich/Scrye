import { Avatar, Badge, Group, Menu, Text, UnstyledButton } from '@mantine/core';
import { IconChevronDown, IconLogout, IconUserCircle } from '@tabler/icons-react';
import { Link } from 'react-router-dom';

import { useAuth } from '../auth/AuthContext';

/** Header menu showing the signed-in user, their role, and a logout action. */
export function UserMenu() {
  const { user, logout } = useAuth();
  if (!user) return null;

  return (
    <Menu position="bottom-end" width={200} withArrow>
      <Menu.Target>
        <UnstyledButton aria-label="User menu">
          <Group gap="xs">
            <Avatar color="teal" radius="xl" size="sm">
              {user.username.slice(0, 2).toUpperCase()}
            </Avatar>
            <Text size="sm" fw={500} visibleFrom="sm">
              {user.username}
            </Text>
            <IconChevronDown size={14} stroke={1.5} />
          </Group>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>
          <Group gap="xs">
            <Text size="xs">{user.username}</Text>
            <Badge size="xs" variant="light">
              {user.role}
            </Badge>
          </Group>
        </Menu.Label>
        <Menu.Divider />
        <Menu.Item component={Link} to="/account" leftSection={<IconUserCircle size={14} />}>
          Account
        </Menu.Item>
        <Menu.Item
          leftSection={<IconLogout size={14} />}
          onClick={() => {
            void logout();
          }}
        >
          Log out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
