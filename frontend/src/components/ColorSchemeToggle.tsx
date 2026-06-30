import { ActionIcon, useComputedColorScheme, useMantineColorScheme } from '@mantine/core';
import { IconMoon, IconSun } from '@tabler/icons-react';

/**
 * Light/dark toggle. Uses Mantine's color-scheme manager so the choice
 * persists and respects the system 'auto' default (PLAN.md § Teal theme).
 */
export function ColorSchemeToggle() {
  const { setColorScheme } = useMantineColorScheme();
  const computed = useComputedColorScheme('light', { getInitialValueInEffect: true });
  const isDark = computed === 'dark';

  return (
    <ActionIcon
      onClick={() => setColorScheme(isDark ? 'light' : 'dark')}
      variant="default"
      size="lg"
      aria-label="Toggle color scheme"
    >
      {isDark ? <IconSun size={18} stroke={1.5} /> : <IconMoon size={18} stroke={1.5} />}
    </ActionIcon>
  );
}
