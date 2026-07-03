import { createTheme } from '@mantine/core';

// Locked decision: teal primary with first-class light and dark modes
// (CLAUDE.md § Locked decisions #7, PLAN.md § Teal theme).
export const theme = createTheme({
  primaryColor: 'teal',
  primaryShade: { light: 6, dark: 8 },
  defaultRadius: 'md',
  fontFamily: 'Inter, system-ui, sans-serif',
});
