import type { ReactElement, ReactNode } from 'react';
import { MantineProvider } from '@mantine/core';
import { MemoryRouter } from 'react-router-dom';
import { render, type RenderOptions, type RenderResult } from '@testing-library/react';

import { theme } from '../theme';

/**
 * Wraps a subtree in the providers every Scrye page assumes are present:
 * MantineProvider (theme + color scheme) and a router. Pages that read the
 * current path use `MemoryRouter`, so tests control the initial location without
 * a real browser history.
 */
function AppProviders({
  children,
  initialEntries,
}: {
  children: ReactNode;
  initialEntries: string[];
}) {
  return (
    <MantineProvider theme={theme}>
      <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
    </MantineProvider>
  );
}

export interface RenderWithProvidersOptions extends Omit<RenderOptions, 'wrapper'> {
  /** Initial router history stack; defaults to a single `/` entry. */
  initialEntries?: string[];
}

/**
 * `render` from React Testing Library with Scrye's providers already applied.
 * Use this instead of the bare `render` for any component that consumes Mantine
 * or router context (i.e. essentially every page and settings panel).
 */
export function renderWithProviders(
  ui: ReactElement,
  { initialEntries = ['/'], ...options }: RenderWithProvidersOptions = {},
): RenderResult {
  return render(ui, {
    wrapper: ({ children }) => (
      <AppProviders initialEntries={initialEntries}>{children}</AppProviders>
    ),
    ...options,
  });
}

// Re-export the Testing Library surface so tests import everything from one
// place: `import { renderWithProviders, screen, userEvent } from '../test/render';`
export { screen, waitFor, within, fireEvent } from '@testing-library/react';
export { default as userEvent } from '@testing-library/user-event';
