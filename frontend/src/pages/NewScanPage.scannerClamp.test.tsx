import { Profiler } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { NewScanPage } from './NewScanPage';
import { renderWithProviders, screen, userEvent, waitFor } from '../test/render';

// Same stubs as NewScanPage.test.tsx: the page's mount fetches are not what is
// under assertion here, only the target-type/scanner pairing is.
vi.mock('../api/targets', () => ({
  listRegistryOptions: vi.fn().mockResolvedValue([]),
  listGitCredentialOptions: vi.fn().mockResolvedValue([]),
}));
vi.mock('../api/settings', () => ({
  getScannerSettings: vi.fn().mockResolvedValue({
    default_severities: ['HIGH', 'CRITICAL'],
    default_ignore_unfixed: false,
  }),
}));
vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({ user: { role: 'admin' } }),
}));

/** How many scanner options are selected in the DOM right now. */
function checkedScanners(): number {
  return document.querySelectorAll('[aria-label="Scanner"] input[type="radio"]:checked').length;
}

describe('NewScanPage — scanner clamped to the target type', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('forces the only allowed scanner when the target type excludes the current one', async () => {
    const user = userEvent.setup();
    renderWithProviders(<NewScanPage />);

    // Image allows both, and starts on Trivy.
    expect(screen.getByRole('radio', { name: 'Trivy' })).toBeChecked();

    // Filesystem is Grype-only, so the Trivy selection cannot survive it.
    await user.click(screen.getByRole('radio', { name: 'Filesystem' }));
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Grype' })).toBeChecked());
    expect(screen.queryByRole('radio', { name: 'Trivy' })).not.toBeInTheDocument();

    // Repository is Trivy-only, the other direction.
    await user.click(screen.getByRole('radio', { name: 'Repository' }));
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Trivy' })).toBeChecked());
    expect(screen.queryByRole('radio', { name: 'Grype' })).not.toBeInTheDocument();
  });

  it('discards the displaced choice rather than restoring it on the way back', async () => {
    const user = userEvent.setup();
    renderWithProviders(<NewScanPage />);

    // Image → Filesystem clamps Trivy away to Grype …
    await user.click(screen.getByRole('radio', { name: 'Filesystem' }));
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Grype' })).toBeChecked());

    // … and coming back to Image, which allows both, leaves Grype selected.
    // The clamp overwrites the choice; it does not shadow it, so nothing
    // resurrects the Trivy the user is no longer on.
    await user.click(screen.getByRole('radio', { name: 'Image' }));
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Trivy' })).toBeInTheDocument());
    expect(screen.getByRole('radio', { name: 'Grype' })).toBeChecked();
    expect(screen.getByRole('radio', { name: 'Trivy' })).not.toBeChecked();
  });

  it('never commits a render in which no allowed scanner is selected', async () => {
    const user = userEvent.setup();

    // The scanner control only offers the current target type's scanners, so a
    // render carrying the previous type's scanner selects nothing at all. That
    // is what clamping in an effect commits — one frame of an empty control —
    // and what clamping alongside the target-type change avoids.
    const selectedPerCommit: number[] = [];
    renderWithProviders(
      <Profiler id="new-scan" onRender={() => selectedPerCommit.push(checkedScanners())}>
        <NewScanPage />
      </Profiler>,
    );

    await user.click(screen.getByRole('radio', { name: 'Filesystem' }));
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Grype' })).toBeChecked());

    expect(selectedPerCommit.length).toBeGreaterThan(1);
    expect(selectedPerCommit).not.toContain(0);
  });
});
