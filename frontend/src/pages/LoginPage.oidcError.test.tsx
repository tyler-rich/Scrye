import { Profiler } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { renderWithProviders, screen } from '../test/render';

// Same shape as LoginPage.httpsAlert.test.tsx: the real AuthProvider does
// network work, so the context is stubbed and the test drives only the query
// string under assertion.
const authState = {
  login: vi.fn(),
  verifyMfa: vi.fn(),
  refresh: vi.fn(),
  oidc: { enabled: false, display_name: 'OIDC' },
  insecureTransport: false,
};

vi.mock('../auth/AuthContext', () => ({
  useAuth: () => authState,
}));

const { LoginPage } = await import('./LoginPage');

/** Put the browser on `/login` with the given query string. */
function locateAt(search: string) {
  window.history.replaceState({}, '', `/login${search}`);
}

describe('LoginPage — OIDC callback failure banner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    locateAt('');
  });

  it('maps a known oidc_error code to its explanation and strips the parameter', () => {
    locateAt('?oidc_error=discovery');
    renderWithProviders(<LoginPage />);

    expect(screen.getByText('Could not reach the identity provider.')).toBeInTheDocument();
    // Stripped so a reload doesn't replay a banner for a sign-in already over.
    expect(window.location.search).toBe('');
    // The form is still usable — the banner explains, it doesn't block.
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('falls back to a generic message for a code it does not know', () => {
    locateAt('?oidc_error=something_new');
    renderWithProviders(<LoginPage />);

    expect(screen.getByText('OIDC sign-in failed.')).toBeInTheDocument();
    expect(window.location.search).toBe('');
  });

  it('shows nothing and leaves the URL alone when there is no oidc_error', () => {
    locateAt('?next=%2Fscans');
    renderWithProviders(<LoginPage />);

    expect(screen.queryByText(/OIDC sign-in failed/i)).not.toBeInTheDocument();
    expect(screen.queryByText('Could not reach the identity provider.')).not.toBeInTheDocument();
    // No oidc_error means nothing to strip: an unrelated parameter survives.
    expect(window.location.search).toBe('?next=%2Fscans');
  });

  it('renders the banner in the first commit, not in a cascading second one', () => {
    locateAt('?oidc_error=provider');

    // One entry per commit, recording whether that commit had the banner. The
    // message is knowable from the URL before anything renders, so the very
    // first commit must already carry it — deriving it in an effect instead
    // would paint the bare form once and then correct itself.
    const bannerPerCommit: boolean[] = [];
    renderWithProviders(
      <Profiler
        id="login"
        onRender={() =>
          bannerPerCommit.push(
            document.body.textContent?.includes('The identity provider reported an error.') ??
              false,
          )
        }
      >
        <LoginPage />
      </Profiler>,
    );

    expect(bannerPerCommit.length).toBeGreaterThan(0);
    expect(bannerPerCommit[0]).toBe(true);
    expect(bannerPerCommit).not.toContain(false);
  });
});
