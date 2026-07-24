import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthProvider, useAuth } from './AuthContext';
import { AUTH_INVALIDATED_EVENT } from '../api/client';
import { act, renderWithProviders, screen, userEvent, waitFor } from '../test/render';

// The provider's only network call on mount is `fetchAuthStatus`; mocking the
// whole auth module lets each test hold that request open and control exactly
// when it resolves relative to an invalidation.
vi.mock('../api/auth', () => ({
  fetchAuthStatus: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  setupFirstAdmin: vi.fn(),
  verifyMfa: vi.fn(),
}));

import { fetchAuthStatus, logout as apiLogout, type AuthStatus, type UserInfo } from '../api/auth';

const mockedFetchAuthStatus = vi.mocked(fetchAuthStatus);
const mockedLogout = vi.mocked(apiLogout);

const USER: UserInfo = {
  id: 1,
  username: 'operator',
  role: 'operator',
  is_active: true,
  mfa_enabled: false,
  created_at: '2026-07-24T00:00:00Z',
  last_login_at: null,
};

const AUTHENTICATED_STATUS: AuthStatus = {
  needs_setup: false,
  authenticated: true,
  user: USER,
  oidc: { enabled: false, display_name: 'OIDC' },
};

/** A promise whose resolution the test drives, standing in for a slow request. */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** Settle the pending status request and let React apply the resulting state. */
async function settle<T>(pending: { promise: Promise<T>; resolve: (value: T) => void }, value: T) {
  await act(async () => {
    pending.resolve(value);
    await pending.promise;
  });
}

/** Renders the session as text, plus the two actions the races involve. */
function SessionProbe() {
  const { loading, user, logout, refresh } = useAuth();
  return (
    <>
      <span data-testid="session">
        {loading ? 'loading' : user ? `signed-in:${user.username}` : 'signed-out'}
      </span>
      <button type="button" onClick={() => void refresh()}>
        Refresh
      </button>
      <button type="button" onClick={() => void logout()}>
        Sign out
      </button>
    </>
  );
}

function renderProvider() {
  return renderWithProviders(
    <AuthProvider>
      <SessionProbe />
    </AuthProvider>,
  );
}

function session(): string {
  return screen.getByTestId('session').textContent ?? '';
}

describe('AuthProvider — P3-4 refresh/invalidation sequencing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not restore the session when a refresh resolves after an invalidation', async () => {
    // The mount refresh is answered by the backend *before* the credential is
    // revoked, but lands after — the P3-4 race.
    const status = deferred<AuthStatus>();
    mockedFetchAuthStatus.mockReturnValue(status.promise);

    renderProvider();
    expect(session()).toBe('loading');

    // A 401 on some other call drops the shell back to the login screen.
    act(() => {
      window.dispatchEvent(new Event(AUTH_INVALIDATED_EVENT));
    });

    // Only now does the stale status arrive, carrying a user.
    await settle(status, AUTHENTICATED_STATUS);

    // Invariant: a logged-out session is never restored by a late refresh.
    await waitFor(() => expect(session()).toBe('signed-out'));
  });

  it('does not restore the session when a refresh resolves after logout', async () => {
    const mount = deferred<AuthStatus>();
    mockedFetchAuthStatus.mockReturnValue(mount.promise);
    mockedLogout.mockResolvedValue(undefined);

    renderProvider();

    // Sign in via the mount refresh so there is a live session to tear down.
    await settle(mount, AUTHENTICATED_STATUS);
    await waitFor(() => expect(session()).toBe('signed-in:operator'));

    // A second status request is in flight when the operator signs out.
    const inFlight = deferred<AuthStatus>();
    mockedFetchAuthStatus.mockReturnValue(inFlight.promise);
    await userEvent.click(screen.getByRole('button', { name: /refresh/i }));
    await userEvent.click(screen.getByRole('button', { name: /sign out/i }));
    await waitFor(() => expect(session()).toBe('signed-out'));

    await settle(inFlight, AUTHENTICATED_STATUS);

    expect(session()).toBe('signed-out');
  });

  it('still applies a refresh that resolves with no invalidation in between', async () => {
    const status = deferred<AuthStatus>();
    mockedFetchAuthStatus.mockReturnValue(status.promise);

    renderProvider();

    await settle(status, AUTHENTICATED_STATUS);

    await waitFor(() => expect(session()).toBe('signed-in:operator'));
  });
});
