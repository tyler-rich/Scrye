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

import {
  fetchAuthStatus,
  login as apiLogin,
  logout as apiLogout,
  setupFirstAdmin,
  verifyMfa as apiVerifyMfa,
  type AuthStatus,
  type LoginResponse,
  type UserInfo,
} from '../api/auth';

const mockedFetchAuthStatus = vi.mocked(fetchAuthStatus);
const mockedLogout = vi.mocked(apiLogout);
const mockedLogin = vi.mocked(apiLogin);
const mockedVerifyMfa = vi.mocked(apiVerifyMfa);
const mockedSetup = vi.mocked(setupFirstAdmin);

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

/** What the backend answers for a request made before the credential existed. */
const ANONYMOUS_STATUS: AuthStatus = {
  needs_setup: false,
  authenticated: false,
  user: null,
  oidc: { enabled: false, display_name: 'OIDC' },
};

const LOGIN_RESULT: LoginResponse = {
  user: USER,
  csrf_token: 'csrf',
  mfa_required: false,
  mfa_token: null,
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

/** Renders the session as text, plus the actions the races involve. */
function SessionProbe() {
  const { loading, user, login, verifyMfa, setup, logout, refresh } = useAuth();
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
      <button type="button" onClick={() => void login('operator', 'pw')}>
        Sign in
      </button>
      <button type="button" onClick={() => void verifyMfa('mfa-token', '123456')}>
        Verify MFA
      </button>
      <button type="button" onClick={() => void setup('operator', 'pw')}>
        Create admin
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

describe('AuthProvider — #83 authentication vs. an in-flight refresh', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  /**
   * The mirror of the P3-4 race: a status request answered *before* the
   * credential existed — so it carries `user: null` — resolves *after* the
   * operator has authenticated, and must not clear the new session.
   */
  async function authenticateWithStaleRefreshInFlight(action: RegExp) {
    // Settle the mount refresh first: the login screen is only reachable once
    // `loading` is false, so the stale request is a later, overlapping one.
    const mount = deferred<AuthStatus>();
    mockedFetchAuthStatus.mockReturnValue(mount.promise);

    renderProvider();
    await settle(mount, ANONYMOUS_STATUS);
    await waitFor(() => expect(session()).toBe('signed-out'));

    // A status request is in flight when the operator authenticates.
    const stale = deferred<AuthStatus>();
    mockedFetchAuthStatus.mockReturnValue(stale.promise);
    await userEvent.click(screen.getByRole('button', { name: /refresh/i }));

    await userEvent.click(screen.getByRole('button', { name: action }));
    await waitFor(() => expect(session()).toBe('signed-in:operator'));

    // Only now does the pre-login status arrive, carrying no user.
    await settle(stale, ANONYMOUS_STATUS);

    // Invariant: a completed authentication is never undone by a refresh that
    // was already in flight when it completed.
    expect(session()).toBe('signed-in:operator');
  }

  it('does not clear the session when a pre-login refresh resolves after login', async () => {
    mockedLogin.mockResolvedValue(LOGIN_RESULT);
    await authenticateWithStaleRefreshInFlight(/sign in/i);
  });

  it('does not clear the session when a pre-login refresh resolves after MFA verification', async () => {
    mockedVerifyMfa.mockResolvedValue(LOGIN_RESULT);
    await authenticateWithStaleRefreshInFlight(/verify mfa/i);
  });

  it('does not clear the session when a pre-setup refresh resolves after first-admin setup', async () => {
    mockedSetup.mockResolvedValue(LOGIN_RESULT);
    await authenticateWithStaleRefreshInFlight(/create admin/i);
  });

  it('still lets a refresh started after login update the session', async () => {
    mockedLogin.mockResolvedValue(LOGIN_RESULT);

    const mount = deferred<AuthStatus>();
    mockedFetchAuthStatus.mockReturnValue(mount.promise);

    renderProvider();
    await settle(mount, ANONYMOUS_STATUS);
    await waitFor(() => expect(session()).toBe('signed-out'));

    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(session()).toBe('signed-in:operator'));

    // Superseding in-flight refreshes must not disable later ones: this one was
    // started after the sign-in, so its answer is authoritative.
    const after = deferred<AuthStatus>();
    mockedFetchAuthStatus.mockReturnValue(after.promise);
    await userEvent.click(screen.getByRole('button', { name: /refresh/i }));
    await settle(after, ANONYMOUS_STATUS);

    expect(session()).toBe('signed-out');
  });
});
