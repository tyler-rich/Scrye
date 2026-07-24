import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type { ReactNode } from 'react';

import { AUTH_INVALIDATED_EVENT } from '../api/client';
import { createLatestGuard } from '../lib/latest';
import {
  fetchAuthStatus,
  login as apiLogin,
  logout as apiLogout,
  setupFirstAdmin,
  verifyMfa as apiVerifyMfa,
  type LoginResponse,
  type OidcStatus,
  type UserInfo,
} from '../api/auth';

interface AuthState {
  loading: boolean;
  needsSetup: boolean;
  user: UserInfo | null;
  oidc: OidcStatus;
}

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<LoginResponse>;
  verifyMfa: (mfaToken: string, code: string) => Promise<LoginResponse>;
  setup: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const DEFAULT_OIDC: OidcStatus = { enabled: false, display_name: 'OIDC' };

const AuthContext = createContext<AuthContextValue | null>(null);

/** Provides login state and auth actions to the whole SPA. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    loading: true,
    needsSetup: false,
    user: null,
    oidc: DEFAULT_OIDC,
  });

  // Session-lifecycle invariant (P3-4): once the session has been invalidated —
  // a 401 from any API call, or an explicit logout — no auth state written by a
  // request that was *already in flight at that moment* may restore `user`. A
  // logged-out session is only re-entered by a fresh authentication. Without
  // this, a `fetchAuthStatus` answered just before revocation but resolving just
  // after it would flash the authenticated shell back over the login screen.
  // `sessionGeneration` is bumped by every invalidation; `refresh()` captures it
  // before fetching and compares afterwards.
  const sessionGeneration = useRef(0);

  const invalidateSession = useCallback(() => {
    sessionGeneration.current += 1;
  }, []);

  // Separately, two overlapping `refresh()` calls can resolve out of order, so
  // the older one must not overwrite the newer one's result (the same
  // latest-wins guard the history/findings fetches use).
  const refreshGuard = useRef(createLatestGuard());

  const refresh = useCallback(async () => {
    const token = refreshGuard.current.begin();
    const generation = sessionGeneration.current;
    try {
      const status = await fetchAuthStatus();
      if (!refreshGuard.current.isCurrent(token)) return;
      // Invalidated mid-flight: keep the fresh setup/OIDC facts (they don't
      // depend on the session) but never the user this response was answered
      // with — the session it belonged to is gone.
      const invalidated = sessionGeneration.current !== generation;
      setState({
        loading: false,
        needsSetup: status.needs_setup,
        user: invalidated ? null : status.user,
        oidc: status.oidc,
      });
    } catch {
      if (!refreshGuard.current.isCurrent(token)) return;
      // Backend unreachable: treat as logged out; the dashboard shows health.
      setState({ loading: false, needsSetup: false, user: null, oidc: DEFAULT_OIDC });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // When any API call reports 401, drop the authenticated shell back to the
  // login screen instead of leaving a stale session where every action fails.
  useEffect(() => {
    const onInvalidated = () => {
      invalidateSession();
      setState((prev) => (prev.user ? { ...prev, loading: false, user: null } : prev));
    };
    window.addEventListener(AUTH_INVALIDATED_EVENT, onInvalidated);
    return () => window.removeEventListener(AUTH_INVALIDATED_EVENT, onInvalidated);
  }, [invalidateSession]);

  const value = useMemo<AuthContextValue>(
    () => ({
      ...state,
      refresh,
      login: async (username, password) => {
        const result = await apiLogin(username, password);
        if (result.user) {
          setState((prev) => ({ ...prev, loading: false, needsSetup: false, user: result.user }));
        }
        return result;
      },
      verifyMfa: async (mfaToken, code) => {
        const result = await apiVerifyMfa(mfaToken, code);
        if (result.user) {
          setState((prev) => ({ ...prev, loading: false, needsSetup: false, user: result.user }));
        }
        return result;
      },
      setup: async (username, password) => {
        const result = await setupFirstAdmin(username, password);
        setState((prev) => ({ ...prev, loading: false, needsSetup: false, user: result.user }));
      },
      logout: async () => {
        // Bump before the request: any refresh already in flight belongs to the
        // session being torn down and must not write its user back afterwards.
        invalidateSession();
        await apiLogout();
        setState((prev) => ({ ...prev, loading: false, needsSetup: false, user: null }));
      },
    }),
    [state, refresh, invalidateSession],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/** Access the auth context; must be used under `AuthProvider`. */
// eslint-disable-next-line react-refresh/only-export-components -- standard context pattern: hook co-located with its provider
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
