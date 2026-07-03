import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

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

  const refresh = useCallback(async () => {
    try {
      const status = await fetchAuthStatus();
      setState({
        loading: false,
        needsSetup: status.needs_setup,
        user: status.user,
        oidc: status.oidc,
      });
    } catch {
      // Backend unreachable: treat as logged out; the dashboard shows health.
      setState({ loading: false, needsSetup: false, user: null, oidc: DEFAULT_OIDC });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

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
        await apiLogout();
        setState((prev) => ({ ...prev, loading: false, needsSetup: false, user: null }));
      },
    }),
    [state, refresh],
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
