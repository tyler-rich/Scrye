import { describe, expect, it, vi } from 'vitest';

import { renderWithProviders, screen } from '../test/render';

// The login form itself does network work through the real AuthProvider; stub
// the context so the test controls exactly the transport state under assertion.
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

describe('LoginPage — HTTPS-enforcement banner', () => {
  it('says nothing about the transport when the page is on HTTPS', () => {
    authState.insecureTransport = false;
    renderWithProviders(<LoginPage />);

    expect(screen.queryByText(/Sign-in requires HTTPS/i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('explains that a plain-HTTP origin — not the credentials — is the problem', () => {
    authState.insecureTransport = true;
    renderWithProviders(<LoginPage />);

    expect(screen.getByText(/Sign-in requires HTTPS/i)).toBeInTheDocument();
    // The whole point: the user must not read this as "wrong password".
    expect(screen.getByText(/not a problem with your username or password/i)).toBeInTheDocument();
    // The banner is shown up-front, before anything is submitted, so it cannot
    // reveal whether any particular credential was valid.
    expect(authState.login).not.toHaveBeenCalled();
  });

  it('names the exact operator remedies, including the opt-out variable and value', () => {
    authState.insecureTransport = true;
    renderWithProviders(<LoginPage />);

    expect(screen.getByText('SCRYE_SESSION_COOKIE_SECURE=false')).toBeInTheDocument();
    expect(screen.getByText('X-Forwarded-Proto: https')).toBeInTheDocument();
    expect(screen.getByText('SCRYE_FORWARDED_ALLOW_IPS')).toBeInTheDocument();
  });

  it('still offers the sign-in form, so a fixed deployment needs no reload dance', () => {
    authState.insecureTransport = true;
    renderWithProviders(<LoginPage />);

    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });
});
