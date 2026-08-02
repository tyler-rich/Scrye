import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { OidcLinkCard } from './OidcLinkCard';
import { renderWithProviders, screen, waitFor } from '../../test/render';

vi.mock('../../api/oidc', async () => {
  const actual = await vi.importActual<typeof import('../../api/oidc')>('../../api/oidc');
  return {
    ...actual,
    getOidcLinkStatus: vi.fn(),
    startOidcLink: vi.fn(),
    unlinkOidcIdentity: vi.fn(),
  };
});

import {
  getOidcLinkStatus,
  startOidcLink,
  unlinkOidcIdentity,
  type OidcLinkStatus,
} from '../../api/oidc';

const mockedStatus = vi.mocked(getOidcLinkStatus);
const mockedStart = vi.mocked(startOidcLink);
const mockedUnlink = vi.mocked(unlinkOidcIdentity);

const UNLINKED: OidcLinkStatus = {
  linked: false,
  issuer: null,
  email: null,
  linked_at: null,
  last_login_at: null,
  provider_ready: true,
  display_name: 'Pocket ID',
  mfa_enrolled: false,
  mfa_delegation_warning: false,
};

const LINKED: OidcLinkStatus = {
  ...UNLINKED,
  linked: true,
  issuer: 'https://idp.example',
  email: 'admin@example',
  linked_at: '2026-08-01T10:00:00',
  last_login_at: '2026-08-02T09:00:00',
};

/** Replace `window.location` so navigation attempts are observable, not fatal. */
function stubLocation(search = ''): { assign: ReturnType<typeof vi.fn> } {
  const assign = vi.fn();
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { assign, search, pathname: '/settings', href: `/settings${search}` },
  });
  return { assign };
}

describe('OidcLinkCard', () => {
  let replaceState: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    stubLocation();
    replaceState = vi.fn();
    vi.spyOn(window.history, 'replaceState').mockImplementation(replaceState);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders no subject field or value anywhere', async () => {
    // The feature exists precisely so nobody has to see or type a subject.
    mockedStatus.mockResolvedValue(LINKED);
    const { container } = renderWithProviders(<OidcLinkCard enabled />);
    await screen.findByText('Linked');
    expect(container.textContent?.toLowerCase()).not.toContain('subject');
    expect(screen.queryByLabelText(/subject/i)).toBeNull();
  });

  it('requires the current password before linking is possible', async () => {
    mockedStatus.mockResolvedValue(UNLINKED);
    renderWithProviders(<OidcLinkCard enabled />);
    const button = await screen.findByRole('button', { name: /link my account/i });
    expect(button).toBeDisabled();
  });

  it('also requires a TOTP code when the account is enrolled', async () => {
    mockedStatus.mockResolvedValue({ ...UNLINKED, mfa_enrolled: true });
    renderWithProviders(<OidcLinkCard enabled />);
    const password = await screen.findByLabelText(/current password/i);
    const { default: userEvent } = await import('@testing-library/user-event');
    await userEvent.type(password, 'a-password');
    // Password alone is not enough while a second factor exists.
    expect(screen.getByRole('button', { name: /link my account/i })).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/authentication code/i), '123456');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /link my account/i })).toBeEnabled(),
    );
  });

  it('warns about MFA delegation before the user creates the bypass path', async () => {
    mockedStatus.mockResolvedValue({
      ...UNLINKED,
      mfa_enrolled: true,
      mfa_delegation_warning: true,
    });
    renderWithProviders(<OidcLinkCard enabled />);
    expect(await screen.findByText(/will not ask for your Scrye MFA code/i)).toBeInTheDocument();
  });

  it('navigates to the provider URL the backend returns', async () => {
    const { assign } = stubLocation();
    mockedStatus.mockResolvedValue(UNLINKED);
    mockedStart.mockResolvedValue({ authorization_url: 'https://idp.example/authorize?state=abc' });
    renderWithProviders(<OidcLinkCard enabled />);
    const { default: userEvent } = await import('@testing-library/user-event');
    await userEvent.type(await screen.findByLabelText(/current password/i), 'a-password');
    await userEvent.click(screen.getByRole('button', { name: /link my account/i }));
    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith('https://idp.example/authorize?state=abc'),
    );
    expect(mockedStart).toHaveBeenCalledWith({ current_password: 'a-password' });
  });

  it('shows the callback success outcome and clears it from the URL', async () => {
    stubLocation('?oidc_link=success');
    mockedStatus.mockResolvedValue(LINKED);
    renderWithProviders(<OidcLinkCard enabled />);
    expect(await screen.findByText(/your account is now linked/i)).toBeInTheDocument();
    expect(replaceState).toHaveBeenCalled();
  });

  it('explains a session-mismatch failure from the callback', async () => {
    stubLocation('?oidc_link_error=session_mismatch');
    mockedStatus.mockResolvedValue(UNLINKED);
    renderWithProviders(<OidcLinkCard enabled />);
    expect(
      await screen.findByText(/did not complete under the account that started it/i),
    ).toBeInTheDocument();
  });

  it('shows when a link was last used, the one hint that it may be stale', async () => {
    mockedStatus.mockResolvedValue({ ...LINKED, last_login_at: null });
    renderWithProviders(<OidcLinkCard enabled />);
    expect(await screen.findByText(/last used never/i)).toBeInTheDocument();
    expect(screen.getByText(/re-link runbook/i)).toBeInTheDocument();
  });

  it('sends fresh credentials when unlinking', async () => {
    mockedStatus.mockResolvedValue(LINKED);
    mockedUnlink.mockResolvedValue(undefined);
    renderWithProviders(<OidcLinkCard enabled />);
    const { default: userEvent } = await import('@testing-library/user-event');
    await userEvent.type(await screen.findByLabelText(/current password/i), 'a-password');
    await userEvent.click(screen.getByRole('button', { name: /unlink/i }));
    await waitFor(() =>
      expect(mockedUnlink).toHaveBeenCalledWith({ current_password: 'a-password' }),
    );
  });

  it('blocks linking until a provider is configured', async () => {
    mockedStatus.mockResolvedValue({ ...UNLINKED, provider_ready: false });
    renderWithProviders(<OidcLinkCard enabled={false} />);
    expect(await screen.findByText(/Enable and save an OIDC provider/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /link my account/i })).toBeDisabled();
  });
});
