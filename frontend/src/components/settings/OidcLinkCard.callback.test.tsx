import { Profiler } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { act, renderWithProviders, screen } from '../../test/render';

vi.mock('../../api/oidc', async () => {
  const actual = await vi.importActual<typeof import('../../api/oidc')>('../../api/oidc');
  return {
    ...actual,
    getOidcLinkStatus: vi.fn(),
    startOidcLink: vi.fn(),
    unlinkOidcIdentity: vi.fn(),
  };
});

import { OidcLinkCard } from './OidcLinkCard';
import { getOidcLinkStatus, type OidcLinkStatus } from '../../api/oidc';

const mockedGetStatus = vi.mocked(getOidcLinkStatus);

const STATUS: OidcLinkStatus = {
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

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** Put the browser on the settings page with the given query string. */
function locateAt(search: string) {
  window.history.replaceState({}, '', `/settings${search}`);
}

describe('OidcLinkCard — link-callback outcome banners', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetStatus.mockResolvedValue(STATUS);
  });

  afterEach(() => {
    locateAt('');
  });

  it('shows the success notice and strips the parameter', async () => {
    locateAt('?oidc_link=success');
    renderWithProviders(<OidcLinkCard enabled />);

    expect(await screen.findByText(/Your account is now linked/i)).toBeInTheDocument();
    expect(window.location.search).toBe('');
  });

  it('maps a known failure code and strips the parameter', async () => {
    locateAt('?oidc_link_error=identity_in_use');
    renderWithProviders(<OidcLinkCard enabled />);

    expect(
      await screen.findByText(/already linked to a different Scrye user/i),
    ).toBeInTheDocument();
    expect(window.location.search).toBe('');
  });

  it('falls back to generic wording for codes it does not know, on either parameter', async () => {
    locateAt('?oidc_link=brand_new&oidc_link_error=also_brand_new');
    renderWithProviders(<OidcLinkCard enabled />);

    // Both parameters are honoured independently, as they were before.
    expect(await screen.findByText('Linking finished.')).toBeInTheDocument();
    expect(screen.getByText('Linking failed.')).toBeInTheDocument();
    expect(window.location.search).toBe('');
  });

  it('shows no banner and leaves an unrelated query string alone', async () => {
    locateAt('?tab=auth');
    renderWithProviders(<OidcLinkCard enabled />);

    expect(await screen.findByText(/Your linked identity/i)).toBeInTheDocument();
    expect(screen.queryByText(/Linking finished/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Linking failed/i)).not.toBeInTheDocument();
    expect(window.location.search).toBe('?tab=auth');
  });

  it('reads the outcome without spending a commit on it', async () => {
    locateAt('?oidc_link=success');
    // The card renders nothing until the status fetch lands, so hold it open:
    // every commit counted here is one the component made *before* it had any
    // data to show. Reading the query string is pure — it needs none of them.
    const pendingStatus = deferred<OidcLinkStatus>();
    mockedGetStatus.mockReturnValue(pendingStatus.promise);

    let commits = 0;
    renderWithProviders(
      <Profiler id="oidc-link" onRender={() => (commits += 1)}>
        <OidcLinkCard enabled />
      </Profiler>,
    );

    expect(commits).toBe(1);

    await act(async () => {
      pendingStatus.resolve(STATUS);
      await pendingStatus.promise;
    });

    expect(await screen.findByText(/Your account is now linked/i)).toBeInTheDocument();
  });
});
