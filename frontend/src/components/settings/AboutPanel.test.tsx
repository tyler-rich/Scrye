import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AboutPanel } from './AboutPanel';
import { renderWithProviders, screen, waitFor } from '../../test/render';

// The panel's only network call is the About GET.
vi.mock('../../api/settings', () => ({
  getAbout: vi.fn(),
}));

import { getAbout, type AboutInfo, type MasterKeyInfo } from '../../api/settings';

const mockedGetAbout = vi.mocked(getAbout);

const BASE_ABOUT: AboutInfo = {
  app_name: 'Scrye',
  version: '0.3.0',
  status: 'healthy',
  database: 'ok',
  python_version: '3.14.6',
  platform: 'Linux-6.1',
  user_count: 1,
  scan_count: 0,
  oidc_enabled: false,
  scanners: [],
  master_key: null,
};

function aboutWith(master_key: MasterKeyInfo | null): AboutInfo {
  return { ...BASE_ABOUT, master_key };
}

/** Wait for the panel to finish its initial load. */
async function renderLoaded(about: AboutInfo) {
  mockedGetAbout.mockResolvedValue(about);
  renderWithProviders(<AboutPanel />);
  await waitFor(() => expect(screen.getByText('Scanners')).toBeInTheDocument());
}

describe('AboutPanel — version stat', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the version the API reports', async () => {
    // The number itself is the backend's (`app.__version__`, kept in step with
    // pyproject/package.json by backend/tests/test_version.py). What this pins
    // is the wiring: the tab shows the served value, not a frontend literal
    // that can drift a release behind.
    await renderLoaded(BASE_ABOUT);

    // Bound to its own stat card: the Scanners table has a "Version" column
    // header too, so the label alone does not identify the app-version stat.
    const value = screen.getByText('0.3.0');
    expect(value.previousElementSibling).toHaveTextContent('Version');
  });
});

/**
 * The master-key row is the only conditional logic on this tab, and inverting it
 * is not a cosmetic bug: it would tell a deployment that supplied a Docker secret
 * — the recommended posture — that its key was auto-generated on the data volume,
 * and vice versa. That is wrong security guidance shown to the operators who did
 * the right thing, so each branch is pinned to text the other one cannot produce.
 */
describe('AboutPanel — master-key row', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('reports an auto-generated key with the at-rest separation advice', async () => {
    await renderLoaded(aboutWith({ source: 'auto_generated', path: '/data/app_secret_key' }));

    expect(screen.getByText('Master key')).toBeInTheDocument();
    expect(screen.getByText(/Auto-generated at/)).toBeInTheDocument();
    expect(screen.getByText('/data/app_secret_key')).toBeInTheDocument();
    expect(
      screen.getByText(/a Docker secret gives stronger at-rest separation/),
    ).toBeInTheDocument();
    // Must not claim the operator supplied the key themselves.
    expect(screen.queryByText(/Supplied as a secret file/)).not.toBeInTheDocument();
  });

  it('reports a supplied secret file without the separation advice', async () => {
    await renderLoaded(aboutWith({ source: 'secret_file', path: '/run/secrets/app_secret_key' }));

    expect(screen.getByText('Master key')).toBeInTheDocument();
    expect(screen.getByText(/Supplied as a secret file at/)).toBeInTheDocument();
    expect(screen.getByText('/run/secrets/app_secret_key')).toBeInTheDocument();
    // The advice is specific to the generated case: this deployment already has
    // the key and the data on separate mounts.
    expect(
      screen.queryByText(/a Docker secret gives stronger at-rest separation/),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/Auto-generated at/)).not.toBeInTheDocument();
  });

  it.each([
    ['auto_generated', '/data/app_secret_key', /back this up/],
    ['secret_file', '/run/secrets/app_secret_key', /keep your copy backed up/],
  ] as const)('tells the operator to back the key up (%s)', async (source, path, guidance) => {
    // True of both sources, in each one's own wording: losing the key makes every
    // stored secret unrecoverable however the key got there.
    await renderLoaded(aboutWith({ source, path }));

    expect(screen.getByText(guidance)).toBeInTheDocument();
  });

  it('omits the row entirely when the response carries no master key', async () => {
    // The API omits the field for non-admins, and when no key resolves at all.
    await renderLoaded(aboutWith(null));

    expect(screen.queryByText('Master key')).not.toBeInTheDocument();
    expect(screen.queryByText(/Auto-generated at/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Supplied as a secret file/)).not.toBeInTheDocument();
    // The rest of the tab still renders.
    expect(screen.getByText(/Python 3\.14\.6/)).toBeInTheDocument();
  });
});
