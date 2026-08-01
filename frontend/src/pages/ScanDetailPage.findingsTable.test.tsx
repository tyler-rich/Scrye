import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';

// Replace SeverityBadge with a spy so we can count how many times the findings
// table renders its rows. SEVERITY_COLOR is also exported from this module and
// imported by ScanDetailPage, so the mock must provide it too.
vi.mock('../components/SeverityBadge', () => ({
  SeverityBadge: vi.fn(() => <span data-testid="sev" />),
  SEVERITY_COLOR: {},
}));

import { FindingsTable } from './ScanDetailPage';
import { SeverityBadge } from '../components/SeverityBadge';
import { renderWithProviders, screen, userEvent, waitFor } from '../test/render';
import type { Finding } from '../api/scans';

const mockedBadge = vi.mocked(SeverityBadge);

function finding(id: number): Finding {
  return {
    id,
    finding_class: 'vulnerability',
    severity: 'high',
    vuln_id: `CVE-2026-${id}`,
    pkg_name: 'openssl',
    installed_version: '1.0.0',
    fixed_version: '1.0.1',
    title: 'Example',
    description: null,
    location: null,
    primary_url: null,
  };
}

// Stable reference so a parent re-render passes identical props to the memoized
// table — the whole point of the memo boundary.
const FINDINGS = [finding(1), finding(2)];

/** Re-renders on an unrelated state change, mimicking a tag-editor keystroke or
 * a poll `setScan` in the real page. */
function Harness() {
  const [n, setN] = useState(0);
  return (
    <>
      <button onClick={() => setN((x) => x + 1)}>bump {n}</button>
      <FindingsTable findings={FINDINGS} findingsTotal={2} findingsLoading={false} findingsLoaded />
    </>
  );
}

describe('ScanDetailPage — P3-5 memoized findings table', () => {
  it('does not re-render its rows when unrelated parent state changes', async () => {
    const user = userEvent.setup();
    renderWithProviders(<Harness />);

    // One SeverityBadge per finding on the initial render.
    const initialCalls = mockedBadge.mock.calls.length;
    expect(initialCalls).toBe(FINDINGS.length);

    // An unrelated parent re-render (props to the memoized table are unchanged)
    // must not re-render the rows.
    await user.click(screen.getByRole('button'));
    await waitFor(() => expect(screen.getByRole('button')).toHaveTextContent('bump 1'));

    expect(mockedBadge.mock.calls.length).toBe(initialCalls);
  });
});
