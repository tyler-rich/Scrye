import { describe, expect, it } from 'vitest';

import { StatusLoader } from './StatusLoader';
import { renderWithProviders, screen } from '../test/render';

describe('StatusLoader — P3-6 accessible loading indicator', () => {
  it('exposes a role="status" live region with a spoken label', () => {
    renderWithProviders(<StatusLoader label="Loading scans" />);

    const status = screen.getByRole('status');
    expect(status).toBeInTheDocument();
    expect(status).toHaveAttribute('aria-live', 'polite');
    expect(status).toHaveTextContent('Loading scans');
  });

  it('defaults to a generic "Loading" label', () => {
    renderWithProviders(<StatusLoader />);
    expect(screen.getByRole('status')).toHaveTextContent('Loading');
  });
});
