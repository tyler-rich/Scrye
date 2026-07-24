import { Loader, VisuallyHidden, type LoaderProps } from '@mantine/core';

export interface StatusLoaderProps extends LoaderProps {
  /** Screen-reader announcement for the loading state. */
  label?: string;
}

/**
 * A Mantine `Loader` wrapped in a `role="status"` live region with visually
 * hidden text. A bare `Loader` renders only an SVG spinner, so assistive tech
 * announces nothing while content loads; the live region gives it a spoken
 * label (P3-6).
 */
export function StatusLoader({ label = 'Loading', ...props }: StatusLoaderProps) {
  return (
    <span role="status" aria-live="polite">
      <Loader {...props} />
      <VisuallyHidden>{label}</VisuallyHidden>
    </span>
  );
}
