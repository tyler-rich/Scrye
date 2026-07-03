import { Badge } from '@mantine/core';

import type { Severity } from '../api/scans';

/** Mantine color per normalized severity, shared across scan views. */
// eslint-disable-next-line react-refresh/only-export-components -- small shared color map co-located with its badge
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'yellow',
  low: 'blue',
  negligible: 'gray',
  unknown: 'gray',
};

/** A colored badge for a single severity level. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge color={SEVERITY_COLOR[severity]} variant="filled" radius="sm">
      {severity}
    </Badge>
  );
}
