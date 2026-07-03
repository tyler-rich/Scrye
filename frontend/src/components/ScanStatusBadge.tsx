import { Badge, Loader } from '@mantine/core';

import type { ScanStatus } from '../api/scans';

const STATUS_COLOR: Record<ScanStatus, string> = {
  queued: 'gray',
  running: 'teal',
  succeeded: 'green',
  failed: 'red',
  canceled: 'gray',
};

/** A badge for a scan's lifecycle status (spinner while still active). */
export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const active = status === 'queued' || status === 'running';
  return (
    <Badge
      color={STATUS_COLOR[status]}
      variant={active ? 'light' : 'filled'}
      leftSection={active ? <Loader size={10} color={STATUS_COLOR[status]} /> : undefined}
    >
      {status}
    </Badge>
  );
}
