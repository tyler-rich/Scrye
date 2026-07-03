/**
 * Minimal health API client. A fully typed client generated from the FastAPI
 * OpenAPI schema arrives in a later phase (CLAUDE.md § Coding standards); this
 * hand-written shim covers the Phase 0 skeleton's single endpoint.
 */

export interface HealthStatus {
  status: string;
  version: string;
  database: string;
}

export async function fetchHealth(): Promise<HealthStatus> {
  const response = await fetch('/healthz', { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new Error(`Health check failed: ${response.status}`);
  }
  return (await response.json()) as HealthStatus;
}
