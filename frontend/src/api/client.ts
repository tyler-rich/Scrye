/**
 * Minimal typed fetch wrapper for the Scrye API.
 *
 * - Sends cookies (session auth is cookie-based).
 * - Echoes the per-session CSRF token (readable `scrye_csrf` cookie) in the
 *   `X-CSRF-Token` header on state-changing requests, as the backend requires.
 * - Raises `ApiError` with the backend's `detail` message on failures.
 */

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function readCookie(name: string): string | null {
  const match = document.cookie.split('; ').find((part) => part.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

/**
 * Event dispatched when any API call returns 401 (session expired or revoked),
 * so `AuthContext` can drop the SPA back to the login screen rather than leaving
 * a stale authenticated shell whose every action fails (FE-1).
 */
export const AUTH_INVALIDATED_EVENT = 'scrye:auth-invalidated';

function notifyUnauthorized(): void {
  window.dispatchEvent(new Event(AUTH_INVALIDATED_EVENT));
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
}

/**
 * Turn a fetch `Response` into its typed payload: raise `ApiError` (carrying the
 * backend's `detail`) on failure, notify on 401, and yield `undefined` for 204.
 *
 * The lone `as T` here is the single unavoidable boundary cast of the
 * hand-written client (FE-2): `Response.json()` is typed `any`, so the client
 * trusts each call site's declared `T` rather than validating at runtime.
 * Centralizing it here removes the blind per-call casts the review flagged
 * (P3-8); a generated client or runtime guards remain the future upgrade path.
 */
async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const data = (await response.json()) as { detail?: unknown };
      if (typeof data.detail === 'string') detail = data.detail;
    } catch {
      // Non-JSON error body; keep the generic message.
    }
    if (response.status === 401) notifyUnauthorized();
    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (method !== 'GET') {
    const csrf = readCookie('scrye_csrf');
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }

  const response = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });

  return parseResponse<T>(response);
}

/**
 * POST multipart form data (file uploads), echoing the CSRF token like `api`.
 * Used for endpoints that accept an uploaded file (e.g. SBOM scans).
 */
export async function apiUpload<T>(path: string, form: FormData): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  const csrf = readCookie('scrye_csrf');
  if (csrf) headers['X-CSRF-Token'] = csrf;

  const response = await fetch(path, {
    method: 'POST',
    headers,
    credentials: 'same-origin',
    body: form,
  });

  return parseResponse<T>(response);
}
