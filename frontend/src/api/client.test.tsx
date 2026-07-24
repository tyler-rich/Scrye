import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { api, ApiError, apiUpload, AUTH_INVALIDATED_EVENT } from './client';

// The client reaches for `document.cookie`, `window`, and `fetch`; jsdom (this
// `.test.tsx` runs under the jsdom project) supplies the first two, and `fetch`
// is stubbed per test.

function jsonResponse(status: number, body: unknown): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('api client — P3-8 response handling', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('parses and returns a JSON body on success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(200, { id: 7, name: 'ok' })));
    const result = await api<{ id: number; name: string }>('/api/thing');
    expect(result).toEqual({ id: 7, name: 'ok' });
  });

  it('returns undefined for a 204 No Content', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(204, null)));
    const result = await api<void>('/api/thing', { method: 'DELETE' });
    expect(result).toBeUndefined();
  });

  it('throws ApiError carrying the backend detail on failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(400, { detail: 'bad input' })));
    await expect(api('/api/thing', { method: 'POST', body: {} })).rejects.toMatchObject({
      name: 'ApiError',
      status: 400,
      message: 'bad input',
    });
  });

  it('dispatches the auth-invalidated event on a 401 (via apiUpload too)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(401, { detail: 'expired' })));
    const onInvalidated = vi.fn();
    window.addEventListener(AUTH_INVALIDATED_EVENT, onInvalidated);
    try {
      await expect(apiUpload('/api/scans/sbom', new FormData())).rejects.toBeInstanceOf(ApiError);
      expect(onInvalidated).toHaveBeenCalledTimes(1);
    } finally {
      window.removeEventListener(AUTH_INVALIDATED_EVENT, onInvalidated);
    }
  });
});
