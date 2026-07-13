/**
 * Safe rendering of externally-derived URLs (FE-9 / account-takeover chain).
 *
 * Finding `primary_url` values come from the scanners' vulnerability databases,
 * which are attacker-influenceable (a crafted package/advisory can carry an
 * arbitrary URL). Rendering one straight into an `<a href>` lets a
 * `javascript:` (or `data:`, `vbscript:`) URL execute on click. This helper
 * gates a URL to the `http:`/`https:` schemes so callers can render only
 * conforming URLs as links and fall back to plain text otherwise.
 */

/**
 * Return `url` if it is a well-formed absolute `http:`/`https:` URL, else null.
 *
 * Anything else — a `javascript:`/`data:`/`vbscript:` scheme, a relative or
 * malformed URL — returns null so the caller renders it as inert text rather
 * than a clickable link.
 */
export function safeHttpUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  let parsed: URL;
  try {
    parsed = new URL(url.trim());
  } catch {
    // Relative or otherwise unparseable URLs have no base here — reject them.
    return null;
  }
  return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? url : null;
}
