import { describe, expect, it } from 'vitest';

import { safeHttpUrl } from './url';

describe('safeHttpUrl', () => {
  it('allows valid https URLs', () => {
    expect(safeHttpUrl('https://nvd.nist.gov/vuln/detail/CVE-2024-0001')).toBe(
      'https://nvd.nist.gov/vuln/detail/CVE-2024-0001',
    );
  });

  it('allows valid http URLs', () => {
    expect(safeHttpUrl('http://example.com/advisory')).toBe('http://example.com/advisory');
  });

  it('rejects javascript: URLs', () => {
    expect(safeHttpUrl('javascript:alert(1)')).toBeNull();
  });

  it('rejects javascript: URLs regardless of surrounding whitespace or case', () => {
    expect(safeHttpUrl('  JavaScript:alert(document.cookie)  ')).toBeNull();
  });

  it('rejects data: URLs', () => {
    expect(safeHttpUrl('data:text/html,<script>alert(1)</script>')).toBeNull();
  });

  it('rejects vbscript: URLs', () => {
    expect(safeHttpUrl('vbscript:msgbox(1)')).toBeNull();
  });

  it('rejects relative URLs', () => {
    expect(safeHttpUrl('/scans/123')).toBeNull();
    expect(safeHttpUrl('advisory/detail')).toBeNull();
  });

  it('rejects empty and nullish input', () => {
    expect(safeHttpUrl('')).toBeNull();
    expect(safeHttpUrl(null)).toBeNull();
    expect(safeHttpUrl(undefined)).toBeNull();
  });
});
