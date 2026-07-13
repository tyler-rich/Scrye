import { describe, expect, it } from 'vitest';

import { sameItems } from './arrays';

describe('sameItems', () => {
  it('is true for the same reference', () => {
    const a = ['x', 'y'];
    expect(sameItems(a, a)).toBe(true);
  });

  it('is true for equal ordered contents', () => {
    expect(sameItems(['a', 'b'], ['a', 'b'])).toBe(true);
    expect(sameItems([], [])).toBe(true);
  });

  it('is false when length differs', () => {
    expect(sameItems(['a'], ['a', 'b'])).toBe(false);
  });

  it('is false when order differs', () => {
    expect(sameItems(['a', 'b'], ['b', 'a'])).toBe(false);
  });

  it('is false when an element differs', () => {
    expect(sameItems(['a', 'b'], ['a', 'c'])).toBe(false);
  });
});
