/** Small array helpers shared across views. */

/**
 * Shallow, order-sensitive equality of two arrays.
 *
 * Used to tell whether a locally-edited draft still matches the last value we
 * synced from the server, so a background poll can refresh the draft only when
 * the user hasn't touched it (L16 / P2-1).
 */
export function sameItems<T>(a: readonly T[], b: readonly T[]): boolean {
  if (a === b) return true;
  if (a.length !== b.length) return false;
  return a.every((item, index) => item === b[index]);
}
