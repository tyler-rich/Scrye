// Vitest setup for the jsdom project (component/page render tests).
//
// - Registers the jest-dom matchers (`toBeInTheDocument`, `toHaveTextContent`,
//   …) on Vitest's `expect`.
// - Unmounts any rendered tree after each test so suites stay isolated.
// - Polyfills the browser APIs Mantine reaches for that jsdom does not implement
//   (`matchMedia`, `ResizeObserver`, `scrollIntoView`), so components render
//   without throwing.
//
// This file is loaded only by the `jsdom` project (see `vite.config.ts`); the
// Node `*.test.ts` suites never see it.
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

afterEach(() => {
  cleanup();
});

// jsdom has no layout engine, so these are absent. Mantine's color-scheme and
// responsive machinery call them on render.
if (!window.matchMedia) {
  window.matchMedia = (query: string): MediaQueryList =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;
}

if (!window.ResizeObserver) {
  window.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = vi.fn();
}
