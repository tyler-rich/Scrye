import { createTheme, type MantineColorsTuple } from '@mantine/core';

// Locked decision: teal primary with first-class light and dark modes
// (CLAUDE.md § Locked decisions #7).
//
// Mantine's built-in `teal` ramp is centred on a bright mint (`teal[6]` is
// #12b886), which reads as green rather than teal. This custom ramp is the
// Tailwind teal scale, whose mid-tones are a deeper, more saturated true teal.
// The primary lands on teal-700 (#0f766e) in light mode and teal-600 (#0d9488)
// in dark mode. `autoContrast` + `luminanceThreshold` pick the higher-contrast
// label on filled controls (white on the darker light-mode shade, black on the
// brighter dark-mode shade), so both modes clear WCAG AA:
//   - light primary #0f766e → white label = 5.47:1; as text on white = 5.47:1
//   - dark  primary #0d9488 → black label = 5.60:1; as text on dark = 4.59:1
const teal: MantineColorsTuple = [
  '#f0fdfa', // 0  teal-50
  '#ccfbf1', // 1  teal-100
  '#99f6e4', // 2  teal-200
  '#5eead4', // 3  teal-300
  '#2dd4bf', // 4  teal-400
  '#14b8a6', // 5  teal-500
  '#0d9488', // 6  teal-600  (primary — dark mode)
  '#0f766e', // 7  teal-700  (primary — light mode)
  '#115e59', // 8  teal-800
  '#134e4a', // 9  teal-900
];

export const theme = createTheme({
  primaryColor: 'teal',
  primaryShade: { light: 7, dark: 6 },
  autoContrast: true,
  luminanceThreshold: 0.2,
  colors: { teal },
  defaultRadius: 'md',
  fontFamily: 'Inter, system-ui, sans-serif',
});
