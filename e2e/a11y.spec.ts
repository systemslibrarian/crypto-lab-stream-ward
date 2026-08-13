import { test } from '@playwright/test'
import { boot, driveAllStates, NARROW } from './gate'

/**
 * WCAG A/AA regression gate.
 *
 * The spec this replaces did three things that made a pass meaningless:
 * it injected `transition/animation: none` through `addStyleTag` (which cannot
 * reach code that reads `matchMedia('(prefers-reduced-motion: reduce)')` in JS,
 * and bypasses the stylesheet's own reduced-motion block), it forced state from
 * script rather than driving the controls, and it scanned twice — at one
 * viewport, after the whole drive had already overwritten every state it built.
 *
 * This one drives the lab the way a visitor does — the three memory sliders and
 * the run that fills the verdict, both constructions, and all three attacks
 * against each with a reset between — and scans after every step, in both themes
 * at desktop and 380px. See `gate.ts` for why nothing is injected, why axe is
 * run twice rather than chained, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000)
    await boot(page, theme)
    await driveAllStates(page, theme)
  })

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000)
    await page.setViewportSize(NARROW)
    await boot(page, theme)
    await driveAllStates(page, `${theme} @380px`)
  })
}
