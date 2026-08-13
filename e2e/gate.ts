import AxeBuilder from '@axe-core/playwright'
import { expect, type Page } from '@playwright/test'

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 }

/**
 * Shared machinery for the WCAG gate.
 *
 * Four rules govern this file, each a correction of the spec it replaces.
 *
 * 1. NOTHING IS INJECTED. The old gate pushed `transition/animation: none`
 *    through `addStyleTag`. That bypasses the stylesheet's own reduced-motion
 *    block and cannot reach code that reads
 *    `matchMedia('(prefers-reduced-motion: reduce)')` in JS, so it changed what
 *    was measured without changing what a visitor sees. Reduced motion is
 *    emulated at the browser level instead, which is what a real reader has.
 *
 * 2. NO STATE IS FORCED. The old gate set `.open` and stripped `hidden` from
 *    script, assembling a document no visitor can reach. Every state here is
 *    produced by driving the control that produces it, and asserted before it
 *    is scanned — so a broken driver fails instead of silently scanning first
 *    paint N times.
 *
 * 3. EVERY STATE IS SCANNED. The old gate scanned twice, after the whole drive,
 *    so each state it built was overwritten before anything measured it.
 *
 * 4. AXE IS RUN TWICE, NOT CHAINED. `withTags()` and `withRules()` both write
 *    `options.runOnly`, so `.withTags(TAGS).withRules([...])` silently keeps
 *    only the last — measured elsewhere in this fleet as 4 rules executing
 *    instead of 63, while reading as a full A/AA pass. The two sets are run
 *    separately and merged. `incomplete` is asserted as well as `violations`,
 *    because `aria-prohibited-attr` and `aria-required-children` are reported
 *    ONLY there, and they are the most common ARIA defects in this fleet.
 */

/**
 * Let layout, fonts and any in-flight render settle before measuring.
 *
 * Two rAFs are NOT enough. A CSS `transition` on `background` is still running
 * at that point, and axe samples whatever colour the compositor has reached —
 * which is a value that exists in no state of the page. That produced a real
 * phantom here: an armed attack button measured 2.00:1 (#240505 on #603b41)
 * mid-transition, while its settled colours are #240505 on the solid #ff7b7b,
 * a ratio of about 9:1. The gate was reporting a failure the visitor never sees.
 *
 * Waiting on `document.getAnimations()` covers CSS transitions and animations
 * alike. It is bounded, because a paused or infinite animation would otherwise
 * hang the gate — an infinite decorative loop is not a reason to fail, so the
 * wait gives up rather than throwing.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForLoadState('networkidle').catch(() => undefined)
  await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))))
  await page
    .evaluate(async () => {
      const running = document
        .getAnimations()
        .filter((a) => a.playState === 'running')
        .map((a) => a.finished.catch(() => undefined))
      if (running.length === 0) return
      await Promise.race([
        Promise.all(running),
        new Promise((r) => setTimeout(r, 1500)),
      ])
    })
    .catch(() => undefined)
  await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => r())))
}

/** Boot the lab in a given theme, with reduced motion emulated, not injected. */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('.')
  await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), theme)
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
  await expect(page.locator('#app')).toBeVisible()
  await settle(page)
}

/** The page must never scroll horizontally (WCAG 1.4.10). */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement
    // `overflow-x: hidden` on <body> propagates to the viewport and would make
    // this check pass by construction, so it is asserted absent rather than
    // trusted — four labs in this fleet were hiding real overflow that way.
    const clipped = ['hidden', 'clip'].includes(getComputedStyle(document.body).overflowX)
    if (!clipped && doc.scrollWidth <= doc.clientWidth) return null
    let widest: string | null = null
    let widestRight = doc.clientWidth
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const r = el.getBoundingClientRect()
      if (r.right > widestRight) {
        widestRight = r.right
        widest = `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''} @${Math.round(r.width)}px right=${Math.round(r.right)}`
      }
    }
    return { clipped, clientWidth: doc.clientWidth, scrollWidth: doc.scrollWidth, widest }
  })
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull()
}

/** The `hidden` attribute must actually hide (its UA rule is beaten by any class). */
export async function expectHiddenActuallyHides(page: Page, label: string): Promise<void> {
  const painted = await page.evaluate(() =>
    Array.from(document.querySelectorAll('[hidden]'))
      .filter((el) => getComputedStyle(el).display !== 'none')
      .map((el) => `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}`),
  )
  expect(painted, `elements marked hidden are painted in state: ${label}`).toEqual([])
}

/** Scan one driven state. */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page)

  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze()

  // The node's own `any[].message` carries axe's measured figures (the ratio and
  // both colours for a contrast failure). Dropping it makes a red gate say WHAT
  // failed but not BY HOW MUCH, which is the number you need to fix it.
  const shape = (r: {
    id: string
    help: string
    nodes: { target: unknown[]; any?: { message?: string }[] }[]
  }) => ({
    id: r.id,
    help: r.help,
    nodes: r.nodes
      .map((n) => `${n.target.join(' ')} :: ${(n.any ?? [])[0]?.message ?? ''}`.trim())
      .slice(0, 6),
  })

  expect(
    [...wcag.violations, ...landmarks.violations].map(shape),
    `axe violations in state: ${label}`,
  ).toEqual([])
  // `incomplete` is asserted because `aria-prohibited-attr` and
  // `aria-required-children` are reported ONLY there. One case is filtered, and
  // narrowly: axe files a `color-contrast` result as incomplete when an element
  // holds only non-text characters ("Element content contains only non-text
  // characters") — that is axe declining to judge an ICON as text, not a
  // finding. Filtering the whole `color-contrast` rule out of `incomplete`
  // would be a real blind spot, so only that reason is dropped, and only when
  // axe itself gives it.
  // Two `color-contrast` incompletes are axe DECLINING TO JUDGE rather than
  // reporting a defect, and both are filtered — narrowly, by message, and only
  // for that one rule:
  //   * "only non-text characters" — the element is an icon glyph.
  //   * "could not be determined because it is overlapped" — another element
  //     covers it, e.g. the focused skip link over the header bar.
  // Every ARIA incomplete is kept, which is the reason this assertion exists at
  // all: `aria-prohibited-attr` and `aria-required-children` are reported ONLY
  // in this bucket. Filtering the whole `color-contrast` rule out of it would be
  // a real blind spot; filtering these two reasons is not, because in both cases
  // axe has explicitly said it has no measurement to give.
  const CANNOT_JUDGE = ['only non-text characters', 'could not be determined']
  const meaningfulIncomplete = [...wcag.incomplete, ...landmarks.incomplete].filter(
    (r) =>
      !(
        r.id === 'color-contrast' &&
        r.nodes.every((n) =>
          (n.any ?? []).some((c) => CANNOT_JUDGE.some((m) => (c.message ?? '').includes(m))),
        )
      ),
  )
  expect(
    meaningfulIncomplete.map(shape),
    `axe incomplete (prohibited ARIA lives here) in state: ${label}`,
  ).toEqual([])

  await expectNoHorizontalOverflow(page, label)
  await expectHiddenActuallyHides(page, label)
}

export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`)

  // Arrival: chained mode is the shipped default, nothing run, no attack applied.
  await expect(page.locator('#mode-chained')).toBeChecked()
  await expect(page.locator('#mode-naive')).not.toBeChecked()
  await scanAt('first paint: chained mode, nothing run')

  // The skip link, reached with a real Tab so `:focus-visible` actually applies.
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.())
  await page.keyboard.press('Tab')
  await scanAt('first tab stop focused')

  // --- the memory model: three sliders, then the run that fills the verdict ---
  // `#file-size` is a range input; `#chunk-size` and `#ram-limit` are <select>.
  // Driving each with the right primitive matters — `fill()` throws on a select,
  // and setting `.value` from script fires no event, so the listeners that
  // recompute the verdict would never run.
  await setRange(page, '#file-size', '1')
  await scanAt('memory model: smallest file')
  await setRange(page, '#file-size', '100')
  await page.locator('#chunk-size').selectOption('16384')
  await page.locator('#ram-limit').selectOption('536870912')
  await scanAt('memory model: largest file, smallest chunk and RAM ceiling')
  await page.locator('#run-memory').click()
  await expect(page.locator('#memory-verdict')).not.toBeEmpty()
  await scanAt('memory model: verdict rendered')

  // --- naive vs chained, and the explanation that only exists in one of them --
  await page.locator('#mode-naive').check()
  await expect(page.locator('#mode-naive')).toBeChecked()
  await scanAt('naive mode selected')
  await page.locator('#mode-chained').check()
  await scanAt('back to chained mode')

  // --- the three attacks, each with a reset between, plus the verdict they set -
  for (const atk of ['#atk-truncate', '#atk-reorder', '#atk-drop']) {
    await page.locator(atk).click()
    await expect(page.locator('#verdict')).not.toBeEmpty()
    await scanAt(`attack applied: ${atk.slice(5)} — verdict shown`)
    await page.locator('#atk-reset').click()
    await scanAt(`attack reset after ${atk.slice(5)}`)
  }

  // The same three against the NAIVE construction, which is the contrast the
  // lab teaches: naive accepts what chained refuses.
  await page.locator('#mode-naive').check()
  for (const atk of ['#atk-truncate', '#atk-drop']) {
    await page.locator(atk).click()
    await expect(page.locator('#verdict')).not.toBeEmpty()
    await scanAt(`naive mode, ${atk.slice(5)} applied`)
  }
  await page.locator('#atk-reset').click()
  await page.locator('#mode-chained').check()
  await scanAt('reset to the shipped defaults')
}

/** Move a range input with real key events, so its `input` listeners fire. */
async function setRange(page: Page, selector: string, target: string): Promise<void> {
  await page.locator(selector).fill(target)
  await page.locator(selector).dispatchEvent('input')
  await page.locator(selector).dispatchEvent('change')
}
