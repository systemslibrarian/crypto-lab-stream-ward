/**
 * Deployment gate: the site has to work when it is served from the project subpath
 * `https://systemslibrarian.github.io/crypto-lab-stream-ward/`, not just from a root.
 * `vite preview` serves the production build under the configured base, so this is the
 * real thing — a root-absolute asset path or a stray fetch would 404 here exactly as it
 * would on Pages.
 */

import { expect, test } from '@playwright/test'

test('loads under the project subpath with no failed requests', async ({ page }) => {
  const failures: string[] = []
  page.on('response', (r) => {
    if (r.status() >= 400) failures.push(`${r.status()} ${r.url()}`)
  })
  page.on('requestfailed', (r) => failures.push(`FAILED ${r.url()}`))
  page.on('pageerror', (e) => failures.push(`PAGEERROR ${e.message}`))
  page.on('console', (m) => {
    if (m.type() === 'error') failures.push(`CONSOLE ${m.text()}`)
  })

  await page.goto('.', { waitUntil: 'networkidle' })

  // The app mounted and the crypto ran, rather than the shell merely rendering.
  await expect(page.locator('#app')).toBeVisible()
  await expect(page.locator('h1.cl-hero-title')).toHaveText('Stream Ward')
  await expect(page.locator('#segments li')).toHaveCount(6)
  await expect(page.locator('#verdict')).toHaveClass(/is-pass/)

  await page.locator('#run-memory').click()
  await page.waitForFunction(() => !(document.getElementById('run-memory') as HTMLButtonElement).disabled, null, {
    timeout: 15_000,
  })

  expect(failures).toEqual([])
})

test('every asset the page pulls is served from under the base path', async ({ page }) => {
  const external: string[] = []
  page.on('request', (r) => {
    const url = r.url()
    if (url.startsWith('data:') || url.startsWith('blob:')) return
    if (!url.startsWith('http://localhost:4287/crypto-lab-stream-ward/')) external.push(url)
  })
  await page.goto('.', { waitUntil: 'networkidle' })
  // No CDN scripts, no webfonts, no backend — the demo has to run offline from the subpath.
  expect(external).toEqual([])
})

test('the layout stacks with no horizontal scroll at phone widths', async ({ page }) => {
  for (const width of [320, 360, 390, 414, 640]) {
    await page.setViewportSize({ width, height: 900 })
    await page.goto('.')
    await page.evaluate(() => document.querySelectorAll('details').forEach((d) => (d.open = true)))
    // Regions that scroll on purpose (the segment strip, the scorecard, the spec block)
    // are excluded by construction: they carry their own overflow-x and are keyboard
    // reachable. Nothing else may push the page sideways.
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    )
    expect(overflow, `horizontal overflow at ${width}px`).toBe(0)
  }
})

test('the single banner landmark and the skip link survive the build', async ({ page }) => {
  await page.goto('.')
  await expect(page.locator('[role="banner"]')).toHaveCount(1)
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app')
  await expect(page.locator('h1')).toHaveCount(1)
  await expect(page.locator('#cl-theme-toggle')).toBeVisible()
})
