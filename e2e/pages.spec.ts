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

test('every asset the page pulls is served from under the base path', async ({ page, baseURL }) => {
  // Read the origin from the config instead of restating it: a second copy is how a
  // port change gets half-applied, and a stale copy here would make the check either
  // fail on every request or, worse, compare against nothing.
  expect(baseURL, 'baseURL must be configured for this check to mean anything').toBeTruthy()
  const base = baseURL as string
  const external: string[] = []
  page.on('request', (r) => {
    const url = r.url()
    if (url.startsWith('data:') || url.startsWith('blob:')) return
    if (!url.startsWith(base)) external.push(url)
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
  await expect(page.locator('.cl-topbar')).toBeVisible()
})

test('the memory verdict includes framing and state in the exact peak', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('./')
  await page.locator('#run-memory').click()
  const limit = 2 ** 31
  const stateBytes = 32 + 24 + 32 + 24
  const frameOverhead = 1 + 16
  const peak = (chunk: number) => (2 * chunk + frameOverhead + stateBytes).toLocaleString('en-US')
  await expect(page.locator('#status-oneshot')).toContainText(
    `${(limit + stateBytes).toLocaleString('en-US')} bytes, above the limit of ${limit.toLocaleString('en-US')} bytes`,
  )
  await expect(page.locator('#status-chunked')).toContainText(`${peak(65536)} bytes`)
  await expect(page.locator('#memory-verdict')).toContainText(`peak of ${peak(65536)} bytes`)

  await page.locator('#chunk-size').selectOption('16384')
  await page.locator('#run-memory').click()
  await expect(page.locator('#memory-verdict')).toContainText(`peak of ${peak(16384)} bytes`)
  await page.locator('#file-size').fill('0')
  await page.locator('#run-memory').click()
  await expect(page.locator('#status-oneshot')).toContainText('2,097,264 bytes')
  await expect(page.locator('#memory-verdict')).toContainText('both finish')
})

test('changing a setting retires an animated memory run', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await page.clock.install()
  await page.goto('./')
  const run = page.locator('#run-memory')
  await run.click()
  await expect(run).toBeDisabled()
  await page.locator('#chunk-size').selectOption('16384')
  await expect(run).toBeEnabled()
  await page.clock.runFor(6000)
  await expect(page.locator('#status-chunked')).toContainText('Idle')
  await expect(page.locator('#peak-chunked')).toHaveText('—')
  await run.click()
  await page.clock.runFor(6000)
  await expect(page.locator('#status-chunked')).toContainText('32,897 bytes')
})
