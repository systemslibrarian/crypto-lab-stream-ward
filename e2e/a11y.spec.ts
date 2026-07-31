import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

/**
 * Axe only checks what is in the DOM, so an unscanned state is an ungated state.
 * This walks the demo into every result state it can reach — both memory outcomes,
 * both constructions, all three attacks under each, the OOM styling, the alarm
 * styling, the filled scorecard — before a single scan runs.
 */
async function driveDemo(page: Page): Promise<void> {
  // Exhibit 1 — the OOM path (10 GiB against 2 GiB), then a surviving path.
  await page.locator('#file-size').fill('100')
  await page.locator('#ram-limit').selectOption('2147483648')
  await page.locator('#chunk-size').selectOption('65536')
  await page.locator('#run-memory').click()
  await page.waitForFunction(() => !(document.getElementById('run-memory') as HTMLButtonElement).disabled, null, {
    timeout: 15_000,
  })
  await expect(page.locator('#panel-oneshot')).toHaveClass(/is-oom/)

  // Exhibits 2–4 — every attack in every mode, so both the rejection styling and the
  // alarm styling are live, and all six scorecard cells are filled.
  for (const mode of ['#mode-chained', '#mode-naive']) {
    await page.locator(mode).check()
    for (const attack of ['#atk-truncate', '#atk-reorder', '#atk-drop']) {
      await page.locator(attack).click()
      await expect(page.locator('#verdict')).not.toBeEmpty()
    }
  }
  await expect(page.locator('#matrix-progress')).toHaveText('6 of 6 run.')

  // Leave the page in the alarm state — naive + drop — so the loudest styling is scanned.
  // (The attack buttons toggle, so clear first rather than clicking a live one twice.)
  await page.locator('#mode-naive').check()
  await page.locator('#atk-reset').click()
  await page.locator('#atk-drop').click()
  await expect(page.locator('#verdict')).toHaveClass(/is-alarm/)
}

/** Reveal anything collapsed or animated so the scan sees the final rendered result. */
async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  })
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true))
    document.querySelectorAll<HTMLElement>('[hidden],[role="tabpanel"]').forEach((el) => {
      el.removeAttribute('hidden')
      el.style.display = ''
      el.classList.add('active', 'is-active', 'open')
    })
  })
  await page.waitForTimeout(300)
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([])
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.')
  await driveDemo(page)
  await prepare(page)
  await scan(page)
})

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.')
  await page.locator('#cl-theme-toggle').click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await driveDemo(page)
  await prepare(page)
  await scan(page)
})

test('the untouched stream verifies and the three attacks are all rejected', async ({ page }) => {
  await page.goto('.')
  await expect(page.locator('#verdict')).toHaveClass(/is-pass/)
  for (const attack of ['#atk-truncate', '#atk-reorder', '#atk-drop']) {
    await page.locator(attack).click()
    await expect(page.locator('#verdict')).toHaveClass(/is-reject/)
    await page.locator('#atk-reset').click()
  }
})

test('the naive split accepts all three attacks silently', async ({ page }) => {
  await page.goto('.')
  await page.locator('#mode-naive').check()
  await expect(page.locator('#verdict')).toHaveClass(/is-pass/)
  for (const attack of ['#atk-truncate', '#atk-reorder', '#atk-drop']) {
    await page.locator(attack).click()
    await expect(page.locator('#verdict')).toHaveClass(/is-alarm/)
    await page.locator('#atk-reset').click()
  }
})
