/**
 * Exhibit 1 — the RAM ceiling.
 *
 * MODELLED, and the exhibit says so in its own chrome. Everything drawn here comes out
 * of the allocation ledger in src/stream/memory.ts; nothing is a hand-drawn curve.
 *
 * Both panels share one y-scale. That is the whole point of the exhibit: the chunked
 * trace is not flat because it was drawn small, it is flat because it is that flat next
 * to a number that kills a process.
 */

import { CHAINED_OVERHEAD } from '../stream/chained.js'
import {
  formatBytes,
  formatCount,
  requiredBytes,
  simulateChunked,
  simulateOneShot,
  type MemoryRun,
} from '../stream/memory.js'
import { el, prefersReducedMotion, setClass } from './dom.js'

const MIN_FILE = 1 << 20 // 1 MiB
const MAX_FILE = 10 * (1 << 30) // 10 GiB
const RUN_MS = 3400

/** Log-scaled slider: position 0 → 1 MiB, position 100 → 10 GiB. */
function sliderToBytes(position: number): number {
  const ratio = MAX_FILE / MIN_FILE
  const raw = MIN_FILE * Math.pow(ratio, position / 100)
  return Math.max(MIN_FILE, Math.round(raw / MIN_FILE) * MIN_FILE)
}

interface PanelRefs {
  panel: HTMLElement
  fill: HTMLElement
  ceiling: HTMLElement
  trace: HTMLElement
  status: HTMLElement
  peak: HTMLElement
  ratio: HTMLElement
  extra: HTMLElement
}

function refs(suffix: string): PanelRefs {
  return {
    panel: el(`panel-${suffix}`),
    fill: el(`fill-${suffix}`),
    ceiling: el(`ceil-${suffix}`),
    trace: el(`trace-${suffix}`),
    status: el(`status-${suffix}`),
    peak: el(`peak-${suffix}`),
    ratio: el(`ratio-${suffix}`),
    extra: el(`allocs-${suffix}`),
  }
}

const SVG_NS = 'http://www.w3.org/2000/svg'
const VB_W = 320
const VB_H = 132
const PAD_L = 4
const PAD_R = 4
const PAD_T = 8
const PAD_B = 14

interface TraceRefs {
  line: SVGPolylineElement
  area: SVGPolygonElement
  marker: SVGGElement
}

/** Build the trace chart once; each frame only updates the point lists. */
function buildTrace(host: HTMLElement, ceilingFraction: number, stroke: string): TraceRefs {
  host.textContent = ''
  const svg = document.createElementNS(SVG_NS, 'svg')
  svg.setAttribute('viewBox', `0 0 ${VB_W} ${VB_H}`)
  svg.setAttribute('preserveAspectRatio', 'none')
  svg.setAttribute('focusable', 'false')
  svg.setAttribute('aria-hidden', 'true')

  const baseline = document.createElementNS(SVG_NS, 'line')
  baseline.setAttribute('x1', String(PAD_L))
  baseline.setAttribute('x2', String(VB_W - PAD_R))
  baseline.setAttribute('y1', String(VB_H - PAD_B))
  baseline.setAttribute('y2', String(VB_H - PAD_B))
  baseline.setAttribute('stroke', 'currentColor')
  baseline.setAttribute('stroke-width', '1')
  baseline.setAttribute('opacity', '0.35')
  svg.append(baseline)

  if (ceilingFraction <= 1) {
    const y = PAD_T + (1 - ceilingFraction) * (VB_H - PAD_T - PAD_B)
    const ceil = document.createElementNS(SVG_NS, 'line')
    ceil.setAttribute('x1', String(PAD_L))
    ceil.setAttribute('x2', String(VB_W - PAD_R))
    ceil.setAttribute('y1', String(y))
    ceil.setAttribute('y2', String(y))
    ceil.setAttribute('stroke', 'var(--bad)')
    ceil.setAttribute('stroke-width', '1.5')
    ceil.setAttribute('stroke-dasharray', '5 4')
    svg.append(ceil)
  }

  const area = document.createElementNS(SVG_NS, 'polygon')
  area.setAttribute('fill', stroke)
  area.setAttribute('opacity', '0.16')
  area.setAttribute('points', '')
  svg.append(area)

  const line = document.createElementNS(SVG_NS, 'polyline')
  line.setAttribute('fill', 'none')
  line.setAttribute('stroke', stroke)
  line.setAttribute('stroke-width', '2')
  line.setAttribute('stroke-linejoin', 'round')
  line.setAttribute('points', '')
  svg.append(line)

  const marker = document.createElementNS(SVG_NS, 'g')
  svg.append(marker)

  host.append(svg)
  return { line, area, marker }
}

function project(progressFraction: number, valueFraction: number): [number, number] {
  const x = PAD_L + progressFraction * (VB_W - PAD_L - PAD_R)
  const y = PAD_T + (1 - Math.min(1, valueFraction)) * (VB_H - PAD_T - PAD_B)
  return [x, y]
}

/** A small, self-scaled sawtooth window — the oscillation the big shared-scale trace hides. */
const ZOOM_W = 320
const ZOOM_H = 42
const ZOOM_WINDOW = 42

function renderZoom(host: HTMLElement, run: MemoryRun, upTo: number): void {
  host.textContent = ''
  const svg = document.createElementNS(SVG_NS, 'svg')
  svg.setAttribute('viewBox', `0 0 ${ZOOM_W} ${ZOOM_H}`)
  svg.setAttribute('preserveAspectRatio', 'none')
  svg.setAttribute('focusable', 'false')
  svg.setAttribute('aria-hidden', 'true')

  const end = Math.max(1, Math.min(upTo, run.samples.length - 1))
  const start = Math.max(0, end - ZOOM_WINDOW)
  const yMax = Math.max(1, run.peakBytes) * 1.18
  const pts: string[] = []
  for (let i = start; i <= end; i++) {
    const s = run.samples[i]
    if (!s) continue
    const x = ((i - start) / Math.max(1, end - start)) * ZOOM_W
    const y = 3 + (1 - s.liveBytes / yMax) * (ZOOM_H - 6)
    pts.push(`${x.toFixed(1)},${y.toFixed(1)}`)
  }
  const line = document.createElementNS(SVG_NS, 'polyline')
  line.setAttribute('fill', 'none')
  line.setAttribute('stroke', 'var(--ok)')
  line.setAttribute('stroke-width', '1.6')
  line.setAttribute('points', pts.join(' '))
  svg.append(line)
  host.append(svg)
}

export function initMemoryExhibit(): void {
  const slider = el<HTMLInputElement>('file-size')
  const sizeOut = el<HTMLOutputElement>('file-size-out')
  const chunkSel = el<HTMLSelectElement>('chunk-size')
  const ramSel = el<HTMLSelectElement>('ram-limit')
  const runBtn = el<HTMLButtonElement>('run-memory')
  const verdict = el('memory-verdict')

  const oneShot = refs('oneshot')
  const chunked = refs('chunked')
  const zoomChunked = el('zoomtrace-chunked')

  let frame = 0

  const readInputs = () => ({
    fileBytes: sliderToBytes(Number(slider.value)),
    chunkBytes: Number(chunkSel.value),
    ramLimitBytes: Number(ramSel.value),
  })

  function resetPanels(): void {
    for (const p of [oneShot, chunked]) {
      p.status.textContent = 'Idle — press “Run both decrypts”.'
      p.status.classList.remove('is-oom', 'is-ok')
      p.panel.classList.remove('is-oom', 'is-flat')
      p.fill.classList.remove('is-oom', 'is-flat')
      p.fill.style.width = '0%'
      p.trace.textContent = ''
      zoomChunked.textContent = ''
      p.peak.textContent = '—'
      p.ratio.textContent = '—'
      p.extra.textContent = '—'
    }
    verdict.textContent = 'Both meters are drawn to the same scale, so the flat line really is that flat.'
  }

  function syncLabel(): void {
    sizeOut.textContent = formatBytes(sliderToBytes(Number(slider.value)))
  }

  function paintFrame(p: PanelRefs, run: MemoryRun, yMax: number, ceilingFraction: number, index: number): void {
    const sample = run.samples[Math.min(index, run.samples.length - 1)]
    if (!sample) return
    const valueFraction = sample.liveBytes / yMax
    p.fill.style.width = `${Math.min(100, valueFraction * 100).toFixed(2)}%`
    setClass(p.fill, 'is-oom', sample.phase === 'oom')
    setClass(p.fill, 'is-flat', run.strategy === 'chunked' && sample.phase !== 'oom')
    p.ceiling.style.left = `${Math.min(100, ceilingFraction * 100).toFixed(2)}%`
  }

  function paintTrace(t: TraceRefs, run: MemoryRun, yMax: number, upTo: number): void {
    const pts: string[] = []
    const last = Math.min(upTo, run.samples.length - 1)
    for (let i = 0; i <= last; i++) {
      const s = run.samples[i]
      if (!s) continue
      const [x, y] = project(run.fileBytes === 0 ? 0 : s.progressBytes / run.fileBytes, s.liveBytes / yMax)
      pts.push(`${x.toFixed(1)},${y.toFixed(1)}`)
    }
    t.line.setAttribute('points', pts.join(' '))
    if (pts.length > 1) {
      const first = pts[0] as string
      const final = pts[pts.length - 1] as string
      const floorY = (VB_H - PAD_B).toFixed(1)
      t.area.setAttribute(
        'points',
        `${(first.split(',')[0] as string)},${floorY} ${pts.join(' ')} ${(final.split(',')[0] as string)},${floorY}`,
      )
    }

    t.marker.textContent = ''
    const endSample = run.samples[last]
    if (endSample && endSample.phase === 'oom') {
      const [x, y] = project(endSample.progressBytes / run.fileBytes, endSample.liveBytes / yMax)
      const dot = document.createElementNS(SVG_NS, 'circle')
      dot.setAttribute('cx', String(x))
      dot.setAttribute('cy', String(Math.max(y, PAD_T)))
      dot.setAttribute('r', '4')
      dot.setAttribute('fill', 'var(--bad)')
      t.marker.append(dot)
      const burst = document.createElementNS(SVG_NS, 'line')
      burst.setAttribute('x1', String(x))
      burst.setAttribute('x2', String(x))
      burst.setAttribute('y1', String(VB_H - PAD_B))
      burst.setAttribute('y2', String(Math.max(y, PAD_T)))
      burst.setAttribute('stroke', 'var(--bad)')
      burst.setAttribute('stroke-width', '2')
      t.marker.append(burst)
    }
  }

  function finalise(p: PanelRefs, run: MemoryRun): void {
    p.peak.textContent = run.oom ? `${formatBytes(run.peakBytes)} (killed)` : formatBytes(run.peakBytes)
    p.ratio.textContent = formatBytes(
      requiredBytes(run.strategy, run.fileBytes, run.chunkBytes, CHAINED_OVERHEAD),
    )
    setClass(p.panel, 'is-oom', run.oom)
    setClass(p.panel, 'is-flat', !run.oom && run.strategy === 'chunked')
    setClass(p.status, 'is-oom', run.oom)
    setClass(p.status, 'is-ok', !run.oom)

    if (run.strategy === 'one-shot') {
      p.extra.textContent = formatCount(run.allocCount)
      p.status.textContent = run.oom
        ? `✕ OOM — process killed. It blew the ${formatBytes(run.ramLimitBytes)} ceiling ` +
          `${run.oomAtBytes === run.fileBytes ? 'while allocating the plaintext output buffer' : `after reading ${formatBytes(run.oomAtBytes ?? 0)} of the file`}.`
        : `✓ Completed. Ciphertext and plaintext were both resident at once — peak ${formatBytes(run.peakBytes)}.`
    } else {
      p.extra.textContent = formatCount(run.segmentCount)
      p.status.textContent = run.oom
        ? `✕ OOM — the segment size alone exceeds the ceiling.`
        : `✓ Completed ${formatCount(run.segmentCount)} segments. Never held more than ` +
          `${formatBytes(run.peakBytes)} — one segment in, one segment out.`
    }
  }

  function summarise(a: MemoryRun, b: MemoryRun): void {
    const needA = requiredBytes('one-shot', a.fileBytes, a.chunkBytes, CHAINED_OVERHEAD)
    const needB = requiredBytes('chunked', b.fileBytes, b.chunkBytes, CHAINED_OVERHEAD)
    const factor = formatCount(Math.round(needA / needB))
    if (a.oom) {
      verdict.textContent =
        `At ${formatBytes(a.fileBytes)} with ${formatBytes(a.ramLimitBytes)} of RAM: one-shot is killed after ` +
        `${formatBytes(a.oomAtBytes ?? 0)} — it needed ${formatBytes(needA)} to finish. The chunked stream ` +
        `authenticates all ${formatCount(b.segmentCount)} segments of the same file holding ${formatBytes(needB)}. ` +
        `Same cipher, same key, ${factor}× less memory.`
    } else {
      verdict.textContent =
        `At ${formatBytes(a.fileBytes)} both finish — but one-shot needs ${formatBytes(needA)} against the chunked ` +
        `stream's ${formatBytes(needB)} (${factor}× less). Drag the slider right until one-shot crosses the ceiling.`
    }
  }

  function run(): void {
    cancelAnimationFrame(frame)
    const { fileBytes, chunkBytes, ramLimitBytes } = readInputs()
    const runOne = simulateOneShot(fileBytes, ramLimitBytes, chunkBytes)
    const runMany = simulateChunked(fileBytes, ramLimitBytes, chunkBytes, CHAINED_OVERHEAD)

    const yMax = Math.max(ramLimitBytes, runOne.peakBytes) * 1.06
    const ceilingFraction = ramLimitBytes / yMax

    const traceOne = buildTrace(oneShot.trace, ceilingFraction, 'var(--accent)')
    const traceMany = buildTrace(chunked.trace, ceilingFraction, 'var(--ok)')

    oneShot.ceiling.style.left = `${(ceilingFraction * 100).toFixed(2)}%`
    chunked.ceiling.style.left = `${(ceilingFraction * 100).toFixed(2)}%`

    // One-shot's timeline is cut short in proportion to how much of the file it got
    // through, so an OOM at 20% of the file freezes at 20% of the animation.
    const oneCoverage = Math.max(
      0.04,
      (runOne.samples.at(-1)?.progressBytes ?? fileBytes) / fileBytes,
    )

    const jump = () => {
      paintFrame(oneShot, runOne, yMax, ceilingFraction, runOne.samples.length - 1)
      paintTrace(traceOne, runOne, yMax, runOne.samples.length - 1)
      paintFrame(chunked, runMany, yMax, ceilingFraction, runMany.samples.length - 1)
      paintTrace(traceMany, runMany, yMax, runMany.samples.length - 1)
      renderZoom(zoomChunked, runMany, runMany.samples.length - 1)
      finalise(oneShot, runOne)
      finalise(chunked, runMany)
      summarise(runOne, runMany)
      runBtn.disabled = false
    }

    if (prefersReducedMotion()) {
      jump()
      return
    }

    runBtn.disabled = true
    const started = performance.now()
    const step = (now: number) => {
      const u = Math.min(1, (now - started) / RUN_MS)
      const uOne = Math.min(1, u / oneCoverage)
      paintFrame(oneShot, runOne, yMax, ceilingFraction, Math.floor(uOne * (runOne.samples.length - 1)))
      paintTrace(traceOne, runOne, yMax, Math.floor(uOne * (runOne.samples.length - 1)))
      const idxMany = Math.floor(u * (runMany.samples.length - 1))
      paintFrame(chunked, runMany, yMax, ceilingFraction, idxMany)
      paintTrace(traceMany, runMany, yMax, idxMany)
      renderZoom(zoomChunked, runMany, idxMany)
      if (u < 1) {
        frame = requestAnimationFrame(step)
      } else {
        jump()
      }
    }
    frame = requestAnimationFrame(step)
  }

  slider.addEventListener('input', () => {
    syncLabel()
    resetPanels()
  })
  chunkSel.addEventListener('change', resetPanels)
  ramSel.addEventListener('change', resetPanels)
  runBtn.addEventListener('click', run)

  syncLabel()
}
