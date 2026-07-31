/**
 * Exhibits 2–4 — the chain, the attacker's bench, and the scorecard.
 *
 * REAL CRYPTO. Every verdict on screen is the return value of the genuine verifier in
 * src/stream/. Nothing is scripted: the UI applies the attack to the frames, calls
 * open*(), and renders whatever comes back.
 *
 * Colour tracks system integrity, not the raw return value — an attack that the
 * chained verifier *rejects* is green, because the system did its job, and an attack
 * that the naive verifier *accepts* is red, because it did not.
 */

import { ATTACKS, attackById, type AttackId } from '../stream/attacks.js'
import { bytesEqual, fromUtf8, hexHead, randomBytes } from '../stream/bytes.js'
import { openChained, sealChained, type SealedChained, type VerifyStep } from '../stream/chained.js'
import { openNaive, sealNaive, type SealedNaive } from '../stream/naive.js'
import { ATTACK_OUTCOMES, LEDGER, LEDGER_SEGMENTS } from '../stream/payload.js'
import type { Frame, Mode, OpenResult, SealedStream } from '../stream/types.js'
import { wireSize } from '../stream/wire.js'
import { el } from './dom.js'

const MODE_EXPLAIN: Record<Mode, string> = {
  chained:
    'Each segment is authenticated against a rolling chain state and its own sequence number, and the last segment ' +
    'carries a FINAL flag inside the encrypted block. A segment that moves lands on a chain state its tag does not cover.',
  naive:
    'Each chunk carries its own random nonce and its own tag, and nothing else. Every chunk is a perfectly valid ' +
    'message on its own — which is exactly what makes the file as a whole rearrangeable.',
}

interface CellResult {
  ok: boolean
  verdict: string
  detail: string
}

function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text !== undefined) node.textContent = text
  return node
}

export function initStreamExhibit(): void {
  // Per-session key, in memory only, never stored or transmitted.
  const key = randomBytes(32)
  const sealed: { chained: SealedChained; naive: SealedNaive } = {
    chained: sealChained(key, LEDGER_SEGMENTS),
    naive: sealNaive(key, LEDGER_SEGMENTS),
  }

  const segmentsList = el<HTMLOListElement>('segments')
  const modeExplain = el('mode-explain')
  const attackNote = el('attack-note')
  const verdictBox = el('verdict')
  const deliveredBox = el('delivered')
  const matrixBody = el<HTMLTableSectionElement>('matrix-body')
  const matrixProgress = el('matrix-progress')

  let mode: Mode = 'chained'
  let attack: AttackId | null = null
  const cells = new Map<string, CellResult>()

  const attackButtons: Record<AttackId, HTMLButtonElement> = {
    truncate: el<HTMLButtonElement>('atk-truncate'),
    reorder: el<HTMLButtonElement>('atk-reorder'),
    drop: el<HTMLButtonElement>('atk-drop'),
  }

  // ── segment strip ──────────────────────────────────────────────────────────

  function renderSegments(
    stream: SealedStream,
    origins: number[],
    removed: number[],
    trace: readonly VerifyStep[],
    result: OpenResult,
  ): void {
    segmentsList.textContent = ''
    const base = sealed[mode]

    stream.frames.forEach((frame, i) => {
      const from = origins[i] ?? i
      const line = LEDGER[from]
      const item = h('li', 'seg')
      item.setAttribute('role', 'listitem')

      item.append(h('span', 'seg-idx', `#${i}`))

      const body = h('div')
      body.append(h('div', 'seg-text', line?.text ?? '(unknown segment)'))

      const meta = h('div', 'seg-meta')
      if (mode === 'chained') {
        const step = trace[i]
        const chainIn = step ? hexHead(step.chainIn, 4) : hexHead(base.chainStates[i] ?? new Uint8Array(4), 4)
        meta.append(metaItem('chain', `${chainIn}…`))
        meta.append(metaItem('nonce', step ? `${hexHead(step.nonce, 4)}…` : '—'))
      } else {
        meta.append(metaItem('nonce', `${hexHead(frame.nonce ?? new Uint8Array(4), 4)}… (shipped with the chunk)`))
      }
      meta.append(metaItem('ct', `${frame.body.length} B`))
      if (from !== i) meta.append(metaItem('moved', `was segment #${from}`))
      body.append(meta)
      item.append(body)

      const { label, cls } = positionState(i, trace, result)
      item.append(h('span', 'seg-state', label))
      if (cls) item.classList.add(cls)

      segmentsList.append(item)

      // The chain link between this segment and the next — the mechanism, shown.
      if (mode === 'chained' && i < stream.frames.length - 1) {
        const failedHere = !result.ok && result.failedAt === i + 1 && result.code === 'SEGMENT_AUTH_FAILED'
        const next = trace[i + 1]
        const link = h(
          'span',
          `chain-link${failedHere ? ' is-broken' : ''}`,
          failedHere
            ? `⛓ chain[${i + 1}] = ${next ? hexHead(next.chainIn, 6) : '????'}… — the frame below was authenticated against a different one`
            : `⛓ chain[${i + 1}] = SHA-256( chain[${i}] ‖ ${i} ‖ ct[${i}] ) = ${next ? hexHead(next.chainIn, 6) : '……'}…`,
        )
        segmentsList.append(link)
      }
      if (mode === 'naive' && i < stream.frames.length - 1) {
        segmentsList.append(h('span', 'chain-link', '⋯ nothing binds this chunk to the next one'))
      }
    })

    for (const idx of removed) {
      const line = LEDGER[idx]
      const item = h('li', 'seg is-skipped')
      item.setAttribute('role', 'listitem')
      item.append(h('span', 'seg-idx', '✂'))
      const body = h('div')
      body.append(h('div', 'seg-text', line?.text ?? ''))
      body.append(h('div', 'seg-meta', 'deleted by the attacker — the verifier is never handed these bytes'))
      item.append(body)
      item.append(h('span', 'seg-state', 'removed'))
      segmentsList.append(item)
    }
  }

  function metaItem(label: string, value: string): HTMLElement {
    const span = h('span')
    span.append(h('b', undefined, `${label} `))
    span.append(document.createTextNode(value))
    return span
  }

  function positionState(
    i: number,
    trace: readonly VerifyStep[],
    result: OpenResult,
  ): { label: string; cls: string | null } {
    if (mode === 'naive') {
      return result.ok || i < result.segmentsAccepted
        ? { label: attack ? '⚠ accepted' : '✓ accepted', cls: attack ? 'is-alarm' : 'is-ok' }
        : { label: '✕ rejected', cls: 'is-bad' }
    }
    const step = trace[i]
    if (!step) return { label: '— not reached', cls: 'is-skipped' }
    if (!step.ok) return { label: '✕ rejected', cls: 'is-bad' }
    return { label: '✓ authenticated', cls: 'is-ok' }
  }

  // ── verdict ────────────────────────────────────────────────────────────────

  function renderVerdict(result: OpenResult): CellResult {
    verdictBox.textContent = ''
    verdictBox.classList.remove('is-pass', 'is-reject', 'is-alarm')

    const head = h('div', 'verdict-head')
    const icon = h('span', 'verdict-icon')
    icon.setAttribute('aria-hidden', 'true')
    head.append(icon)

    let cell: CellResult

    if (result.ok && attack === null) {
      // Correct path, untouched stream.
      verdictBox.classList.add('is-pass')
      icon.textContent = '✓'
      head.append(h('span', undefined, 'ACCEPTED — plaintext recovered intact'))
      head.append(h('span', 'verdict-code', mode === 'chained' ? 'FINAL SEEN' : 'NO FINAL MARKER'))
      verdictBox.append(head)
      verdictBox.append(
        h(
          'p',
          'verdict-body',
          mode === 'chained'
            ? `All ${result.segmentsAccepted} segments authenticated in order, and segment ${result.segmentsAccepted - 1} carried the FINAL flag, so the verifier knows it has the whole file.`
            : `All ${result.segmentsAccepted} chunks authenticated. Note what is missing: there is no FINAL marker in this format, so the verifier cannot tell a complete file from a truncated one even now.`,
        ),
      )
      cell = { ok: true, verdict: 'Accepted', detail: 'untouched stream' }
    } else if (!result.ok) {
      // The construction refused. That is the system working.
      verdictBox.classList.add('is-reject')
      icon.textContent = '🛡'
      head.append(h('span', undefined, 'ABORTED — the attack was blocked'))
      head.append(h('span', 'verdict-code', result.code))
      verdictBox.append(head)
      verdictBox.append(h('p', 'verdict-body', result.reason))
      if (result.code === 'TRUNCATED_STREAM' && result.releasedBeforeAbort.length > 0) {
        verdictBox.append(
          h(
            'p',
            'verdict-body',
            `Read this one carefully: ${result.releasedBeforeAbort.length} segments were genuine, in order, and ` +
              `already released to the application before the abort fired. A streaming verifier detects truncation; ` +
              `it cannot un-process the prefix it already handed over. That is why you must check for the FINAL ` +
              `marker before treating a stream as a complete file.`,
          ),
        )
      }
      cell = { ok: true, verdict: 'Rejected', detail: result.code }
    } else {
      // Accepted a mangled stream. Colour tracks integrity, so this is ALARM.
      verdictBox.classList.add('is-alarm')
      icon.textContent = '⚠'
      head.append(h('span', undefined, 'ACCEPTED — corrupted plaintext handed to the application'))
      head.append(h('span', 'verdict-code', 'NO ERROR RAISED'))
      verdictBox.append(head)
      verdictBox.append(
        h(
          'p',
          'verdict-body',
          `Every one of the ${result.segmentsAccepted} chunks the attacker left behind passed its own Poly1305 check, ` +
            `so this verifier reports success. It has nothing to check the arrangement against.`,
        ),
      )
      verdictBox.append(h('p', 'verdict-body', ATTACK_OUTCOMES[attack as string] ?? ''))
      cell = { ok: false, verdict: 'Accepted silently', detail: `${result.segmentsAccepted} chunks, no error` }
    }

    return cell
  }

  // ── delivered plaintext ────────────────────────────────────────────────────

  function renderDelivered(result: OpenResult, origins: number[], removed: number[]): void {
    deliveredBox.textContent = ''

    if (!result.ok) {
      if (result.releasedBeforeAbort.length === 0) {
        deliveredBox.append(
          h('div', 'delivered-none', 'Nothing. The verifier failed closed before releasing a single byte of plaintext.'),
        )
        return
      }
      result.releasedBeforeAbort.forEach((seg) => {
        deliveredBox.append(h('div', 'delivered-line', fromUtf8(seg)))
      })
      deliveredBox.append(
        h(
          'div',
          'delivered-line is-missing',
          `⛔ verifier aborted here — ${result.code}. No further plaintext was released.`,
        ),
      )
      return
    }

    result.segments.forEach((seg, i) => {
      const moved = (origins[i] ?? i) !== i
      deliveredBox.append(h('div', `delivered-line${moved ? ' is-moved' : ''}`, fromUtf8(seg)))
    })
    for (const idx of removed) {
      deliveredBox.append(
        h('div', 'delivered-line is-missing', `✂ never arrived: "${LEDGER[idx]?.text ?? ''}" — and nothing said so.`),
      )
    }

    const expected = LEDGER_SEGMENTS.map(fromUtf8).join('')
    const got = result.segments.map(fromUtf8).join('')
    const identical = bytesEqual(new TextEncoder().encode(expected), new TextEncoder().encode(got))
    deliveredBox.append(
      h(
        'div',
        `delivered-none${identical ? '' : ' is-missing'}`,
        identical
          ? `✓ Byte-for-byte comparison against what was sealed: ${expected.length} of ${expected.length} bytes identical.`
          : `✕ Byte-for-byte comparison against what was sealed: ${got.length} bytes delivered vs ${expected.length} sealed — and the verifier did not object.`,
      ),
    )
  }

  // ── scorecard ──────────────────────────────────────────────────────────────

  function renderMatrix(): void {
    matrixBody.textContent = ''
    for (const spec of ATTACKS) {
      const row = h('tr')
      const label = h('th', undefined, spec.label)
      label.setAttribute('scope', 'row')
      row.append(label)
      for (const m of ['chained', 'naive'] as const) {
        const td = h('td')
        const found = cells.get(`${spec.id}:${m}`)
        const cell = h('span', `cell ${found ? (found.ok ? 'is-good' : 'is-bad') : 'is-untried'}`)
        cell.append(h('span', 'cell-verdict', found ? `${found.ok ? '🛡 ' : '⚠ '}${found.verdict}` : '— not tried'))
        cell.append(
          h('span', 'cell-detail', found ? found.detail : `run “${spec.label}” in ${m === 'chained' ? 'chained' : 'naive'} mode`),
        )
        if (found && !found.ok) td.classList.add('is-alarm')
        td.append(cell)
        row.append(td)
      }
      matrixBody.append(row)
    }
    matrixProgress.textContent = `${cells.size} of 6 run.`
  }

  // ── main render ────────────────────────────────────────────────────────────

  function render(): void {
    const base: SealedStream = sealed[mode]
    const stream = attack ? attackById(attack).apply(base) : base

    // Attacks move whole Frame objects, so identity recovers what the attacker did.
    const origins = stream.frames.map((f) => base.frames.indexOf(f as Frame))
    const removed = base.frames.map((_, i) => i).filter((i) => !origins.includes(i))

    let result: OpenResult
    let trace: readonly VerifyStep[] = []
    if (mode === 'chained') {
      const opened = openChained(key, stream)
      result = opened.result
      trace = opened.trace
    } else {
      result = openNaive(key, stream)
    }

    modeExplain.textContent = MODE_EXPLAIN[mode]
    if (attack) {
      const spec = attackById(attack)
      const before = wireSize(base)
      const after = wireSize(stream)
      const size =
        after === before
          ? `The stream is still ${before} bytes on the wire — not one byte was added, removed or altered.`
          : `The stream is now ${after} bytes on the wire, down from ${before}.`
      attackNote.textContent = `${spec.label}: ${spec.describe(base)} ${size}`
    } else {
      attackNote.textContent = `No attack applied — the stream is exactly as it was sealed (${wireSize(base)} bytes on the wire, ${base.frames.length} frames).`
    }

    renderSegments(stream, origins, removed, trace, result)
    const cell = renderVerdict(result)
    renderDelivered(result, origins, removed)

    if (attack) cells.set(`${attack}:${mode}`, cell)
    renderMatrix()

    for (const [id, btn] of Object.entries(attackButtons)) {
      btn.setAttribute('aria-pressed', String(attack === id))
    }
  }

  // ── wiring ─────────────────────────────────────────────────────────────────

  for (const radio of document.querySelectorAll<HTMLInputElement>('input[name="mode"]')) {
    radio.addEventListener('change', () => {
      if (!radio.checked) return
      mode = radio.value === 'naive' ? 'naive' : 'chained'
      render()
    })
  }

  for (const [id, btn] of Object.entries(attackButtons)) {
    btn.addEventListener('click', () => {
      attack = attack === id ? null : (id as AttackId)
      render()
    })
  }

  el<HTMLButtonElement>('atk-reset').addEventListener('click', () => {
    attack = null
    render()
  })

  render()
}
