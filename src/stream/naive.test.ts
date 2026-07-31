/**
 * The vulnerable path, tested as vulnerable.
 *
 * The template requires an attack demo to carry a passing test proving the broken mode
 * really is broken — otherwise the demo is asserting a flaw it never demonstrates.
 * Every test in the first block below asserts that a mangled stream is *accepted*.
 */

import { describe, expect, it } from 'vitest'
import { fromUtf8, utf8 } from './bytes.js'
import { drop, reorder, truncate } from './attacks.js'
import { NAIVE_OVERHEAD, openNaive, sealNaive } from './naive.js'
import { LEDGER_SEGMENTS } from './payload.js'
import { NONCE_BYTES } from './chained.js'

const KEY = new Uint8Array(32).fill(7)
const HEADER = new Uint8Array(NONCE_BYTES).fill(0x5a)
const NONCES = LEDGER_SEGMENTS.map((_, i) => new Uint8Array(NONCE_BYTES).fill(0x10 + i))

function seal() {
  return sealNaive(KEY, LEDGER_SEGMENTS, HEADER, NONCES)
}

describe('naive split — round trip', () => {
  it('recovers the exact plaintext when untouched', () => {
    const result = openNaive(KEY, seal())
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.segments.map(fromUtf8)).toEqual(LEDGER_SEGMENTS.map(fromUtf8))
  })

  it('never reports a FINAL marker, because the format has none', () => {
    const result = openNaive(KEY, seal())
    if (result.ok) expect(result.sawFinal).toBe(false)
  })

  it('uses a distinct nonce per chunk — this is NOT a nonce-reuse bug', () => {
    const stream = sealNaive(KEY, LEDGER_SEGMENTS)
    const nonces = stream.frames.map((f) => Array.from(f.nonce!).join(','))
    expect(new Set(nonces).size).toBe(nonces.length)
  })

  it('pays a bigger per-segment overhead than chaining, because the nonce must travel', () => {
    const stream = seal()
    stream.frames.forEach((f, i) => {
      const total = f.body.length + (f.nonce?.length ?? 0)
      expect(total).toBe((LEDGER_SEGMENTS[i] as Uint8Array).length + NAIVE_OVERHEAD)
    })
  })
})

describe('naive split — the three attacks all SUCCEED SILENTLY (this is the flaw)', () => {
  it('TRUNCATE is accepted: the app gets a short batch and no error', () => {
    const result = openNaive(KEY, truncate(seal(), 2))
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.segmentsAccepted).toBe(4)
    expect(fromUtf8(result.plaintext)).not.toContain('END BATCH')
  })

  it('REORDER is accepted: PAY 8812 now precedes the HOLD meant to block it', () => {
    const result = openNaive(KEY, reorder(seal(), 2, 3))
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const lines = result.segments.map(fromUtf8)
    expect(lines[2]).toContain('PAY   acct 8812')
    expect(lines[3]).toContain('HOLD  acct 8812')
  })

  it('DROP is accepted: the HOLD is gone and nothing complains', () => {
    const result = openNaive(KEY, drop(seal(), 2))
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(fromUtf8(result.plaintext)).not.toContain('HOLD')
    expect(fromUtf8(result.plaintext)).toContain('PAY   acct 8812')
  })

  it('a replayed chunk is accepted — the same payment lands twice', () => {
    const stream = seal()
    const frames = [...stream.frames.slice(0, 4), stream.frames[3]!, ...stream.frames.slice(4)]
    const result = openNaive(KEY, { ...stream, frames })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.segments.filter((s) => fromUtf8(s).includes('PAY   acct 8812')).length).toBe(2)
    }
  })
})

describe('naive split — what it DOES still catch', () => {
  it('rejects a flipped bit inside a chunk: the per-chunk tag is real', () => {
    const stream = seal()
    const body = Uint8Array.from(stream.frames[1]!.body)
    body[0] = (body[0] as number) ^ 0x01
    const frames = stream.frames.slice()
    frames[1] = { body, nonce: stream.frames[1]!.nonce as Uint8Array }
    const result = openNaive(KEY, { ...stream, frames })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('SEGMENT_AUTH_FAILED')
  })

  it('rejects a chunk re-labelled with someone else’s nonce', () => {
    const stream = seal()
    const frames = stream.frames.slice()
    frames[1] = { body: stream.frames[1]!.body, nonce: stream.frames[2]!.nonce as Uint8Array }
    const result = openNaive(KEY, { ...stream, frames })
    expect(result.ok).toBe(false)
  })

  it('rejects the wrong key', () => {
    expect(openNaive(new Uint8Array(32).fill(8), seal()).ok).toBe(false)
  })

  it('rejects a frame with no nonce prefix', () => {
    const stream = seal()
    const frames = stream.frames.slice()
    frames[0] = { body: stream.frames[0]!.body }
    const result = openNaive(KEY, { ...stream, frames })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('MALFORMED_FRAME')
  })

  it('refuses to seal a stream with no segments', () => {
    expect(() => sealNaive(KEY, [])).toThrow()
  })

  it('round-trips a single empty segment', () => {
    const result = openNaive(KEY, sealNaive(KEY, [utf8('')], HEADER, [NONCES[0] as Uint8Array]))
    expect(result.ok).toBe(true)
  })
})
