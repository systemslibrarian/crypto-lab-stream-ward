/**
 * The chained construction: does it round-trip, and does it fail closed on every
 * arrangement attack an attacker can mount without the key?
 */

import { describe, expect, it } from 'vitest'
import { bytesEqual, fromUtf8, toHex, utf8 } from './bytes.js'
import { CHAINED_OVERHEAD, HEADER_BYTES, NONCE_BYTES, deriveNonce, initialChain, openChained, sealChained } from './chained.js'
import { drop, reorder, truncate } from './attacks.js'
import { LEDGER_SEGMENTS } from './payload.js'
import { TAG_FINAL, TAG_MESSAGE, type Frame } from './types.js'

const KEY = new Uint8Array(32).fill(7)
const HEADER = new Uint8Array(HEADER_BYTES).fill(0x5a)

function seal() {
  return sealChained(KEY, LEDGER_SEGMENTS, HEADER)
}

describe('chained AEAD — round trip', () => {
  it('recovers the exact plaintext and reports the FINAL marker', () => {
    const { result } = openChained(KEY, seal())
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.sawFinal).toBe(true)
    expect(result.segmentsAccepted).toBe(LEDGER_SEGMENTS.length)
    expect(result.segments.map(fromUtf8)).toEqual(LEDGER_SEGMENTS.map(fromUtf8))
  })

  it('is deterministic for a fixed header, and different for a fresh one', () => {
    expect(toHex(seal().frames[0]!.body)).toBe(toHex(seal().frames[0]!.body))
    const other = sealChained(KEY, LEDGER_SEGMENTS)
    expect(toHex(other.frames[0]!.body)).not.toBe(toHex(seal().frames[0]!.body))
  })

  it('adds exactly one flag byte plus one Poly1305 tag per segment', () => {
    const stream = seal()
    stream.frames.forEach((f, i) => {
      expect(f.body.length).toBe((LEDGER_SEGMENTS[i] as Uint8Array).length + CHAINED_OVERHEAD)
    })
  })

  it('marks only the last segment FINAL', () => {
    const flags = seal().steps.map((s) => s.flag)
    expect(flags.slice(0, -1).every((f) => f === TAG_MESSAGE)).toBe(true)
    expect(flags.at(-1)).toBe(TAG_FINAL)
  })

  it('handles a single-segment stream (the segment is both first and FINAL)', () => {
    const one = sealChained(KEY, [utf8('only line')], HEADER)
    const { result } = openChained(KEY, one)
    expect(result.ok).toBe(true)
    if (result.ok) expect(fromUtf8(result.plaintext)).toBe('only line')
  })

  it('handles an empty-plaintext segment without losing the flag byte', () => {
    const stream = sealChained(KEY, [new Uint8Array(0), utf8('tail')], HEADER)
    const { result } = openChained(KEY, stream)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.segments.map((s) => s.length)).toEqual([0, 4])
  })
})

describe('chained AEAD — nonce and chain hygiene', () => {
  it('never repeats a nonce inside a stream', () => {
    const nonces = seal().steps.map((s) => toHex(s.nonce))
    expect(new Set(nonces).size).toBe(nonces.length)
    nonces.forEach((n) => expect(n.length).toBe(NONCE_BYTES * 2))
  })

  it('gives two streams with different headers disjoint nonce sets', () => {
    const a = sealChained(KEY, LEDGER_SEGMENTS, new Uint8Array(HEADER_BYTES).fill(1))
    const b = sealChained(KEY, LEDGER_SEGMENTS, new Uint8Array(HEADER_BYTES).fill(2))
    const setA = new Set(a.steps.map((s) => toHex(s.nonce)))
    b.steps.forEach((s) => expect(setA.has(toHex(s.nonce))).toBe(false))
  })

  it('advances the chain state on every segment', () => {
    const states = seal().chainStates.map(toHex)
    expect(new Set(states).size).toBe(states.length)
    expect(states.length).toBe(LEDGER_SEGMENTS.length + 1)
  })

  it('derives the chain seed from the header, so a different header reroutes everything', () => {
    const a = initialChain(new Uint8Array(HEADER_BYTES).fill(1))
    const b = initialChain(new Uint8Array(HEADER_BYTES).fill(2))
    expect(bytesEqual(a, b)).toBe(false)
    expect(bytesEqual(deriveNonce(a, 0), deriveNonce(b, 0))).toBe(false)
  })
})

describe('chained AEAD — the three attacks all fail closed', () => {
  it('TRUNCATE: aborts with TRUNCATED_STREAM naming the missing FINAL', () => {
    const { result } = openChained(KEY, truncate(seal(), 2))
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('TRUNCATED_STREAM')
    expect(result.reason).toContain('FINAL')
    // The prefix really was authentic — that is the honest part of the lesson.
    expect(result.releasedBeforeAbort.length).toBe(4)
  })

  it('REORDER: the moved frame fails Poly1305 at the position it was moved to', () => {
    const { result } = openChained(KEY, reorder(seal(), 2, 3))
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('SEGMENT_AUTH_FAILED')
    expect(result.failedAt).toBe(2)
    expect(result.releasedBeforeAbort.length).toBe(2)
  })

  it('DROP: the frame that slides into the gap fails Poly1305', () => {
    const { result } = openChained(KEY, drop(seal(), 2))
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('SEGMENT_AUTH_FAILED')
    expect(result.failedAt).toBe(2)
  })

  it('rejects a swap of ANY two distinct frames, not just the demo default', () => {
    const n = LEDGER_SEGMENTS.length
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const { result } = openChained(KEY, reorder(seal(), i, j))
        expect(result.ok, `swap ${i}<->${j} must be rejected`).toBe(false)
      }
    }
  })

  it('rejects dropping ANY single frame', () => {
    for (let i = 0; i < LEDGER_SEGMENTS.length; i++) {
      const { result } = openChained(KEY, drop(seal(), i))
      expect(result.ok, `dropping ${i} must be rejected`).toBe(false)
    }
  })

  it('rejects truncation at EVERY length short of the full stream', () => {
    for (let cut = 1; cut < LEDGER_SEGMENTS.length; cut++) {
      const { result } = openChained(KEY, truncate(seal(), cut))
      expect(result.ok, `truncating ${cut} frame(s) must be rejected`).toBe(false)
      if (!result.ok) expect(result.code).toBe('TRUNCATED_STREAM')
    }
  })
})

describe('chained AEAD — other fail-closed paths', () => {
  it('rejects a single flipped bit anywhere in any frame', () => {
    const stream = seal()
    stream.frames.forEach((frame, i) => {
      const body = Uint8Array.from(frame.body)
      body[0] = (body[0] as number) ^ 0x01
      const frames = stream.frames.slice()
      frames[i] = { body }
      const { result } = openChained(KEY, { ...stream, frames })
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.failedAt).toBe(i)
    })
  })

  it('rejects a replayed frame', () => {
    const stream = seal()
    const frames = stream.frames.slice()
    frames[3] = frames[2] as Frame
    const { result } = openChained(KEY, { ...stream, frames })
    expect(result.ok).toBe(false)
  })

  it('rejects data appended after the FINAL segment', () => {
    const stream = seal()
    const frames = [...stream.frames, stream.frames[1] as Frame]
    const { result } = openChained(KEY, { ...stream, frames })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('TRAILING_DATA_AFTER_FINAL')
  })

  it('rejects a stream re-headed with a different header', () => {
    const stream = seal()
    const { result } = openChained(KEY, { ...stream, header: new Uint8Array(HEADER_BYTES).fill(0x5b) })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.failedAt).toBe(0)
  })

  it('rejects the wrong key', () => {
    const { result } = openChained(new Uint8Array(32).fill(8), seal())
    expect(result.ok).toBe(false)
  })

  it('rejects an empty stream', () => {
    const { result } = openChained(KEY, { ...seal(), frames: [] })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('EMPTY_STREAM')
  })

  it('refuses to seal a stream with no segments', () => {
    expect(() => sealChained(KEY, [])).toThrow()
  })
})
