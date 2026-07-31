import { describe, expect, it } from 'vitest'
import { toHex, u32be, u64le, utf8 } from './bytes.js'
import { sealChained, openChained, HEADER_BYTES } from './chained.js'
import { openNaive, sealNaive } from './naive.js'
import { LEDGER_SEGMENTS } from './payload.js'
import { PREAMBLE_BYTES, WireFormatError, decodeStream, encodeStream, wireSize } from './wire.js'
import { truncate } from './attacks.js'

const KEY = new Uint8Array(32).fill(7)
const HEADER = new Uint8Array(HEADER_BYTES).fill(0x5a)

describe('byte helpers', () => {
  it('encodes little-endian u64', () => {
    expect(toHex(u64le(0))).toBe('0000000000000000')
    expect(toHex(u64le(1))).toBe('0100000000000000')
    expect(toHex(u64le(258))).toBe('0201000000000000')
  })

  it('encodes big-endian u32 and rejects out-of-range values', () => {
    expect(toHex(u32be(258))).toBe('00000102')
    expect(() => u32be(-1)).toThrow()
    expect(() => u32be(0x1_0000_0000)).toThrow()
  })
})

describe('wire encoding — chained', () => {
  it('round-trips through bytes and still verifies', () => {
    const sealed = sealChained(KEY, LEDGER_SEGMENTS, HEADER)
    const decoded = decodeStream(encodeStream(sealed))
    expect(decoded.mode).toBe('chained')
    expect(toHex(decoded.header)).toBe(toHex(HEADER))
    expect(openChained(KEY, decoded).result.ok).toBe(true)
  })

  it('an attack applied to the bytes survives the round trip', () => {
    const sealed = sealChained(KEY, LEDGER_SEGMENTS, HEADER)
    const decoded = decodeStream(encodeStream(truncate(sealed, 2)))
    expect(decoded.frames.length).toBe(LEDGER_SEGMENTS.length - 2)
    const { result } = openChained(KEY, decoded)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.code).toBe('TRUNCATED_STREAM')
  })

  it('quotes a wire size equal to preamble + per-frame length prefix + bodies', () => {
    const sealed = sealChained(KEY, LEDGER_SEGMENTS, HEADER)
    const bodies = sealed.frames.reduce((n, f) => n + f.body.length, 0)
    expect(wireSize(sealed)).toBe(PREAMBLE_BYTES + 4 * sealed.frames.length + bodies)
  })
})

describe('wire encoding — naive', () => {
  it('round-trips the per-chunk nonce and still verifies', () => {
    const sealed = sealNaive(KEY, LEDGER_SEGMENTS, HEADER)
    const decoded = decodeStream(encodeStream(sealed))
    expect(decoded.mode).toBe('naive')
    expect(openNaive(KEY, decoded).ok).toBe(true)
  })

  it('costs more on the wire than chaining, for the same plaintext', () => {
    const chained = wireSize(sealChained(KEY, LEDGER_SEGMENTS, HEADER))
    const naive = wireSize(sealNaive(KEY, LEDGER_SEGMENTS, HEADER))
    expect(naive).toBeGreaterThan(chained)
  })
})

describe('wire parsing is strict', () => {
  const sealed = sealChained(KEY, LEDGER_SEGMENTS, HEADER)
  const bytes = encodeStream(sealed)

  it('rejects a buffer shorter than the preamble', () => {
    expect(() => decodeStream(bytes.slice(0, PREAMBLE_BYTES - 1))).toThrow(WireFormatError)
  })

  it('rejects bad magic', () => {
    const bad = Uint8Array.from(bytes)
    bad[0] = 0x00
    expect(() => decodeStream(bad)).toThrow(/magic/)
  })

  it('rejects an unknown mode byte', () => {
    const bad = Uint8Array.from(bytes)
    bad[4] = 0x09
    expect(() => decodeStream(bad)).toThrow(/mode byte/)
  })

  it('rejects a length that runs past the end', () => {
    const bad = Uint8Array.from(bytes)
    bad.set(u32be(0xffff), PREAMBLE_BYTES)
    expect(() => decodeStream(bad)).toThrow(/past the end/)
  })

  it('rejects a zero-length frame', () => {
    const bad = Uint8Array.from(bytes)
    bad.set(u32be(0), PREAMBLE_BYTES)
    expect(() => decodeStream(bad)).toThrow(/zero-length/)
  })

  it('rejects a dangling length prefix', () => {
    expect(() => decodeStream(bytes.slice(0, PREAMBLE_BYTES + 2))).toThrow(/truncated frame length/)
  })

  it('rejects a naive frame too short to hold a nonce', () => {
    const naive = encodeStream(sealNaive(KEY, [utf8('x')], HEADER))
    const bad = Uint8Array.from(naive)
    bad.set(u32be(4), PREAMBLE_BYTES)
    expect(() => decodeStream(bad.slice(0, PREAMBLE_BYTES + 8))).toThrow(/too short/)
  })

  it('refuses to encode a naive frame that lost its nonce', () => {
    const sealedNaive = sealNaive(KEY, LEDGER_SEGMENTS, HEADER)
    const frames = sealedNaive.frames.slice()
    frames[0] = { body: sealedNaive.frames[0]!.body }
    expect(() => encodeStream({ ...sealedNaive, frames })).toThrow(WireFormatError)
  })
})
