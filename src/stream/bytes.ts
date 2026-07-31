/**
 * Byte helpers shared by the chained and naive constructions.
 * Deliberately tiny and dependency-free so the construction code below reads
 * as the spec it is meant to teach.
 */

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

/** Little-endian 64-bit encoding of a non-negative safe integer. */
export function u64le(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`u64le: not a safe non-negative integer: ${n}`)
  const out = new Uint8Array(8)
  let v = BigInt(n)
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/** Big-endian 32-bit encoding — the frame length prefix. */
export function u32be(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError(`u32be: out of range: ${n}`)
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff])
}

export function readU32be(bytes: Uint8Array, offset: number): number {
  const a = bytes[offset]
  const b = bytes[offset + 1]
  const c = bytes[offset + 2]
  const d = bytes[offset + 3]
  if (a === undefined || b === undefined || c === undefined || d === undefined) {
    throw new RangeError('readU32be: out of bounds')
  }
  return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d
}

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: false })

export function utf8(text: string): Uint8Array {
  return encoder.encode(text)
}

export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes)
}

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

/** First `n` bytes as hex, for the chain-state display. */
export function hexHead(bytes: Uint8Array, n: number): string {
  return toHex(bytes.subarray(0, n))
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}

/** Cryptographically strong random bytes (WebCrypto in the browser, node:crypto under Vitest). */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n)
  globalThis.crypto.getRandomValues(out)
  return out
}
