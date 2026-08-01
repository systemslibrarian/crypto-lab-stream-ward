/**
 * Stream Ward — a secretstream-style chained AEAD.
 *
 * Hand-rolled on top of real XChaCha20-Poly1305 (@noble/ciphers, verified against
 * draft-irtf-cfrg-xchacha-03 Appendix A.1 / A.3.1 KATs in kat.test.ts) and real SHA-256
 * (@noble/hashes, verified against FIPS 180-4 KATs). The *chaining* — the part this
 * demo exists to teach — is written out here in full rather than hidden in a library,
 * so every byte that goes into an authenticator is inspectable.
 *
 * Construction, per segment i of n:
 *
 *   chain[0]   = SHA-256( DOMAIN ‖ "chain-init" ‖ header )
 *   nonce[i]   = SHA-256( DOMAIN ‖ "nonce" ‖ chain[i] ‖ LE64(i) )[0..24]
 *   aad[i]     = DOMAIN ‖ "seg" ‖ LE64(i) ‖ chain[i]
 *   inner[i]   = flag[i] ‖ plaintext[i]           flag = 0x01 on the last segment, else 0x00
 *   ct[i]      = XChaCha20-Poly1305(key, nonce[i], aad[i]).encrypt(inner[i])
 *   chain[i+1] = SHA-256( DOMAIN ‖ "chain" ‖ chain[i] ‖ LE64(i) ‖ ct[i] )
 *
 * Three properties fall straight out of that, and they are the three attacks:
 *
 *   Reorder / drop — chain[i] absorbs *every previous ciphertext including its
 *     Poly1305 tag*, and the sequence number LE64(i) is in the AAD. A segment moved
 *     to a different position is authenticated against a chain state and an index
 *     that its tag does not cover, so Poly1305 rejects it.
 *   Truncate — the FINAL flag lives inside the encrypted, authenticated block (as in
 *     libsodium's crypto_secretstream). A truncated stream simply runs out of frames
 *     while the last one it did deliver authenticates as a MESSAGE, not a FINAL.
 *
 * Not secret, deliberately: chain[i] is public binding material derived from the
 * header and the ciphertexts. Confidentiality comes from the key alone; the chain
 * buys ordering and completeness, nothing else.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes, randomBytes, u64le, utf8 } from './bytes.js'
import { TAG_FINAL, TAG_MESSAGE, type Frame, type OpenResult, type SealedStream } from './types.js'

/** Domain separator — keeps these hashes from ever colliding with another protocol's. */
export const DOMAIN = utf8('crypto-lab/stream-ward/v1')

export const HEADER_BYTES = 24
export const NONCE_BYTES = 24
export const TAG_BYTES = 16
/** Overhead the chained construction adds per segment: the flag byte + the Poly1305 tag. */
export const CHAINED_OVERHEAD = 1 + TAG_BYTES

const L_CHAIN_INIT = utf8('chain-init')
const L_NONCE = utf8('nonce')
const L_SEG = utf8('seg')
const L_CHAIN = utf8('chain')

/** One encryption step, exposed so the UI can show the real bytes rather than assert them. */
export interface ChainStep {
  readonly index: number
  readonly chainIn: Uint8Array
  readonly nonce: Uint8Array
  readonly aad: Uint8Array
  readonly ciphertext: Uint8Array
  readonly chainOut: Uint8Array
  readonly flag: number
}

export interface SealedChained extends SealedStream {
  readonly mode: 'chained'
  readonly steps: readonly ChainStep[]
}

/** One verification step, as observed by the verifier — never by peeking at the attack. */
export interface VerifyStep {
  readonly index: number
  readonly chainIn: Uint8Array
  readonly nonce: Uint8Array
  readonly ok: boolean
  /** The flag byte recovered from inside the authenticated block; -1 if it never decrypted. */
  readonly flag: number
}

export function initialChain(header: Uint8Array): Uint8Array {
  return sha256(concatBytes(DOMAIN, L_CHAIN_INIT, header))
}

export function deriveNonce(chain: Uint8Array, index: number): Uint8Array {
  return sha256(concatBytes(DOMAIN, L_NONCE, chain, u64le(index))).subarray(0, NONCE_BYTES)
}

export function deriveAad(chain: Uint8Array, index: number): Uint8Array {
  return concatBytes(DOMAIN, L_SEG, u64le(index), chain)
}

export function advanceChain(chain: Uint8Array, index: number, ciphertext: Uint8Array): Uint8Array {
  return sha256(concatBytes(DOMAIN, L_CHAIN, chain, u64le(index), ciphertext))
}

/**
 * Seal plaintext segments into a chained stream.
 * `header` is normally left undefined so a fresh random stream header (and therefore a
 * fresh nonce sequence) is drawn; the tests pass one in for determinism.
 */
export function sealChained(
  key: Uint8Array,
  segments: readonly Uint8Array[],
  header: Uint8Array = randomBytes(HEADER_BYTES),
): SealedChained {
  if (segments.length === 0) throw new RangeError('sealChained: a stream needs at least one segment')

  const frames: Frame[] = []
  const steps: ChainStep[] = []
  const chainStates: Uint8Array[] = []

  let chain = initialChain(header)
  chainStates.push(chain)

  for (let i = 0; i < segments.length; i++) {
    const flag = i === segments.length - 1 ? TAG_FINAL : TAG_MESSAGE
    const nonce = deriveNonce(chain, i)
    const aad = deriveAad(chain, i)
    const inner = concatBytes(new Uint8Array([flag]), segments[i] as Uint8Array)
    const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(inner)

    const chainOut = advanceChain(chain, i, ciphertext)
    frames.push({ body: ciphertext })
    steps.push({ index: i, chainIn: chain, nonce, aad, ciphertext, chainOut, flag })
    chain = chainOut
    chainStates.push(chain)
  }

  return { mode: 'chained', header, frames, chainStates, steps }
}

export interface OpenChainedResult {
  readonly result: OpenResult
  readonly trace: readonly VerifyStep[]
}

/**
 * Verify and decrypt a chained stream.
 *
 * Fail-closed: the moment a segment fails to authenticate, or the stream ends without a
 * FINAL, the verifier stops and reports. `releasedBeforeAbort` records the prefix a
 * streaming consumer would already have acted on — genuinely authentic, genuinely
 * in order, and still not a complete file. That gap is the honest lesson of the
 * truncation attack, and the UI says so.
 */
export function openChained(key: Uint8Array, stream: SealedStream): OpenChainedResult {
  const trace: VerifyStep[] = []
  const released: Uint8Array[] = []

  if (stream.frames.length === 0) {
    return {
      result: {
        ok: false,
        code: 'EMPTY_STREAM',
        reason: 'The stream carries no segments at all — nothing to authenticate.',
        failedAt: -1,
        segmentsAccepted: 0,
        releasedBeforeAbort: [],
      },
      trace,
    }
  }

  let chain = initialChain(stream.header)

  for (let i = 0; i < stream.frames.length; i++) {
    const frame = stream.frames[i] as Frame
    const nonce = deriveNonce(chain, i)
    const aad = deriveAad(chain, i)

    let inner: Uint8Array
    try {
      inner = xchacha20poly1305(key, nonce, aad).decrypt(frame.body)
    } catch {
      trace.push({ index: i, chainIn: chain, nonce, ok: false, flag: -1 })
      return {
        result: {
          ok: false,
          code: 'SEGMENT_AUTH_FAILED',
          reason:
            `Poly1305 rejected segment ${i}. Its authenticator does not cover sequence number ${i} ` +
            `together with the chain state this position reached, so the bytes sitting here are not ` +
            `the bytes the sender put here.`,
          failedAt: i,
          segmentsAccepted: i,
          releasedBeforeAbort: released,
        },
        trace,
      }
    }

    if (inner.length < 1) {
      trace.push({ index: i, chainIn: chain, nonce, ok: false, flag: -1 })
      return {
        result: {
          ok: false,
          code: 'MALFORMED_FRAME',
          reason: `Segment ${i} authenticated but carries no flag byte — the frame is malformed.`,
          failedAt: i,
          segmentsAccepted: i,
          releasedBeforeAbort: released,
        },
        trace,
      }
    }

    const flag = inner[0] as number
    const plaintext = inner.subarray(1)
    trace.push({ index: i, chainIn: chain, nonce, ok: true, flag })

    const isLastFrame = i === stream.frames.length - 1

    if (flag === TAG_FINAL && !isLastFrame) {
      return {
        result: {
          ok: false,
          code: 'TRAILING_DATA_AFTER_FINAL',
          reason:
            `Segment ${i} authenticates as FINAL but ${stream.frames.length - i - 1} more frame(s) follow it. ` +
            `Something was appended to a completed stream.`,
          failedAt: i + 1,
          segmentsAccepted: i + 1,
          releasedBeforeAbort: released,
        },
        trace,
      }
    }

    released.push(plaintext)

    if (flag === TAG_FINAL) {
      return {
        result: {
          ok: true,
          plaintext: concatBytes(...released),
          segments: released,
          segmentsAccepted: released.length,
          sawFinal: true,
        },
        trace,
      }
    }

    chain = advanceChain(chain, i, frame.body)
  }

  // Ran out of frames while the last one still said MESSAGE.
  return {
    result: {
      ok: false,
      code: 'TRUNCATED_STREAM',
      reason:
        `The stream ended after ${stream.frames.length} segment(s), and segment ${stream.frames.length - 1} ` +
        `authenticates as MESSAGE, not FINAL. Every delivered segment is genuine and in order, but the ` +
        `sender did not stop here — the tail was cut off.`,
      failedAt: stream.frames.length,
      segmentsAccepted: stream.frames.length,
      releasedBeforeAbort: released,
    },
    trace,
  }
}
