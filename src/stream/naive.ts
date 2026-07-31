/**
 * Naive split — the deliberately-broken control. NEVER the default mode.
 *
 * This is what "just chunk the file" actually looks like in the wild: split the
 * plaintext, encrypt each chunk under the same key with its own fresh random nonce,
 * and ship `nonce ‖ ciphertext‖tag` per chunk. The cryptography here is real and
 * correct — the same audited XChaCha20-Poly1305 the chained mode uses, with unique
 * nonces, so this is not a nonce-reuse bug and not a broken primitive.
 *
 * What is missing is *binding between chunks*: no sequence number, no rolling state,
 * no end-of-stream marker. Every chunk is a valid standalone message, so an attacker
 * can reorder, delete or truncate chunks and every surviving tag still verifies. The
 * verifier below is not sloppy — it checks every authenticator it is given. It simply
 * has nothing to check the *arrangement* against, and hands the application a plaintext
 * the sender never wrote.
 *
 * That is the §7.1 lesson: authenticated chunks do not make an authenticated stream.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { concatBytes, randomBytes } from './bytes.js'
import { NONCE_BYTES, TAG_BYTES } from './chained.js'
import type { Frame, OpenResult, SealedStream } from './types.js'

/** Per-segment overhead: the nonce that has to travel with each chunk, plus the tag. */
export const NAIVE_OVERHEAD = NONCE_BYTES + TAG_BYTES

export interface SealedNaive extends SealedStream {
  readonly mode: 'naive'
}

export function sealNaive(
  key: Uint8Array,
  segments: readonly Uint8Array[],
  header: Uint8Array = randomBytes(NONCE_BYTES),
  /** Test seam: supply the per-segment nonces instead of drawing them randomly. */
  nonces?: readonly Uint8Array[],
): SealedNaive {
  if (segments.length === 0) throw new RangeError('sealNaive: a stream needs at least one segment')

  const frames: Frame[] = segments.map((segment, i) => {
    const nonce = nonces?.[i] ?? randomBytes(NONCE_BYTES)
    // No AAD, no sequence number, no final marker — that is the whole point.
    const body = xchacha20poly1305(key, nonce).encrypt(segment)
    return { body, nonce }
  })

  return { mode: 'naive', header, frames, chainStates: [] }
}

/**
 * Verify and decrypt a naively-split stream.
 *
 * Every tag is genuinely checked. A bit-flip inside any chunk is still caught. What
 * is not caught — cannot be caught — is anything done to the *order or completeness*
 * of the chunk list.
 */
export function openNaive(key: Uint8Array, stream: SealedStream): OpenResult {
  if (stream.frames.length === 0) {
    return {
      ok: false,
      code: 'EMPTY_STREAM',
      reason: 'The stream carries no segments at all — nothing to authenticate.',
      failedAt: -1,
      segmentsAccepted: 0,
      releasedBeforeAbort: [],
    }
  }

  const segments: Uint8Array[] = []

  for (let i = 0; i < stream.frames.length; i++) {
    const frame = stream.frames[i] as Frame
    if (!frame.nonce || frame.nonce.length !== NONCE_BYTES) {
      return {
        ok: false,
        code: 'MALFORMED_FRAME',
        reason: `Segment ${i} is missing its ${NONCE_BYTES}-byte nonce prefix.`,
        failedAt: i,
        segmentsAccepted: i,
        releasedBeforeAbort: segments,
      }
    }
    try {
      segments.push(xchacha20poly1305(key, frame.nonce).decrypt(frame.body))
    } catch {
      return {
        ok: false,
        code: 'SEGMENT_AUTH_FAILED',
        reason: `Poly1305 rejected segment ${i} — this chunk's own bytes were altered.`,
        failedAt: i,
        segmentsAccepted: i,
        releasedBeforeAbort: segments,
      }
    }
  }

  // Every chunk authenticated, so this verifier is satisfied. It has no way to ask
  // whether these are all the chunks, or whether they are in the order they were written.
  return {
    ok: true,
    plaintext: concatBytes(...segments),
    segments,
    segmentsAccepted: segments.length,
    sawFinal: false,
  }
}
