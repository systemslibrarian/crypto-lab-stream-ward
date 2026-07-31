/** Shared vocabulary for both stream constructions. */

/** Which construction produced (or is verifying) a stream. */
export type Mode = 'chained' | 'naive'

/**
 * Segment role, bound into the AAD of every chained segment.
 * The FINAL marker is what makes truncation cryptographically detectable:
 * a truncated stream ends on a segment whose authenticator says MESSAGE.
 */
export const TAG_MESSAGE = 0x00
export const TAG_FINAL = 0x01

/** One wire frame: the length-prefixed unit an attacker can move around. */
export interface Frame {
  /** Ciphertext ‖ Poly1305 tag. In naive mode the 24-byte nonce is carried separately. */
  readonly body: Uint8Array
  /** Naive mode ships a per-segment nonce alongside the ciphertext; chained mode derives it. */
  readonly nonce?: Uint8Array
}

/** A sealed stream, as it would sit on disk or on the wire. */
export interface SealedStream {
  readonly mode: Mode
  /** 24-byte public stream header. Chained: the chain seed / nonce base. Naive: unused label. */
  readonly header: Uint8Array
  readonly frames: readonly Frame[]
  /** Rolling chain state after each segment, for the visualization. Empty in naive mode. */
  readonly chainStates: readonly Uint8Array[]
}

/** Why a verifier stopped. Every value is produced by verification, never by inspecting the attack. */
export type FailureCode =
  | 'SEGMENT_AUTH_FAILED'
  | 'TRUNCATED_STREAM'
  | 'TRAILING_DATA_AFTER_FINAL'
  | 'EMPTY_STREAM'
  | 'MALFORMED_FRAME'

export interface OpenSuccess {
  readonly ok: true
  /** Plaintext the verifier is willing to hand to the application. */
  readonly plaintext: Uint8Array
  /** Per-segment plaintext, in delivery order. */
  readonly segments: readonly Uint8Array[]
  /** Segments the verifier authenticated before returning. */
  readonly segmentsAccepted: number
  /** True when the stream ended on a segment whose AAD said FINAL. */
  readonly sawFinal: boolean
}

export interface OpenFailure {
  readonly ok: false
  readonly code: FailureCode
  /** Human-readable reason, derived only from what verification observed. */
  readonly reason: string
  /** Index of the segment the verifier stopped at, or -1. */
  readonly failedAt: number
  /** Segments authenticated before the stop. A fail-closed verifier releases none of them. */
  readonly segmentsAccepted: number
  /**
   * Plaintext a *non*-fail-closed caller would already have consumed by the time the
   * abort fired. Shown in the UI as "released before abort" — never as accepted output.
   */
  readonly releasedBeforeAbort: readonly Uint8Array[]
}

export type OpenResult = OpenSuccess | OpenFailure
