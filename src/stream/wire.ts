/**
 * The on-the-wire encoding. The attacks operate on frames, but frames are only
 * meaningful because they are a real, parseable byte layout — this module is what
 * makes "the attacker deleted two frames" a statement about bytes on a disk rather
 * than about an array in memory.
 *
 *   chained:  "SWv1" ‖ 0x01 ‖ header[24] ‖ ( len:u32be ‖ ct‖tag )*
 *   naive:    "SWv1" ‖ 0x02 ‖ header[24] ‖ ( len:u32be ‖ nonce[24] ‖ ct‖tag )*
 *
 * Parsing is strict: any length that runs past the end of the buffer, any trailing
 * byte that is not a whole frame, and any unknown mode byte is a hard reject. A
 * lenient parser here would quietly hand the verifier a stream the sender never wrote,
 * which is the same class of bug the demo is about.
 */

import { concatBytes, readU32be, u32be, utf8 } from './bytes.js'
import { NONCE_BYTES } from './chained.js'
import type { Frame, Mode, SealedStream } from './types.js'

export const MAGIC = utf8('SWv1')
export const MODE_BYTE: Record<Mode, number> = { chained: 0x01, naive: 0x02 }
export const HEADER_LEN = 24
/** magic + mode byte + stream header. */
export const PREAMBLE_BYTES = MAGIC.length + 1 + HEADER_LEN

export class WireFormatError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'WireFormatError'
  }
}

export function encodeStream(stream: SealedStream): Uint8Array {
  const parts: Uint8Array[] = [MAGIC, new Uint8Array([MODE_BYTE[stream.mode]]), stream.header]
  for (const frame of stream.frames) {
    if (stream.mode === 'naive') {
      if (!frame.nonce || frame.nonce.length !== NONCE_BYTES) {
        throw new WireFormatError('naive frames must carry a 24-byte nonce')
      }
      parts.push(u32be(frame.nonce.length + frame.body.length), frame.nonce, frame.body)
    } else {
      parts.push(u32be(frame.body.length), frame.body)
    }
  }
  return concatBytes(...parts)
}

export function decodeStream(bytes: Uint8Array): SealedStream {
  if (bytes.length < PREAMBLE_BYTES) throw new WireFormatError('stream is shorter than its preamble')
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) throw new WireFormatError('bad magic — this is not a Stream Ward stream')
  }
  const modeByte = bytes[MAGIC.length]
  const mode: Mode | undefined =
    modeByte === MODE_BYTE.chained ? 'chained' : modeByte === MODE_BYTE.naive ? 'naive' : undefined
  if (!mode) throw new WireFormatError(`unknown mode byte 0x${(modeByte ?? 0).toString(16)}`)

  const header = bytes.slice(MAGIC.length + 1, PREAMBLE_BYTES)
  const frames: Frame[] = []
  let off = PREAMBLE_BYTES

  while (off < bytes.length) {
    if (off + 4 > bytes.length) throw new WireFormatError('truncated frame length prefix')
    const len = readU32be(bytes, off)
    off += 4
    if (len === 0) throw new WireFormatError('zero-length frame')
    if (off + len > bytes.length) throw new WireFormatError('frame length runs past the end of the stream')
    if (mode === 'naive') {
      if (len <= NONCE_BYTES) throw new WireFormatError('naive frame is too short to hold a nonce and a tag')
      frames.push({ nonce: bytes.slice(off, off + NONCE_BYTES), body: bytes.slice(off + NONCE_BYTES, off + len) })
    } else {
      frames.push({ body: bytes.slice(off, off + len) })
    }
    off += len
  }

  return { mode, header, frames, chainStates: [] }
}

/** Total bytes this stream occupies on disk — what the overhead comparison quotes. */
export function wireSize(stream: SealedStream): number {
  return encodeStream(stream).length
}
