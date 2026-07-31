/**
 * The attacker's bench. Each function is a pure transformation of the wire frames —
 * exactly the power a network or storage attacker has over a sealed stream. None of
 * them touch the key, and none of them modify a single byte inside a frame: they only
 * remove frames or move them around.
 *
 * That restraint is the point. If reordering intact, individually-valid ciphertexts is
 * enough to change what the application reads, the construction is broken.
 */

import type { SealedStream } from './types.js'

export type AttackId = 'truncate' | 'reorder' | 'drop'

export interface Attack {
  readonly id: AttackId
  readonly label: string
  /** What the attacker physically did to the frame list. */
  readonly describe: (stream: SealedStream) => string
  readonly apply: (stream: SealedStream) => SealedStream
  /** Smallest stream this attack needs to be meaningful. */
  readonly minSegments: number
}

/** Drop the final `count` frames — the classic "cut the file short" storage attack. */
export function truncate(stream: SealedStream, count = 2): SealedStream {
  const keep = Math.max(1, stream.frames.length - count)
  return { ...stream, frames: stream.frames.slice(0, keep) }
}

/** Swap two frames. Bytes are untouched; only their positions change. */
export function reorder(stream: SealedStream, i: number, j: number): SealedStream {
  const frames = stream.frames.slice()
  const a = frames[i]
  const b = frames[j]
  if (a === undefined || b === undefined) throw new RangeError('reorder: index out of range')
  frames[i] = b
  frames[j] = a
  return { ...stream, frames }
}

/** Delete one frame from the middle of the stream. */
export function drop(stream: SealedStream, index: number): SealedStream {
  if (index < 0 || index >= stream.frames.length) throw new RangeError('drop: index out of range')
  return { ...stream, frames: stream.frames.filter((_, k) => k !== index) }
}

/**
 * The three buttons, with the default targets the demo uses against the sample ledger.
 * Chosen so each attack changes the *meaning* of the batch, not just its bytes.
 */
export const ATTACKS: readonly Attack[] = [
  {
    id: 'truncate',
    label: 'Truncate',
    minSegments: 3,
    describe: (s) => `Deleted the last 2 of ${s.frames.length} frames. Nothing else was touched.`,
    apply: (s) => truncate(s, 2),
  },
  {
    id: 'reorder',
    label: 'Reorder',
    minSegments: 4,
    describe: () => 'Swapped frames 2 and 3. Both frames are byte-for-byte the originals.',
    apply: (s) => reorder(s, 2, 3),
  },
  {
    id: 'drop',
    label: 'Drop',
    minSegments: 4,
    describe: () => 'Deleted frame 2 from the middle. The frames on either side are untouched.',
    apply: (s) => drop(s, 2),
  },
]

export function attackById(id: AttackId): Attack {
  const found = ATTACKS.find((a) => a.id === id)
  if (!found) throw new RangeError(`unknown attack: ${id}`)
  return found
}
