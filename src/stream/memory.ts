/**
 * The memory half — MODELLED, and labelled as such everywhere it is shown.
 *
 * Nothing here measures a real process. What it does do is run a real allocation
 * ledger: `AllocTracker` is charged and credited by a simulator that walks the actual
 * control flow of each decryption strategy, one buffer at a time, and the meters in the
 * UI read that ledger. So the numbers are derived from tracked buffer allocations —
 * they are not a hand-drawn curve, and they are not process RSS either.
 *
 * The two strategies differ in exactly one structural way:
 *
 *   One-shot  — a single AEAD tag covers the whole file, so not one byte of plaintext
 *               may be released until the last byte of ciphertext has been read. The
 *               entire ciphertext must be resident, and then the plaintext output
 *               buffer is allocated on top of it. Peak ≈ 2 × file size.
 *   Chunked   — each segment carries its own tag, so a segment can be verified,
 *               released and freed before the next one is read. Peak ≈ 2 × chunk size,
 *               flat in the file size.
 */

/** Long-lived state a streaming decryptor holds: key + stream header + chain state + nonce. */
export const STATE_BYTES = 32 + 24 + 32 + 24

/** Size of the reads a one-shot decryptor uses while buffering the file. */
export const READ_BLOCK_BYTES = 1 << 20 // 1 MiB

export type Strategy = 'one-shot' | 'chunked'

/** What the process is doing at a given sample — shown as the meter's phase label. */
export type Phase = 'idle' | 'buffering' | 'allocating-output' | 'verifying' | 'streaming' | 'done' | 'oom'

export interface MemorySample {
  /** Bytes of the file processed so far. */
  readonly progressBytes: number
  /** Live tracked allocation at this instant. */
  readonly liveBytes: number
  readonly phase: Phase
}

export interface MemoryRun {
  readonly strategy: Strategy
  readonly fileBytes: number
  readonly chunkBytes: number
  readonly ramLimitBytes: number
  readonly samples: readonly MemorySample[]
  /** Highest live allocation reached before the run ended (or was killed). */
  readonly peakBytes: number
  /** Total bytes ever handed out by the tracker — the allocation churn. */
  readonly allocatedBytes: number
  /** Number of tracked allocation calls. */
  readonly allocCount: number
  readonly oom: boolean
  /** Bytes of the file processed when the limit was blown, or null. */
  readonly oomAtBytes: number | null
  /** Segments the strategy processes end to end. */
  readonly segmentCount: number
}

/**
 * A plain allocation ledger. Every buffer a simulator would need is charged here and
 * credited when it goes out of scope; `peak` is the high-water mark the meters render.
 */
export class AllocTracker {
  #live = 0
  #peak = 0
  #allocated = 0
  #allocCount = 0

  alloc(bytes: number): void {
    if (bytes < 0) throw new RangeError('AllocTracker.alloc: negative size')
    this.#live += bytes
    this.#allocated += bytes
    this.#allocCount += 1
    if (this.#live > this.#peak) this.#peak = this.#live
  }

  free(bytes: number): void {
    if (bytes < 0) throw new RangeError('AllocTracker.free: negative size')
    if (bytes > this.#live) throw new RangeError('AllocTracker.free: freeing more than is live')
    this.#live -= bytes
  }

  get live(): number {
    return this.#live
  }
  get peak(): number {
    return this.#peak
  }
  get allocated(): number {
    return this.#allocated
  }
  get allocCount(): number {
    return this.#allocCount
  }
}

/** Roughly how many samples the UI wants for a smooth meter, per phase. */
const SAMPLE_TARGET = 180

/**
 * One-shot AEAD decrypt: buffer the entire ciphertext, verify the single tag over all
 * of it, then allocate the plaintext output buffer.
 */
export function simulateOneShot(fileBytes: number, ramLimitBytes: number, chunkBytes: number): MemoryRun {
  const t = new AllocTracker()
  const samples: MemorySample[] = []
  t.alloc(STATE_BYTES)
  samples.push({ progressBytes: 0, liveBytes: t.live, phase: 'idle' })

  const blocks = Math.max(1, Math.ceil(fileBytes / READ_BLOCK_BYTES))
  const stride = Math.max(1, Math.floor(blocks / SAMPLE_TARGET))

  // Phase 1 — read the whole ciphertext in. Nothing can be released yet: the tag
  // covers the entire file, so a partial read proves nothing.
  let read = 0
  for (let b = 0; b < blocks; b++) {
    const size = Math.min(READ_BLOCK_BYTES, fileBytes - read)
    t.alloc(size)
    read += size
    if (t.live > ramLimitBytes) {
      samples.push({ progressBytes: read, liveBytes: t.live, phase: 'oom' })
      return finish(t, samples, 'one-shot', fileBytes, chunkBytes, ramLimitBytes, true, read, 1)
    }
    if (b % stride === 0 || b === blocks - 1) {
      samples.push({ progressBytes: read, liveBytes: t.live, phase: 'buffering' })
    }
  }

  samples.push({ progressBytes: fileBytes, liveBytes: t.live, phase: 'verifying' })

  // Phase 2 — the output buffer is a single allocation, so the meter jumps rather
  // than creeps. A file that survived the read can still die right here.
  t.alloc(fileBytes)
  if (t.live > ramLimitBytes) {
    samples.push({ progressBytes: fileBytes, liveBytes: t.live, phase: 'oom' })
    return finish(t, samples, 'one-shot', fileBytes, chunkBytes, ramLimitBytes, true, fileBytes, 1)
  }
  samples.push({ progressBytes: fileBytes, liveBytes: t.live, phase: 'allocating-output' })
  samples.push({ progressBytes: fileBytes, liveBytes: t.live, phase: 'done' })

  return finish(t, samples, 'one-shot', fileBytes, chunkBytes, ramLimitBytes, false, null, 1)
}

/**
 * Chunked stream decrypt: read one segment, verify its own tag, release its plaintext,
 * free both buffers, repeat. The loop below is the real control flow — it runs once per
 * segment, all 163,840 of them at 10 GiB with 64 KiB chunks.
 */
export function simulateChunked(
  fileBytes: number,
  ramLimitBytes: number,
  chunkBytes: number,
  overheadBytes: number,
): MemoryRun {
  const t = new AllocTracker()
  const samples: MemorySample[] = []
  t.alloc(STATE_BYTES)
  samples.push({ progressBytes: 0, liveBytes: t.live, phase: 'idle' })

  const segments = Math.max(1, Math.ceil(fileBytes / chunkBytes))
  const stride = Math.max(1, Math.floor(segments / SAMPLE_TARGET))

  let done = 0
  for (let i = 0; i < segments; i++) {
    const plain = Math.min(chunkBytes, fileBytes - done)
    const cipher = plain + overheadBytes
    const record = i % stride === 0 || i === segments - 1

    t.alloc(cipher) // read this segment's frame
    if (t.live > ramLimitBytes) {
      samples.push({ progressBytes: done, liveBytes: t.live, phase: 'oom' })
      return finish(t, samples, 'chunked', fileBytes, chunkBytes, ramLimitBytes, true, done, segments)
    }

    t.alloc(plain) // decrypt into a fresh plaintext buffer
    if (t.live > ramLimitBytes) {
      samples.push({ progressBytes: done, liveBytes: t.live, phase: 'oom' })
      return finish(t, samples, 'chunked', fileBytes, chunkBytes, ramLimitBytes, true, done, segments)
    }
    done += plain
    if (record) samples.push({ progressBytes: done, liveBytes: t.live, phase: 'streaming' })

    t.free(cipher) // frame verified — the ciphertext is dead weight now
    t.free(plain) // plaintext handed to the sink
    if (record) samples.push({ progressBytes: done, liveBytes: t.live, phase: 'streaming' })
  }

  samples.push({ progressBytes: fileBytes, liveBytes: t.live, phase: 'done' })
  return finish(t, samples, 'chunked', fileBytes, chunkBytes, ramLimitBytes, false, null, segments)
}

function finish(
  t: AllocTracker,
  samples: MemorySample[],
  strategy: Strategy,
  fileBytes: number,
  chunkBytes: number,
  ramLimitBytes: number,
  oom: boolean,
  oomAtBytes: number | null,
  segmentCount: number,
): MemoryRun {
  return {
    strategy,
    fileBytes,
    chunkBytes,
    ramLimitBytes,
    samples,
    peakBytes: t.peak,
    allocatedBytes: t.allocated,
    allocCount: t.allocCount,
    oom,
    oomAtBytes,
    segmentCount,
  }
}

/**
 * How much memory a strategy needs to run the file to completion — the number the
 * exhibit quotes next to the ceiling. For one-shot this is what it *would* have needed
 * had it not been killed, which is the honest comparison: a killed run's peak only
 * tells you where the limit was, not what the strategy costs.
 */
export function requiredBytes(
  strategy: Strategy,
  fileBytes: number,
  chunkBytes: number,
  overheadBytes: number,
): number {
  if (strategy === 'one-shot') return 2 * fileBytes + STATE_BYTES
  const segment = Math.min(chunkBytes, fileBytes)
  return 2 * segment + overheadBytes + STATE_BYTES
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'] as const

/** Binary units throughout — 1 MiB is 1,048,576 bytes, and the labels say so. */
export function formatBytes(bytes: number): string {
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit += 1
  }
  const digits = value >= 100 || unit === 0 ? 0 : value >= 10 ? 1 : 2
  return `${value.toFixed(digits)} ${UNITS[unit]}`
}

export function formatCount(n: number): string {
  return n.toLocaleString('en-US')
}
