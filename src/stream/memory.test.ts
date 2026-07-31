/**
 * The memory model. These tests pin the two claims the exhibit makes on screen:
 * one-shot peak grows with the file, chunked peak does not — and both numbers come
 * out of the allocation ledger rather than a drawn curve.
 */

import { describe, expect, it } from 'vitest'
import {
  AllocTracker,
  READ_BLOCK_BYTES,
  STATE_BYTES,
  formatBytes,
  requiredBytes,
  simulateChunked,
  simulateOneShot,
} from './memory.js'
import { CHAINED_OVERHEAD } from './chained.js'

const MiB = 1 << 20
const GiB = 1 << 30
const CHUNK = 64 * 1024
const LIMIT = 2 * GiB

describe('AllocTracker', () => {
  it('tracks live, peak, and churn independently', () => {
    const t = new AllocTracker()
    t.alloc(100)
    t.alloc(50)
    expect(t.live).toBe(150)
    t.free(100)
    expect(t.live).toBe(50)
    expect(t.peak).toBe(150)
    expect(t.allocated).toBe(150)
    expect(t.allocCount).toBe(2)
  })

  it('refuses to free more than is live', () => {
    const t = new AllocTracker()
    t.alloc(10)
    expect(() => t.free(11)).toThrow()
  })

  it('refuses negative sizes', () => {
    const t = new AllocTracker()
    expect(() => t.alloc(-1)).toThrow()
    expect(() => t.free(-1)).toThrow()
  })
})

describe('one-shot decrypt model', () => {
  it('peaks at about twice the file size when RAM allows', () => {
    const run = simulateOneShot(64 * MiB, LIMIT, CHUNK)
    expect(run.oom).toBe(false)
    expect(run.peakBytes).toBe(2 * 64 * MiB + STATE_BYTES)
  })

  it('reads the file in 1 MiB blocks, so the climb is genuinely incremental', () => {
    const run = simulateOneShot(8 * MiB, LIMIT, CHUNK)
    // 1 state alloc + 8 read blocks + 1 output buffer
    expect(run.allocCount).toBe(1 + 8 * (MiB / READ_BLOCK_BYTES) + 1)
  })

  it('OOMs during the read when the file alone exceeds the limit', () => {
    const run = simulateOneShot(10 * GiB, 2 * GiB, CHUNK)
    expect(run.oom).toBe(true)
    expect(run.oomAtBytes).toBeGreaterThan(2 * GiB - READ_BLOCK_BYTES)
    expect(run.oomAtBytes).toBeLessThan(10 * GiB)
    expect(run.samples.at(-1)?.phase).toBe('oom')
  })

  it('OOMs on the output buffer when the file fits but twice the file does not', () => {
    const run = simulateOneShot(3 * GiB, 4 * GiB, CHUNK)
    expect(run.oom).toBe(true)
    expect(run.oomAtBytes).toBe(3 * GiB)
  })

  it('survives when twice the file fits', () => {
    const run = simulateOneShot(1 * GiB, 4 * GiB, CHUNK)
    expect(run.oom).toBe(false)
    expect(run.samples.at(-1)?.phase).toBe('done')
  })

  it('never reports a sample above the limit unless it is the OOM sample', () => {
    const run = simulateOneShot(10 * GiB, 2 * GiB, CHUNK)
    run.samples.slice(0, -1).forEach((s) => expect(s.liveBytes).toBeLessThanOrEqual(2 * GiB))
  })
})

describe('chunked stream decrypt model', () => {
  it('peaks at about two chunks regardless of file size', () => {
    const small = simulateChunked(1 * MiB, LIMIT, CHUNK, CHAINED_OVERHEAD)
    const huge = simulateChunked(10 * GiB, LIMIT, CHUNK, CHAINED_OVERHEAD)
    expect(small.peakBytes).toBe(huge.peakBytes)
    expect(huge.peakBytes).toBe(2 * CHUNK + CHAINED_OVERHEAD + STATE_BYTES)
  })

  it('never OOMs, at any file size the slider reaches', () => {
    for (const size of [1 * MiB, 128 * MiB, 1 * GiB, 10 * GiB]) {
      expect(simulateChunked(size, 512 * MiB, CHUNK, CHAINED_OVERHEAD).oom).toBe(false)
    }
  })

  it('really walks every segment — 163,840 of them at 10 GiB / 64 KiB', () => {
    const run = simulateChunked(10 * GiB, LIMIT, CHUNK, CHAINED_OVERHEAD)
    expect(run.segmentCount).toBe((10 * GiB) / CHUNK)
    // one state alloc + two allocations per segment
    expect(run.allocCount).toBe(1 + 2 * run.segmentCount)
  })

  it('oscillates: live memory returns to the floor after every segment', () => {
    const run = simulateChunked(4 * MiB, LIMIT, CHUNK, CHAINED_OVERHEAD)
    const lows = run.samples.filter((s) => s.liveBytes === STATE_BYTES)
    expect(lows.length).toBeGreaterThan(10)
    expect(run.samples.at(-1)?.liveBytes).toBe(STATE_BYTES)
  })

  it('moves the same total bytes as one-shot, in far smaller pieces', () => {
    const size = 64 * MiB
    const one = simulateOneShot(size, LIMIT, CHUNK)
    const many = simulateChunked(size, LIMIT, CHUNK, CHAINED_OVERHEAD)
    expect(many.allocatedBytes).toBeGreaterThan(one.allocatedBytes)
    expect(many.peakBytes / one.peakBytes).toBeLessThan(0.002)
  })

  it('handles a file smaller than one chunk', () => {
    const run = simulateChunked(1024, LIMIT, CHUNK, CHAINED_OVERHEAD)
    expect(run.segmentCount).toBe(1)
    expect(run.oom).toBe(false)
    expect(run.peakBytes).toBe(2 * 1024 + CHAINED_OVERHEAD + STATE_BYTES)
  })

  it('bigger chunks trade memory for fewer segments — the real tuning knob', () => {
    const small = simulateChunked(1 * GiB, LIMIT, 16 * 1024, CHAINED_OVERHEAD)
    const big = simulateChunked(1 * GiB, LIMIT, 1 * MiB, CHAINED_OVERHEAD)
    expect(big.peakBytes).toBeGreaterThan(small.peakBytes)
    expect(big.segmentCount).toBeLessThan(small.segmentCount)
  })
})

describe('requiredBytes', () => {
  it('quotes twice the file for one-shot, whether or not the run survived', () => {
    expect(requiredBytes('one-shot', 10 * GiB, CHUNK, CHAINED_OVERHEAD)).toBe(2 * 10 * GiB + STATE_BYTES)
  })

  it('quotes twice the segment for chunked, flat in the file size', () => {
    const want = 2 * CHUNK + CHAINED_OVERHEAD + STATE_BYTES
    expect(requiredBytes('chunked', 10 * GiB, CHUNK, CHAINED_OVERHEAD)).toBe(want)
    expect(requiredBytes('chunked', 64 * MiB, CHUNK, CHAINED_OVERHEAD)).toBe(want)
  })

  it('never quotes more than the file itself for a sub-segment file', () => {
    expect(requiredBytes('chunked', 1024, CHUNK, CHAINED_OVERHEAD)).toBe(2 * 1024 + CHAINED_OVERHEAD + STATE_BYTES)
  })

  it('matches the surviving run’s measured peak', () => {
    const run = simulateChunked(1 * GiB, LIMIT, CHUNK, CHAINED_OVERHEAD)
    expect(requiredBytes('chunked', 1 * GiB, CHUNK, CHAINED_OVERHEAD)).toBe(run.peakBytes)
    const one = simulateOneShot(64 * MiB, LIMIT, CHUNK)
    expect(requiredBytes('one-shot', 64 * MiB, CHUNK, CHAINED_OVERHEAD)).toBe(one.peakBytes)
  })
})

describe('formatBytes', () => {
  it('labels binary units honestly', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1023)).toBe('1023 B')
    expect(formatBytes(1024)).toBe('1.00 KiB')
    expect(formatBytes(64 * 1024)).toBe('64.0 KiB')
    expect(formatBytes(10 * GiB)).toBe('10.0 GiB')
  })
})
