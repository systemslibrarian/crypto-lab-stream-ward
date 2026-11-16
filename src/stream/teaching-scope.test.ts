import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const read = (file: string) => readFileSync(new URL(file, import.meta.url), 'utf8')
const page = read('../../index.html')
const readme = read('../../README.md')
const model = read('./memory.ts')

function checkScope(text: string): void {
  expect(text).toMatch(/buffer API model|modeled API|buffer API strategies/)
  expect(text).toMatch(/trusted plaintext|plaintext.*untrusted/)
  expect(text).toMatch(/Staged disk storage/)
  expect(text).toMatch(/immutable ciphertext/)
  expect(text).toMatch(/I\/O and latency|I\/O.*latency/)
  expect(text).toMatch(/not implemented[\s\S]*measured|Neither alternative is implemented or measured/)
  expect(text).not.toMatch(/entire ciphertext must be resident|ciphertext therefore has\s+to be fully resident|impossible for a 10/)
}

describe('whole-file authentication teaching scope', () => {
  it('scopes the public page, README and allocation model to their storage assumptions', () => {
    for (const text of [page, readme, model]) checkScope(text)
    expect(page).toMatch(/authenticated[\s\S]*FINAL|FINAL[\s\S]*authenticated/)
    expect(readme).toMatch(/ordering and completeness/)
  })

  it('rejects a restored universal memory premise, including when model labels remain', () => {
    expect(() => checkScope(page + '\nThe ciphertext therefore has\nto be fully resident.')).toThrow()
    expect(() => checkScope(page.replaceAll('immutable ciphertext', 'ciphertext'))).toThrow()
  })
})

describe('SHA-256 vector attribution', () => {
  // FIPS 180-4 prints no digests at all: its Appendix A is "Additional
  // Information", Appendix B is the reference list, and §A.2 points at NIST's
  // separate examples page. The "abc" and two-block digests pinned in
  // kat.test.ts come from that page's SHA256.pdf; the empty-string digest
  // comes from CAVP's SHA256ShortMsg.rsp at Len = 0. Neither page nor README
  // may credit them to FIPS 180-4 as known-answer tests.
  const kat = read('./kat.test.ts')
  const chained = read('./chained.ts')

  it('credits the pinned digests to the documents that actually print them', () => {
    for (const text of [page, readme, kat, chained]) {
      expect(text).not.toMatch(/FIPS 180-4 KATs/)
    }
    expect(page).toMatch(/NIST’s published SHA-256 example values/)
    expect(readme).toMatch(/Examples with Intermediate Values/)
    expect(readme).toMatch(/SHA256ShortMsg\.rsp/)
    expect(kat).toMatch(/Examples with Intermediate Values/)
    expect(kat).toMatch(/SHA256ShortMsg\.rsp, Len = 0/)
  })
})
