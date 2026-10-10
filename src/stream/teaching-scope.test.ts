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
