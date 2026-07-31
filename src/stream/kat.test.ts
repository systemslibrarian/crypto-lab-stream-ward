/**
 * Known-answer tests, verbatim from the specifications.
 *
 * These pin the primitives the Stream Ward construction is built on. If any of them
 * drift, nothing else in this repo is trustworthy, so they run first.
 *
 * Sources:
 *   draft-irtf-cfrg-xchacha-03, Appendix A.1 / A.3.1  — AEAD_XCHACHA20_POLY1305
 *   RFC 8439 §2.4.2                                   — ChaCha20 encryption
 *   RFC 8439 §2.5.2                                   — Poly1305 one-time authenticator
 *   FIPS 180-4 / NIST CAVP short messages             — SHA-256
 */

import { chacha20, xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { poly1305 } from '@noble/ciphers/_poly1305.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'
import { toHex, utf8 } from './bytes.js'

function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-f]/gi, '')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

const SUNSCREEN =
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

describe('KAT — AEAD_XCHACHA20_POLY1305 (draft-irtf-cfrg-xchacha-03)', () => {
  // A.1 and A.3.1 are the same vector presented two ways; A.3.1 gives it as flat hex.
  const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
  const iv = fromHex('404142434445464748494a4b4c4d4e4f5051525354555657')
  const aad = fromHex('50515253c0c1c2c3c4c5c6c7')
  const ciphertext = fromHex(`
    bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
    731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
    2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
    21f9664c97637da9768812f615c68b13b52e`)
  const tag = fromHex('c0875924c1c7987947deafd8780acf49')

  it('A.3.1 — encrypt reproduces the specified ciphertext and tag', () => {
    const out = xchacha20poly1305(key, iv, aad).encrypt(utf8(SUNSCREEN))
    expect(toHex(out)).toBe(toHex(ciphertext) + toHex(tag))
  })

  it('A.3.1 — decrypt recovers the specified plaintext', () => {
    const sealed = new Uint8Array(ciphertext.length + tag.length)
    sealed.set(ciphertext)
    sealed.set(tag, ciphertext.length)
    expect(new TextDecoder().decode(xchacha20poly1305(key, iv, aad).decrypt(sealed))).toBe(SUNSCREEN)
  })

  it('A.3.1 — a one-bit change in the AAD is rejected', () => {
    const sealed = new Uint8Array(ciphertext.length + tag.length)
    sealed.set(ciphertext)
    sealed.set(tag, ciphertext.length)
    const badAad = Uint8Array.from(aad)
    badAad[0] = (badAad[0] as number) ^ 0x01
    expect(() => xchacha20poly1305(key, iv, badAad).decrypt(sealed)).toThrow()
  })
})

describe('KAT — ChaCha20 (RFC 8439 §2.4.2)', () => {
  it('encrypts the sunscreen plaintext at block counter 1', () => {
    const key = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    const nonce = fromHex('000000000000004a00000000')
    const expected = fromHex(`
      6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b
      f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8
      07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736
      5af90bbf74a35be6b40b8eedf2785e42874d`)
    expect(toHex(chacha20(key, nonce, utf8(SUNSCREEN), undefined, 1))).toBe(toHex(expected))
  })
})

describe('KAT — Poly1305 (RFC 8439 §2.5.2)', () => {
  it('authenticates "Cryptographic Forum Research Group"', () => {
    const otk = fromHex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
    expect(toHex(poly1305(utf8('Cryptographic Forum Research Group'), otk))).toBe('a8061dc1305136c6c22b8baf0c0127a9')
  })
})

describe('KAT — SHA-256 (FIPS 180-4)', () => {
  it('hashes the empty string', () => {
    expect(toHex(sha256(new Uint8Array(0)))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
  })

  it('hashes "abc"', () => {
    expect(toHex(sha256(utf8('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })

  it('hashes the 448-bit two-block message', () => {
    expect(toHex(sha256(utf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))).toBe(
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    )
  })
})
