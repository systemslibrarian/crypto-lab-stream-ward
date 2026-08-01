# Stream Ward

**Streaming AEAD · XChaCha20-Poly1305 · secretstream-style chaining**

A browser demo of why you cannot decrypt a large file in one shot — and why splitting it
into chunks, on its own, is not the fix.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-stream-ward/

---

## What It Is

One-shot authenticated encryption puts a single Poly1305 tag over an entire message. That
tag cannot be checked until the last byte has been read, so a correct implementation
refuses to release any plaintext before then — which means the whole ciphertext has to be
resident in memory, and the plaintext output buffer is allocated on top of it. Peak memory
is roughly **two times the file size**, chosen not by you but by whoever uploaded the file.

The fix everyone reaches for is to cut the file into segments and authenticate each one.
That solves the memory problem completely and introduces a new one: each segment is now a
valid standalone message, so an attacker who cannot read or forge a single byte can still
**reorder, delete, or truncate** the segment list, and every surviving tag still verifies.
The application is handed a file the sender never wrote, with no error raised.

This demo builds both sides:

- **Stream Ward**, a hand-rolled secretstream-style chained construction. Real
  **XChaCha20-Poly1305** (`@noble/ciphers`) per segment, with each tag covering a rolling
  **SHA-256** chain state (`@noble/hashes`) plus the segment's sequence number, and an
  authenticated **FINAL** flag inside the encrypted block.
- **Naive split**, the deliberately-broken control. Same cipher, unique nonces per chunk,
  no chaining. It is never the default and is marked broken wherever it appears.

**Security model.** The attacker sees the ciphertext and can delete or rearrange whole
frames. They do not have the key and never modify bytes inside a frame — if rearranging
intact, individually-valid ciphertexts is enough to change what the application reads, the
construction is broken.

**Not production crypto.** This is a teaching demo. For real work use libsodium's
`crypto_secretstream_xchacha20poly1305`, the [age](https://age-encryption.org/) format, or
Tink's streaming AEAD.

### The construction

```
DOMAIN = "crypto-lab/stream-ward/v1"

chain[0]   = SHA-256( DOMAIN ‖ "chain-init" ‖ header )
nonce[i]   = SHA-256( DOMAIN ‖ "nonce" ‖ chain[i] ‖ LE64(i) )[0..24]
aad[i]     = DOMAIN ‖ "seg" ‖ LE64(i) ‖ chain[i]
inner[i]   = flag[i] ‖ plaintext[i]      flag = 0x01 on the last segment, else 0x00
ct[i]      = XChaCha20-Poly1305( key, nonce[i], aad[i] ).encrypt( inner[i] )
chain[i+1] = SHA-256( DOMAIN ‖ "chain" ‖ chain[i] ‖ LE64(i) ‖ ct[i] )
```

`chain[i]` absorbs every earlier ciphertext *including its Poly1305 tag*, so a segment that
moves lands on a chain state its tag does not cover. `LE64(i)` in the associated data binds
each segment to its position. The FINAL flag lives inside the encrypted block, so a
truncated stream ends on a segment that authenticates as MESSAGE — and the verifier can say
exactly that.

`chain[i]` is **not secret**: it is derived from the public header and the ciphertexts, and
an attacker can compute it too. Confidentiality comes from the key alone; the chain buys
ordering and completeness, nothing more.

---

## Exhibits

1. **The RAM ceiling** (modelled). A file-size slider from 1 MiB to 10 GiB, a segment-size
   selector and a RAM limit. Two panels on one shared y-scale: one-shot climbs linearly as
   it buffers the ciphertext, jumps again when the plaintext buffer is allocated, and slams
   into a red OOM ceiling; chunked oscillates inside a two-segment band regardless of file
   size, with a magnified inset showing the sawtooth. Memory footprint is modelled from
   tracked buffer allocations, not measured process RSS — the exhibit says so in its own
   chrome.
2. **The chain** (real crypto). The sealed segments of a settlement batch, each row showing
   its real chain state, derived nonce and ciphertext length, stitched together by the
   actual `chain[i+1] = SHA-256(chain[i] ‖ i ‖ ct[i])` step. A construction switch flips the
   whole exhibit to the naive split, where the rows visibly float apart with nothing binding
   them.
3. **Break it yourself** (real crypto). Truncate, Reorder and Drop, applied to the frames
   without touching a byte inside any of them, then run through the genuine verifier. Under
   Stream Ward each aborts with a specific code (`TRUNCATED_STREAM`, `SEGMENT_AUTH_FAILED`);
   under the naive split each is accepted silently and the corrupted ledger it produces is
   shown, with the moved and missing lines called out.
4. **Scorecard.** A 3 × 2 grid — three attacks against both constructions — that fills in
   with what the verifier actually reported for each combination you ran. Nothing in it is
   pre-written.

---

## When to Use It

**Use a chained / streaming AEAD when:**

- The plaintext can be larger than the memory you are willing to spend on it — backups,
  video, object storage, log shipping, database dumps.
- The consumer processes data incrementally and must not act on out-of-order or partial
  content.
- You need the receiver to be able to distinguish "the file ended" from "the file stopped".

**Do NOT use this pattern when:**

- **You need random access.** Chaining is strictly sequential by design; seeking to segment
  9,000 means processing everything before it. Seekable encrypted formats use a different
  structure (per-segment independent nonces plus a separately authenticated index, or a
  Merkle tree over segments).
- **The message is small.** A single AEAD call is simpler, smaller on the wire, and has no
  ordering surface at all. Do not add a stream format to protect a 4 KB blob.
- **You were about to hand-roll it.** Use the demo to understand the shape, then use
  libsodium, age, or Tink.

---

## Live Demo

https://systemslibrarian.github.io/crypto-lab-stream-ward/

At the live site you can drag the file size to 10 GiB and watch one-shot die against a 2 GiB
ceiling while the chunked meter holds at 128 KiB; switch between the chained and naive
constructions; fire all three attacks under each; and watch the scorecard fill in with the
verifier's own answers. Everything below Exhibit 1 is real cryptography running in your
browser. The key is generated per page load, held in memory only, and never stored or
transmitted. There is no backend.

---

## What Can Go Wrong

- **Chunking without chaining.** The headline failure. Individually authenticated chunks
  give you no ordering and no completeness guarantee; Exhibit 3 shows all three attacks
  succeeding silently against it.
- **Forgetting the end-of-stream marker.** Without an authenticated FINAL flag, a truncated
  stream is indistinguishable from a complete one. This is the single most commonly omitted
  piece of a home-made chunked format.
- **Acting on the prefix.** Even a correct streaming verifier releases each segment as it is
  authenticated, so a truncation attack still gets your application to process the prefix
  before the abort fires. Detection is not undo — check for FINAL before you treat a stream
  as a complete file. The demo makes this point explicitly rather than pretending the
  rejection was free.
- **Nonce reuse across segments.** Deriving each nonce from a per-stream random header keeps
  them unique; a counter reused under a fixed key across two streams would be catastrophic.
  The demo tests that no nonce repeats within a stream and that two headers give disjoint
  nonce sets.
- **Lenient parsing.** A frame length that runs past the end of the buffer, a zero-length
  frame, or a dangling length prefix are all hard rejects here. A lenient parser hands the
  verifier a stream the sender never wrote — the same class of bug the demo is about.
- **Assuming big chunks are free.** Segment size is a direct memory/overhead trade: 1 MiB
  segments cost 64× the memory of 16 KiB segments and save you tag bytes. Exhibit 1 lets you
  move it and watch both sides.

---

## Real-World Usage

- **libsodium** — `crypto_secretstream_xchacha20poly1305_*`, the construction this demo is
  modelled on. It additionally ratchets the key, which Stream Ward does not.
- **age** — the file encryption tool; its payload is ChaCha20-Poly1305 in 64 KiB chunks with
  a final-chunk marker.
- **Tink** — `StreamingAead` (AES-GCM-HKDF-Streaming, AES-CTR-HMAC-Streaming).
- **TLS 1.3 records** — the same idea at a different scale: a per-record AEAD with a sequence
  number folded into the nonce, plus `close_notify` as the end-of-stream signal.
- **Signal, MLS, and backup formats** generally — anywhere a message stream must resist
  reordering and truncation, not just forgery.

---

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-stream-ward.git
cd crypto-lab-stream-ward
npm install
npm run dev          # http://localhost:5173/crypto-lab-stream-ward/

npm test             # 81 unit tests, including 8 spec KATs
npm run build        # typecheck + production build
npm run test:a11y    # WCAG 2.1 AA gate against the production build, both themes
```

The a11y gate needs the Playwright browser once: `npx playwright install --with-deps chromium`.

---

## Related Demos

- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — the stream cipher underneath, and what nonce reuse does to it
- [crypto-lab-poly1305-mac](https://systemslibrarian.github.io/crypto-lab-poly1305-mac/) — the authenticator, stepped through its polynomial
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — nonce-misuse resistance, the other half of AEAD hygiene
- [crypto-lab-hpke-envelope](https://systemslibrarian.github.io/crypto-lab-hpke-envelope/) — how the key reaches the receiver in the first place
- [crypto-lab-ratchet-wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/) — chaining taken further, into forward secrecy

---

## Build & Verify

**81 unit tests (Vitest), 8 of them spec KATs**, run in CI before anything is built:

| KAT | Source |
| --- | --- |
| AEAD_XCHACHA20_POLY1305 encrypt / decrypt / AAD rejection | `draft-irtf-cfrg-xchacha-03` §A.1, §A.3.1 |
| ChaCha20 encryption at block counter 1 | RFC 8439 §2.4.2 |
| Poly1305 one-time authenticator | RFC 8439 §2.5.2 |
| SHA-256 (empty, `"abc"`, two-block) | FIPS 180-4 |

KAT file: [`src/stream/kat.test.ts`](src/stream/kat.test.ts). The rest cover round-trips,
nonce and chain hygiene, strict wire parsing, and the attack surface:

- Every swap of any two frames, every single-frame drop, and every truncation length is
  rejected by the chained verifier — not just the three the UI's buttons fire.
- A passing test proves the **vulnerable** path is vulnerable:
  [`src/stream/naive.test.ts`](src/stream/naive.test.ts) asserts that truncate, reorder, drop
  and replay are all *accepted* by the naive split, and that it still catches a flipped bit —
  so the demo's claim is that chunk binding is missing, not that the cipher is broken.
- The memory model is tested as a model: the allocation ledger's invariants, one-shot's 2×
  peak, chunked's flat peak across a 10,000× range of file sizes, and both OOM paths.

**Accessibility gate.** `npm run test:a11y` runs `@axe-core/playwright` against the
production build in **both** themes, driving the page through every result state first —
the OOM run, both constructions, all three attacks under each, and the filled scorecard —
because an unscanned state is an ungated state. Zero WCAG 2.1 A/AA violations, and the
GitHub Pages deploy is blocked if that ever stops being true.

**Deploy.** GitHub Actions (`.github/workflows/deploy.yml`): `npm ci` → unit tests → build
(the typecheck rides inside it) → Playwright browser → a11y gate → Pages. Vite `base` is
`/crypto-lab-stream-ward/` and there are no root-absolute asset paths, so the site works
under the project subpath.

---

## Performance

All cryptography runs in the browser on a six-segment, ~250-byte message, so sealing and
verifying are instantaneous — this demo is not a benchmark, and no timing claim is made.
The memory exhibit does walk its allocation ledger for real: at 10 GiB with 64 KiB segments
that is 163,840 loop iterations and 327,681 tracked allocations, completing in a few
milliseconds. The animation length is a fixed 3.4 seconds chosen for legibility and measures
nothing.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
