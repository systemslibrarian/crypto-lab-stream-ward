Brief 1 — Stream Ward (closes §7.1, "mostly")

Category: Authenticated Encryption / Streaming
Slug: crypto-lab-stream-ward
One-liner: One-shot AEAD buffers the whole file to verify its tag — watch RAM climb to the ceiling, then watch a chained secretstream hold flat while an attacker fails to truncate, reorder, or drop a segment.

The two failures it must show (this is the point — §7.1 has two halves):

The memory half (modelled, labelled as such). A file-size slider (1 MB → 10 GB, simulated). Two panels side by side: One-shot decrypt and Chunked stream. As "decryption" runs, a memory meter fills. One-shot: the meter climbs linearly to the full file size and slams into a red "OOM — process killed" ceiling at your set RAM limit. Chunked: the meter oscillates within a small fixed band (one chunk + tag) regardless of file size. The honest label, verbatim in the exhibit chrome, matching your Power Trace convention: "Memory footprint is modelled from tracked buffer allocations, not measured process RSS. The chunk-chaining below uses real cryptographic operations."
The authentication half (real crypto, no simulation). Below the meters, the actual reason chunked ≠ "just split the file." Build a real secretstream-style chained construction (XChaCha20-Poly1305 per segment, each tag covering a rolling state + sequence number). Then give the attacker three buttons: Truncate (drop the final segments), Reorder (swap two segments), Drop (delete a middle segment). Each one must make the real verifier abort with the specific reason — and a fourth toggle, "naive split (no chaining)," shows those same three attacks succeeding silently, which is the actual §7.1 lesson: unauthenticated chunking hands the app corrupted plaintext.

Signature moment: the OOM ceiling collision on one-shot at 10 GB, next to the flat chunked meter — the visceral "why you can't just decrypt the whole file" — paired with the naive-split toggle proving splitting alone isn't the fix.

Honest gap it leaves: none, if labelled right. It moves §7.1 from "partial" to "mostly." The bridge marker becomes ◑→ with a note.

Libraries: @noble/ciphers for real XChaCha20-Poly1305 (you already use noble elsewhere). No backend.