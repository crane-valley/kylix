# 0001 - Wipe secret-absorbing hash state with an in-crate Keccak sponge

- Status: accepted
- Date: 2026-09-27

## Context and Problem Statement

ML-KEM, ML-DSA and SLH-DSA feed secret material into SHA3/SHAKE: seeds
(d, z, xi, rho', K), short secret concatenations such as d||k, sigma||N,
m||h, z||c, xi||k||l and K||rnd||mu, and they squeeze secret-derived output
(ExpandS/ExpandMask streams, PRF output, shared secrets). Keccak-f is a
permutation, so any sponge state or buffer left in memory after use reveals
what was absorbed or what will be squeezed next.

All three crates depend on `sha3 = { version = "0.10", default-features = false }`
without the `zeroize` feature. With the dependency set locked today:

- sha3 0.10.9 wipes its Keccak state on drop only under
  `#[cfg(feature = "zeroize")]` (`impl Drop for Sha3State` in `src/state.rs`).
- Even with that feature, the digest 0.10 `CoreWrapper` keeps input in a
  block-buffer 0.10.4 `BlockBuffer` that is never wiped. `pad_with_zeros`
  clears only the bytes from the current position onward, so an input shorter
  than one block (every example above) remains in the dropped buffer.
- The digest 0.10 XOF reader keeps a buffered output block that is not wiped.
- sha2 0.10, hmac 0.12, digest 0.10 and block-buffer 0.10 have no zeroize
  support at all.

How do we hash secret inputs so that no copy of the absorbed data or of the
secret output stream survives the hash object?

## Decision Drivers

- Every byte of secret input and secret-derived output must be wiped when the
  hash object is dropped, including partial blocks.
- MSRV stays at Rust 1.75.
- `no_std` without `alloc`, and no new `unsafe` code.
- Correctness must be demonstrable against an independent implementation.
- Keep the amount of hand-written cryptographic code small.

## Considered Options

1. Enable the sha3 `zeroize` feature only.
2. Use the digest 0.10 core API (`Sha3_256Core` and friends) with our own
   wipeable block buffer.
3. Write a small Keccak sponge in kylix-core over `keccak::f1600`.
4. Upgrade to the digest 0.11 generation of RustCrypto hashes.

## Decision Outcome

Chosen option: 3, a sponge in `kylix_core::hash` over `keccak::f1600`
(keccak 0.1.6, already in the dependency graph through sha3 and now a direct
dependency of kylix-core).

The sponge state is a single `[u64; 25]` plus a byte position. There is no
input or output buffer: absorbing XORs input bytes straight into the lanes and
squeezing reads output bytes straight from them, so the only copy of the data
is the Keccak state, and that is zeroized on drop. The public API covers what
the crates need for secret inputs and nothing more:

- `Sha3_256`, `Sha3_512`: `new`, `update`, `finalize_into(self, &mut [u8; N])`
  and a one-shot `hash_into`.
- `Shake128`, `Shake256`: `new`, `update`, `finalize_xof(self)` returning a
  reader whose `read` squeezes into caller buffers across any number of calls.

Finalizing consumes the hasher, so absorbing after padding or reading before
padding cannot be expressed. Padding follows FIPS 202: domain byte 0x06 for
SHA3 and 0x1F for SHAKE at the current position, 0x80 in the last byte of the
rate block (rates 136, 72, 168 and 136 bytes for SHA3-256, SHA3-512, SHAKE128
and SHAKE256).

Hashing that absorbs only public data (for example SampleNTT/ExpandA over rho,
H(ek), H(pk)) may keep using the sha3 crate; the call sites that move to the
new sponge, and why each remaining sha3 call is public-only, are recorded when
the ML-KEM and ML-DSA call sites are converted. The sha3 `zeroize` feature is
enabled for the remaining sha3 uses at the same time.

### Option 1: sha3 `zeroize` feature only

- Good: one-line change, no new code.
- Bad: wipes only the Keccak state. The digest 0.10 block buffer keeps short
  secret inputs and the XOF reader keeps an output block, which is exactly the
  data this decision is about.

### Option 2: digest 0.10 core API with our own buffer

- Good: reuses the upstream sponge and padding code.
- Bad: the core types absorb whole blocks, so we would still need our own
  zeroizing block buffer and XOF read-ahead buffer, which is about as much code
  as the sponge itself, and the core state wipe still depends on the sha3
  `zeroize` feature and on the internals of `digest::core_api`.

### Option 3: own sponge over `keccak::f1600` (chosen)

- Good: the state is the only storage, so there is nothing else to wipe.
- Good: the sponge core is about 60 lines with no `unsafe`, no allocation and no
  dependency on digest internals; the permutation itself stays upstream.
- Bad: kylix now owns absorb, pad and squeeze logic and must keep it correct.

### Option 4: digest 0.11 generation hashes

Per the local crates.io index cache (checked 2026-09-27, cache last updated
2026-07), the stable releases of that generation are sha3 0.11.0 and 0.12.0,
digest 0.11.2 and 0.11.3, sha2 0.11.0, hmac 0.13.0, block-buffer 0.11.0 and
0.12.x, and keccak 0.2.x, and every one of them declares `rust-version = 1.85`.

- Bad: requires raising the MSRV from 1.75 to 1.85, a breaking change for
  users, for a problem that option 3 solves without it.
- Neutral: whether the newer buffers are wiped was not evaluated, because the
  MSRV cost rules the option out for now.

## Consequences

- kylix-core carries a small permutation wrapper (absorb, pad, squeeze). The
  Keccak-f[1600] permutation remains the RustCrypto `keccak` crate.
- Differential tests in `kylix-core/src/hash.rs` are the safety net: all four
  functions are compared with the sha3 crate for every input length from 0 to
  3 * rate + 1, with the input split across one, two (every split point) and
  three absorb calls, SHAKE output split across reads of many sizes spanning
  several rate blocks, and FIPS 202 known answers (empty string for all four,
  "abc" for SHA3-256 and SHA3-512). ML-KEM and ML-DSA ACVP vectors keep
  covering the integrated behavior.
- The sha3 crate stays for public-input hashing and as a dev-dependency of
  kylix-core for the differential tests.
- Residual exposure the sponge does not address: Rust moves of a hasher value
  are plain copies and the source location is not wiped; transient locals in
  registers or spilled to the stack (the per-lane word in absorb and squeeze,
  the permutation's own scratch lanes inside `keccak::f1600`) are not wiped.
  Callers should keep hashers in place and let them drop where they were
  created.
- SHA-2 and HMAC secret inputs in SLH-DSA are not covered by this sponge; they
  are handled in a follow-up change (wipeable SHA-256/SHA-512 and HMAC over the
  sha2 block functions), recorded as an extension of this ADR or a new one.
