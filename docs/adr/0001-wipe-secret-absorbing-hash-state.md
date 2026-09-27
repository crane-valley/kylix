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
is the Keccak state. Once data has been absorbed the state is never moved:
finalizing pads and squeezes it where it lives and then wipes it, and it is
also zeroized on drop. The public API covers what the crates need for secret
inputs and nothing more:

- `Sha3_256`, `Sha3_512`: `new`, `update`, `finalize_into(&mut self,
  &mut [u8; N])`, which writes the digest and then wipes the state in place,
  leaving a fresh hasher, and a one-shot `hash_into`.
- `Shake128`, `Shake256`: `new`, `update`, `finalize_xof(&mut self)` returning
  a reader that mutably borrows the hasher's state. Its `read` squeezes into
  caller buffers across any number of calls, and dropping the reader wipes the
  state in place, again leaving a fresh hasher.

Misuse is ruled out at compile time by the borrow instead of a runtime phase
flag: while the reader exists the hasher cannot be updated, and output can only
be read through a reader, which only `finalize_xof` creates. A runtime phase
would need a panic (or a silently wrong result) on misuse in library code that
otherwise avoids panics, and a check that only fires in tests. Finalizing by
value (`finalize_xof(self)`, used in the first version of this change) was
rejected because moving the hasher copies the absorbed state and the
moved-from location is never dropped or wiped; swapping the state out with
`mem::replace` does not help, since the by-value `self` is already such a copy.

Padding follows FIPS 202: domain byte 0x06 for
SHA3 and 0x1F for SHAKE at the current position, 0x80 in the last byte of the
rate block (rates 136, 72, 168 and 136 bytes for SHA3-256, SHA3-512, SHAKE128
and SHAKE256).

Hashing that absorbs only public data may keep using the sha3 crate. The sha3
`zeroize` feature is enabled in all three crates for those remaining uses; the
requirement is sha3 0.10.9 because 0.10.8 has no such feature.

### Call sites

ML-KEM (`kylix-ml-kem/src/hash.rs`):

- G (SHA3-512) moves to the sponge. It absorbs d||k in K-PKE.KeyGen, m||H(ek)
  in Encaps and m'||h in Decaps, and its output (rho, sigma) or (K, r) is
  secret. It now takes the two parts separately, so no concatenated input
  buffer exists.
- PRF (SHAKE256 over sigma||N or r||N) moves: the seed is secret and the
  output is the CBD noise for s, e, r, e1 and e2.
- J (SHAKE256 over z||c) moves: z is secret and the output is the implicit
  rejection key.
- H (SHA3-256) stays on sha3: it is only applied to ek, in KeyGen, in Encaps
  on the peer's ek, and in the Decaps check of the ek embedded in dk. ek is
  public.
- The SampleNTT XOF (SHAKE128 over rho||j||i) stays on sha3: rho is part of ek.

ML-DSA (`kylix-ml-dsa/src/hash.rs`):

- H(xi||k||l) in KeyGen moves: xi is the seed and rho' and K are secret.
- H(K||rnd||mu) in Sign moves: K is secret and the output rho'' seeds
  ExpandMask.
- ExpandS (SHAKE256 over rho'||nonce) and ExpandMask (SHAKE256 over
  rho''||nonce) move: seeds and output streams (s1, s2, y encodings) are
  secret. The seed||nonce input is absorbed in two parts instead of being
  copied into a local array, and the samplers read from a reader borrowed from
  a hasher local to the sampler.
- c_tilde = H(mu||w1Encode(w1)) in Sign and SampleInBall over c_tilde move:
  w1 and c_tilde of rejected iterations are never published and derive from
  y. Verify recomputes c_tilde through the same helper; its inputs are public,
  and a separate public helper would buy nothing. SampleInBall writes c
  straight into a caller-owned (in Sign, zeroizing) polynomial and wipes its
  sign and index buffers, because it runs before the rejection checks.
- tr = H(pk) and mu = H(tr||M') stay on sha3: pk, tr, the prefix and the
  message are public.
- ExpandA (SHAKE128 over rho||j||i) stays on sha3: rho is part of pk.

SLH-DSA call sites are unchanged here; only its sha3 `zeroize` feature is
enabled (see the last consequence below).

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
  "abc" for SHA3-256 and SHA3-512). A further test checks that the state is
  all zero after `finalize_into` and after a reader is dropped, and that the
  hasher then computes a fresh hash. ML-KEM and ML-DSA ACVP vectors keep
  covering the integrated behavior.
- The sha3 crate stays for public-input hashing and as a dev-dependency of
  kylix-core for the differential tests.
- Residual exposure the sponge does not address: the API cannot stop a caller
  from moving a hasher after absorbing (a Rust move is a plain copy and the
  source is not wiped), so every call site in the workspace creates its hasher
  as a local and never moves it after the first `update`. Transient locals in
  registers or spilled to the stack (the per-lane word in absorb and squeeze,
  the permutation's own scratch lanes inside `keccak::f1600`) are not wiped.
- For the same reason, the secret-producing ML-KEM helpers write into
  caller-owned zeroizing destinations instead of returning by value: CBD noise
  polynomials, the message encoding and decoding, m' from K-PKE.Decrypt, and
  the shared secret, which the `Kem` implementations write straight into
  `SharedSecret`. By-value residue that remains:
  - the public API boundary: `kem::ml_kem_encaps` and `kem::ml_kem_decaps`
    return the shared secret as a plain `[u8; 32]` (documented as the caller's
    to wipe), and the `Kem` trait methods return `SharedSecret` by value, so
    the move out of the method can leave an unwiped copy;
  - polynomial arithmetic that returns a fresh value which callers then wrap
    in `Zeroizing`: in ML-KEM `PolyVec::from_bytes` of dk_pke,
    `inner_product` and `matrix_vec_mul`, in ML-DSA `mul_vec`, `pointwise_mul`
    and `Poly::add`. The compiler usually builds such results in the
    destination, but that is not guaranteed.
- SHA-2 and HMAC secret inputs in SLH-DSA are not covered by this sponge; they
  are handled in a follow-up change (wipeable SHA-256/SHA-512 and HMAC over the
  sha2 block functions), recorded as an extension of this ADR or a new one.
