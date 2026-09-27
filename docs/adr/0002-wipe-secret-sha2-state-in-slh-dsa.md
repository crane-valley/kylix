# 0002 - Wipe secret-absorbing hash state in SLH-DSA

- Status: accepted
- Date: 2026-09-27

## Context and Problem Statement

ADR 0001 introduced wipeable SHA3/SHAKE in `kylix_core::hash` and moved the
ML-KEM and ML-DSA secret hashing onto it. SLH-DSA has the same problem in
both of its instantiations:

- PRF absorbs SK.seed and outputs WOTS+ chain starts and FORS leaf secrets.
- PRF_msg absorbs SK.prf. In the SHA-2 instantiation it is HMAC, and
  hmac 0.12 XORs the padded key into a block in place and keeps the inner and
  outer midstates, either of which lets anyone compute HMAC(SK.prf, x) for
  any x.
- F absorbs secret values: PRF outputs at the start of a WOTS+ chain, the
  chain values below the position a signature reveals, and FORS leaf
  secrets.

The SHAKE instantiation used the sha3 crate, whose block buffer and XOF
output block are not wiped (ADR 0001). The SHA-2 instantiation used sha2 0.10
and hmac 0.12, which have no zeroize support at all: the chaining state, the
block-buffer 0.10 buffer and the HMAC key block and midstates are all dropped
unwiped.

The sha2 0.10.9 block functions themselves also leave copies. The portable
backend (`sha256/soft.rs`, `sha512/soft.rs`) converts each input block into a
local word array and runs the rounds on a local copy of the chaining state;
neither is wiped. For HMAC that block is SK.prf XOR ipad or opad, so one
leftover stack array yields SK.prf. The SHA-NI backend keeps the block and
state in vector registers.

How do we hash the SLH-DSA secret inputs so that no copy of them, or of
state derived from them, survives the hash object?

## Decision Drivers

- The drivers of ADR 0001: complete wipe including partial blocks, MSRV 1.75,
  `no_std` without `alloc`, no new `unsafe`, differential testing against an
  independent implementation, little hand-written cryptographic code.
- Long-term secrets (SK.seed, SK.prf) must not pass through explicit arrays
  that are dropped unwiped, including arrays inside the block function.
- Outputs must stay bit-identical to FIPS 205 for all twelve parameter sets
  (ACVP vectors, OpenSSL cross-checks, deterministic fixtures).
- F is the hot path of SLH-DSA; a large signing slowdown there is a cost that
  has to be weighed against what it protects (one-time values, see below).

## Considered Options

For the SHAKE instantiation there is nothing new to decide: PRF, PRF_msg and
F use `kylix_core::hash::Shake256` (ADR 0001, option 3).

For the SHA-2 instantiation:

1. Keep sha2 0.10 and hmac 0.12.
2. Use the digest 0.10 core API (`Sha256VarCore`, `Sha512VarCore`) with our
   own wipeable buffer.
3. A small wipeable SHA-256/SHA-512 wrapper over the public block functions
   `sha2::compress256` and `sha2::compress512`, with HMAC on top.
4. The digest 0.11 generation of RustCrypto hashes.
5. The wrapper of option 3 over an in-crate FIPS 180-4 compression function
   whose message schedule and working variables live in storage owned by the
   hasher and wiped after every block.

## Decision Outcome

Chosen option: 5 for every computation that absorbs a long-term secret (PRF,
PRF_msg), and 3 for F. Both live in `kylix-slh-dsa/src/wipe_sha2.rs`; option
3 needs the sha2 `compress` feature (sha2 0.10.9 exports `compress256` and
`compress512` only under it).

Each hasher is a struct holding the eight-word chaining state, a one-block
input buffer (64 bytes for SHA-256, 128 for SHA-512), the buffer position,
the block count and the compression scratch. Full input blocks are
compressed straight from the caller's slice; a partial block is copied into
the buffer. `finalize_into(&mut self, out)` pads in the buffer (0x80, zeros,
then the 64-bit or 128-bit big-endian bit length), compresses, writes the
first `out.len()` digest bytes byte by byte from the state words into `out`
(no per-word byte array, and the n-byte truncation needs no digest copy),
wipes state, buffer, position and count, and reloads the IV. It asserts that
`out` is no longer than the digest. Drop wipes the same fields. As in ADR
0001, hashers are locals that are never moved after the first update.

- `Sha256` and `Sha512` use the in-crate compression. Its scratch is a
  rolling 16-word message schedule and the eight working variables, both
  fields of the hasher; the block bytes are read into the schedule directly,
  and the scratch is zeroized before the compression returns.
- `Sha256Accel` uses `sha2::compress256`, with the same buffer handling and
  wiping around it.

HMAC (`hmac_sha256_into`, `hmac_sha512_into`) is a one-shot function over
two `Sha256` or `Sha512` hashers. The padded key is built in the inner
hasher's own buffer (a key longer than a block is first hashed into it), the
outer buffer is derived from it with the opad, and both are compressed, so
the key block exists only in wiped buffers and the keyed midstates only in
wiped hashers. The inner digest is finalized straight into the outer
hasher's buffer. Being one-shot, the keyed hashers cannot be reused or moved
by a caller.

The SHA-2 `HashSuite` methods F, PRF and PRF_msg check the output length
with `assert_eq!` in all builds, as the earlier `copy_from_slice` into a
fixed-size digest did.

The FIPS 205 layout is unchanged: F and PRF are SHA-256 over PK.seed ||
toByte(0, 64-n) || ADRSc || M for every category, so PK.seed and its padding
fill exactly one SHA-256 block; H and T_l use SHA-512 with toByte(0, 128-n)
for categories 3 and 5; PRF_msg is HMAC-SHA-256 for category 1 and
HMAC-SHA-512 for categories 3 and 5.

hmac is no longer a normal dependency; it stays a dev-dependency as the
reference for the differential tests.

### Placement of F: measurement

Signing time with F on the in-crate compression (`Sha256`) against F on
`sha2::compress256` (`Sha256Accel`), PRF and PRF_msg on the in-crate
compression in both runs. Intel Core i5-13500 (SHA extensions, so sha2 uses
its SHA-NI backend), Windows 11, rustc 1.92.0, release profile,
features `std`, `slh-dsa-sha2-128f` and `slh-dsa-sha2-128s` (no `parallel`),
one process at a time, one fixed key per run:

- SLH-DSA-SHA2-128f, 20 signatures: 41.0 to 41.2 ms mean (min 40.7 ms) with
  the in-crate compression; 12.0 ms mean (min 11.7 ms) with
  `sha2::compress256`.
- SLH-DSA-SHA2-128s, 3 signatures: 852 to 854 ms mean with the in-crate
  compression; 254 to 259 ms mean with `sha2::compress256`.

The in-crate F makes signing about 3.4 times slower, far beyond the 25%
budget set for this change, so F stays on `sha2::compress256`. F absorbs
PK.seed and one-time values (WOTS+ chain values and FORS leaf secrets), never
SK.seed or SK.prf.

### Call sites

Both instantiations (`hash_shake.rs`, `hash_sha2.rs`):

- PRF moves (kylix-core SHAKE256; `Sha256`): it absorbs SK.seed and its
  output is a WOTS+ or FORS secret.
- PRF_msg moves (kylix-core SHAKE256; HMAC over `Sha256` or `Sha512`): it
  absorbs SK.prf. Its output R is published in the signature, but the caller
  already receives it in a zeroizing buffer.
- F moves (kylix-core SHAKE256; `Sha256Accel`): it absorbs the secret chain
  starts, secret intermediate chain values and FORS leaf secrets. F is one
  trait method used by key generation, signing and verification alike;
  splitting it by caller would need a second method and a correct choice at
  every call site, while the cost of the wipeable wrapper is only the buffer
  handling around the same permutation or block function.
- H and T_l stay on sha3 and sha2: their inputs are XMSS and FORS tree nodes,
  WOTS+ chain ends and FORS roots. These are public-key material of the
  one-time and few-time schemes; signatures publish them in authentication
  paths and the scheme's security does not rely on their secrecy.
- H_msg (including MGF1 in the SHA-2 instantiation) stays: R, PK.seed,
  PK.root and the message are public.

### Option 1: keep sha2 0.10 and hmac 0.12

- Bad: the chaining state, the block buffer and the HMAC key block and
  midstates of every secret computation remain in freed memory.

### Option 2: digest 0.10 core API with our own buffer

- Bad: the core types keep their chaining state in private fields with no
  `Zeroize` implementation, so the state would still be dropped unwiped, and
  HMAC would still have to be rebuilt on top.

### Option 3: wrapper over `compress256` / `compress512` (chosen for F)

- Good: all buffering storage is ours and is wiped; the block functions,
  including their SHA-NI and other accelerated backends, stay upstream.
- Bad: on the portable backend the block function copies the input block and
  chaining state into unwiped locals, which for HMAC exposes SK.prf.

### Option 4: digest 0.11 generation

- Bad: requires MSRV 1.85 (see ADR 0001, option 4).

### Option 5: in-crate compression (chosen for PRF and PRF_msg)

- Good: no explicit array outside the wiped hasher ever holds the block, the
  schedule or the working variables, on every target.
- Good: no `unsafe`, no allocation; the compression is about 60 lines shared
  by SHA-256 and SHA-512 through one macro, plus round constants.
- Bad: more hand-written cryptographic code (compression, buffering, padding,
  length encoding and HMAC keying) that kylix must keep correct.
- Bad: no hardware acceleration; about 3.4 times slower signing if used for
  F (see the measurement), negligible for PRF and PRF_msg.

## Consequences

- Differential tests in `kylix-slh-dsa/src/wipe_sha2.rs` compare `Sha256`,
  `Sha256Accel` and `Sha512` with the sha2 crate for every input length from
  0 to 3 * block + 1, as one update, split at every point into two updates,
  and in chunks of 1, 7, block - 1 and block + 3 bytes, plus truncated
  output. HMAC-SHA-256 and HMAC-SHA-512 are compared with the hmac crate for
  key lengths 0, 1, 16, 32, block - 1, block, block + 1 and 2 * block + 3
  over the same message lengths. Further tests check that the compression
  scratch is zero after a direct call and after blocks compressed from the
  caller's slice and from the buffer, and that finalizing leaves the IV, an
  all-zero buffer and zero counters and the hasher then computes a fresh
  hash. SLH-DSA ACVP vectors for all twelve parameter sets, the OpenSSL
  cross-checks and the deterministic fixtures cover the integrated behavior.
- The sha2 `compress` feature is required for F; it does not change
  Cargo.lock. Dropping hmac as a normal dependency removed it from the
  SLH-DSA fuzz lockfile.
- Residual exposure:
  - F: on targets where sha2 runs its portable backend (no SHA-NI, and
    targets without an accelerated backend such as thumbv7em), the input
    block and chaining state are copied into unwiped locals inside
    `sha2::compress256`. These hold PK.seed, ADRSc and one-time WOTS+ or
    FORS values, not SK.seed or SK.prf. With SHA-NI they stay in vector
    registers.
  - Registers and compiler spills of the in-crate compression (the round
    temporaries and any spilled working variables) and of the byte-wise
    digest output are not wiped, the same class as the Keccak permutation
    scratch in ADR 0001.
  - Output buffers are the caller's to wipe; the existing SLH-DSA callers
    already wipe their PRF and chain scratch buffers.
