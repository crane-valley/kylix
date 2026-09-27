# 0003 - Hold rand 0.9 and rayon 1.10 until the MSRV bump

- Status: accepted
- Date: 2026-09-27

## Context and Problem Statement

Kylix supports Rust 1.75. Dependabot keeps opening updates that cannot build
on that toolchain:

- rand, rand_core and rand_chacha 0.10 declare rust-version 1.85 and
  edition 2024. rand_core is part of the public API: the
  `rand_core::CryptoRng` bounds in `kylix-core/src/traits.rs` are what every
  keygen, encapsulation and signing entry point accepts, and rand_core 0.10
  reworks the `CryptoRng`/`RngCore` trait hierarchy.
- rayon 1.11 and rayon-core 1.13 declare rust-version 1.80. kylix-slh-dsa
  already pins them to `<1.11` and `<1.13` for its `parallel` feature.
- dudect-bencher 0.7 (used only by the `timing/` workspace) declares
  rust-version 1.85 and depends on rand 0.10.
- keccak 0.2 declares rust-version 1.85 and removes `keccak::f1600`, the
  permutation the wipeable sponge in `kylix-core/src/hash.rs` calls
  (ADR 0001), so it does not compile against the current sponge.

These updates used to be dismissed with `@dependabot ignore` PR comments
(#73, #130, #135, #137). Those decisions were lost when the Dependabot
configuration switched from `directory: "/"` to `directories:` (#197), and
the same updates came back as PRs #199-#207.

How do we keep the dependency set building on Rust 1.75 without the same
update PRs recurring?

## Decision Drivers

- MSRV 1.75 is a documented support promise; CI checks it.
- rand_core is public API, so a rand_core major change is a breaking change
  for every downstream user, not an internal dependency bump.
- The rand family has to move together: kylix-core, the three algorithm
  crates, the `kylix-pqc` facade (dev-dependency), the kylix-slh-dsa fuzz
  crate and `timing/` all use it, and mixing rand_core 0.9 and 0.10 would
  give two incompatible trait sets.
- Ignore decisions must survive changes to the Dependabot configuration and
  be reviewable in the repository.

## Considered Options

1. Accept the 0.10 / 1.11 / 1.13 updates as they arrive.
2. Keep dismissing the PRs with `@dependabot ignore` comments.
3. Hold the current lines and record the ignores in
   `.github/dependabot.yml`, then migrate everything together with an MSRV
   bump.

## Decision Outcome

Chosen option: 3.

- rand, rand_core and rand_chacha stay on 0.9; rayon stays below 1.11 and
  rayon-core below 1.13; keccak stays on 0.1; `timing/` stays on
  dudect-bencher 0.6.
- `.github/dependabot.yml` ignores rand, rand_chacha and rand_core `>=0.10.0`,
  keccak `>=0.2.0`, rayon `>=1.11.0`, rayon-core `>=1.13.0` and
  dudect-bencher `>=0.7.0` for every configured cargo directory.
- keccak 0.2 is not a plain version bump: when the MSRV is raised, the
  kylix-core sponge has to be ported to the 0.2 permutation API in the same
  change.
- The move to rand_core 0.10 is a single coordinated breaking change done
  together with raising the MSRV to at least 1.85: all three algorithm
  crates, kylix-core, the facade, the fuzz crate and `timing/` in one
  release, with the public `CryptoRng` bounds updated and the change called
  out as breaking.

Option 1 was rejected because each update fails the MSRV check, and the
rand_core one is a public API break that cannot land as a routine bump.
Option 2 was rejected because comment ignores live in Dependabot state, not
in the repository, and were silently dropped by a configuration change.

## Consequences

- Dependabot stops proposing these updates; updates inside the held lines
  are not ignored and still arrive.
- Kylix does not pick up fixes that exist only in rand 0.10, rayon 1.11+ or
  dudect-bencher 0.7+ until the MSRV bump. Advisories against the held lines
  have to be fixed within them; for example RUSTSEC-2026-0097 is fixed by
  moving the rand 0.8 that dudect-bencher 0.6 pulls into `timing/` from
  0.8.5 to 0.8.8.
- When the MSRV is raised, the matching ignore entries have to be removed in
  the same change, or the migration will not be proposed.
