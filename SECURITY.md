# Security Policy

## Important Notice

- This project is experimental and has NOT been independently audited.
- It is NOT intended for production use.
- This is an AI-assisted implementation experiment.
- Passing NIST test vectors does NOT guarantee security.

---

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.4.x   | Yes       |
| 0.3.x   | Yes       |
| < 0.3   | No        |

---

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please send an email to:

**security@crane-valley.co.jp**

Include the following information where possible:

- Type of vulnerability (e.g., buffer overflow, timing attack, key leakage)
- Affected algorithm and parameter set (ML-KEM / ML-DSA / SLH-DSA, variant)
- Architecture / target (e.g., x86_64 AVX2, aarch64 NEON, no_std)
- Full path to the affected source file(s)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if available)
- Impact assessment (confidentiality, integrity, authenticity)

---

## Response Timeline

- **Initial Response**: Within 48 hours (best-effort)
- **Status Update**: Within 7 days (best-effort)
- **Resolution Target**: Within 90 days (depending on severity and complexity)

## What to Expect

1. **Acknowledgment**: We will acknowledge receipt of your report.
2. **Assessment**: We will assess the issue and determine its severity and scope.
3. **Updates**: We will keep you informed of progress where possible.
4. **Fix**: If a fix is developed, we will coordinate disclosure with the reporter.
5. **Credit**: With your permission, we will acknowledge your contribution in release notes.

---

## Security Considerations

### Cryptographic Implementation

This library implements post-quantum cryptographic algorithms as specified in NIST FIPS standards.
However, the following limitations apply:

- **No Audit**: This library has NOT been independently audited.
- **No Warranty**: The software is provided "as is" without warranty of any kind.
- **Experimental**: This is an AI-assisted implementation experiment.
- **Use at Your Own Risk**: Do not use in production systems without independent evaluation.

### Side-Channel Considerations

We aim to implement the following protections against side-channel attacks (best-effort):

- Constant-time operations where practical (not formally verified)
- Memory zeroization using the `zeroize` crate
- Avoiding obvious secret-dependent branches

However, complete side-channel resistance is NOT guaranteed and depends on:

- Compiler behavior and optimization settings
- Target architecture and microarchitectural effects
- Operating system and runtime environment

### Known Limitations

1. **Randomness**: Security depends on the quality of the provided RNG.
2. **Memory Safety**: While Rust provides memory safety, `unsafe` code may exist.
3. **Platform-Specific Leakage**: Cache, timing, power, or other side channels may exist.
4. **Test Vectors**: Passing NIST test vectors does NOT imply real-world security.

---

## Security Best Practices

If you experiment with this library:

1. Use a cryptographically secure random number generator (e.g., `OsRng`).
2. Keep sensitive material in memory for the minimum required time.
3. Ensure zeroization is triggered where applicable.
4. Keep dependencies and the library itself up to date.
5. For production systems, use audited and well-maintained alternatives such as RustCrypto.

---

## Coordinated Disclosure

We follow a coordinated disclosure process:

- We will work with reporters to understand and address issues.
- We aim to release fixes before public disclosure where feasible.
- Reporters will be credited with permission after fixes are released.
- We request a disclosure window of up to 90 days for complex issues.

---

## Bug Bounty

We do not currently operate a bug bounty program.
However, responsible disclosure is greatly appreciated, and contributors may be acknowledged in release notes.
