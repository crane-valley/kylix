# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please send an email to: **security@crane-valley.co.jp**

Include the following information:

- Type of vulnerability (e.g., buffer overflow, timing attack, key leakage)
- Full path to the affected source file(s)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if available)
- Impact assessment of the vulnerability

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 90 days (depending on complexity)

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.
2. **Assessment**: Our team will assess the vulnerability and determine its severity.
3. **Updates**: We will keep you informed of our progress.
4. **Fix**: Once a fix is developed, we will coordinate the release with you.
5. **Credit**: With your permission, we will acknowledge your contribution in the release notes.

## Security Considerations

### Cryptographic Implementation

This library implements post-quantum cryptographic algorithms as specified in NIST FIPS standards. However:

- **No Audit**: This library has NOT been independently audited.
- **No Warranty**: The software is provided "as is" without warranty of any kind.
- **Use at Your Own Risk**: Do not use in production systems without proper evaluation.

### Side-Channel Protections

We implement the following protections against side-channel attacks:

- **Constant-time operations**: Using the `subtle` crate for constant-time comparisons
- **Memory zeroization**: Using the `zeroize` crate to clear sensitive data
- **No secret-dependent branches**: Avoiding conditional code based on secret values

However, complete side-channel resistance depends on:

- The compiler not optimizing away protections
- The hardware platform's characteristics
- The operating system's memory management

### Known Limitations

1. **Randomness**: Security depends on the quality of the provided RNG
2. **Memory Safety**: While Rust provides memory safety, `unsafe` blocks may exist
3. **Platform-Specific**: Some platforms may leak information through caches or power analysis

## Security Best Practices

When using this library:

1. Use a cryptographically secure random number generator (e.g., `OsRng`)
2. Keep keys in memory for the minimum required time
3. Use the zeroization features to clear sensitive data
4. Keep the library updated to the latest version
5. Consider additional hardware security measures for high-security applications

## Coordinated Disclosure

We follow a coordinated disclosure policy:

- We will work with reporters to understand and resolve vulnerabilities
- We aim to release fixes before public disclosure
- We will publicly acknowledge reporters (with permission) after fixes are released
- We request a 90-day disclosure window for complex issues

## Bug Bounty

Currently, we do not offer a bug bounty program. However, we deeply appreciate responsible disclosure and will acknowledge contributors in our release notes.
