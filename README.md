# mooncrypt

Cryptographic algorithms for MoonBit, one algorithm to a package.

```moonbit
let sha256 = fn() -> &@spec.Hash { @sha2.Hasher::new() }

// A digest, a MAC, and a key derived from a password.
let digest = @sha2.hash(b"the quick brown fox"[:])
let tag = @hmac.mac(b"shared secret"[:], b"the quick brown fox"[:], sha256)
let key = @pbkdf2.key(b"correct horse"[:], b"battery staple"[:], sha256,
                      rounds=600000, len=32)

// A signature. Both schemes here are deterministic: the same key and message
// always give the same bytes, so there is no entropy source to get wrong.
let sk = @ed25519.PrivateKey::new(seed[:])
let sig = sk.sign(b"the quick brown fox"[:])
sk.public().verify(b"the quick brown fox"[:], sig[:])  // true
```

Run `moon run examples/tour` for the whole surface in one go.

## Packages

Import the ones you use. A package nothing imports is not linked, which is what
`features` buys in other languages, without a build-time switch.

| Package | What | Specification |
|:--:|:--|:--|
| `spec` | The `Hash`, `Mac`, `Aead`, `Signer` and `Verifier` traits, constant-time comparison, erasure | — |
| `hash/sha2` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | FIPS 180-4 |
| `hash/sha1` | SHA-1 | FIPS 180-4 |
| `hash/md5` | MD5 | RFC 1321 |
| `mac/hmac` | HMAC over any `Hash` | RFC 2104, FIPS 198-1 |
| `kdf/hkdf` | HKDF, extract and expand separately | RFC 5869 |
| `kdf/pbkdf2` | PBKDF2 | RFC 8018 §5.2 |
| `sign/ed25519` | Ed25519 | RFC 8032 |
| `sign/ecdsa` | ECDSA over P-256, P-384, P-521 and secp256k1, with RFC 6979 nonces | FIPS 186-4, RFC 6979 |
| `sign/rsa` | RSA PKCS#1 v1.5 and PSS signatures | RFC 8017 |

Each package's `moon.pkg` names the specification it implements and links to it.

## The contracts

Everything is written against five traits in `spec`, so a digest or a signature
scheme that is not here becomes usable throughout the library the day it
implements one of them. HMAC takes a function that makes a hash rather than a
hash function, which is why one HMAC serves every digest — including yours.

Failures raise. `@spec.Broken` says whether a length was wrong, and with what
was expected, or whether an authentication tag did not match. Verification is
the exception: it answers `Bool`, because a bad signature is an expected
outcome, not an exceptional one.

Secrets are compared with `@spec.eq`, which reads both inputs to the end. It is
the only comparison the library offers, so there is no wrong one to reach for.

## What is checked

Every algorithm is tested against the vectors its specification publishes —
FIPS 180-4's worked examples, RFC 4231, RFC 5869 appendix A, RFC 6070, RFC 8032
§7.1, RFC 6979 §A.2.5 — and, where a specification publishes none, against
signatures produced by a third-party implementation. The curve parameters were
derived from a third-party library rather than transcribed, and checked: the
generator on the curve, the order annihilating it.

Beyond the vectors, each hash is checked for agreement between one-shot and
chunked writes at every split around a block boundary, and each signature scheme
is checked to refuse a bent byte, a truncated signature, a foreign key and an
out-of-range scalar.

## What is not here

Symmetric ciphers, AEAD, SHA-3, BLAKE, the Chinese national algorithms,
post-quantum schemes, ASN.1 and key file formats, and a random-number generator.
They are planned, in that order; the tracking list lives with the project.

Certificates and tokens are not cryptography and live in `mooncred`; protocols
live in `moonhttp`, `moontls` and `moonquic`; encodings live in `moonbase`.

MD5 and SHA-1 are here because protocols in use still mandate them. Neither is
fit for new work, and both say so in their documentation.

## Install

```bash
moon add moonbitstack/mooncrypt
```

## Licence

Apache-2.0.
