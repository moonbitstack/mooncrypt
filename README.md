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
| `spec` | The `Hash`, `Mac`, `Block`, `Aead`, `Signer` and `Verifier` traits, constant-time comparison, erasure | — |
| `hash/sha2` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | FIPS 180-4 |
| `hash/sha1` | SHA-1 | FIPS 180-4 |
| `hash/md5` | MD5 | RFC 1321 |
| `mac/hmac` | HMAC over any `Hash` | RFC 2104, FIPS 198-1 |
| `kdf/hkdf` | HKDF, extract and expand separately | RFC 5869 |
| `kdf/pbkdf2` | PBKDF2 | RFC 8018 §5.2 |
| `sign/ed25519` | Ed25519 | RFC 8032 |
| `sign/ecdsa` | ECDSA over P-256, P-384, P-521 and secp256k1, with RFC 6979 nonces | FIPS 186-4, RFC 6979 |
| `sign/rsa` | RSA PKCS#1 v1.5 and PSS signatures | RFC 8017 |
| `cipher/aes` | AES-128, AES-192 and AES-256, both directions | FIPS 197 |
| `aead/gcm` | GCM over any 128-bit block cipher, any nonce length, the seven tag lengths | SP 800-38D |
| `kex/x25519` | X25519, with a low-order point refused | RFC 7748 |
| `asn1` | ASN.1 DER, read and write — the layer a key file and a certificate are built on | ITU-T X.690 |

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

## Configuration

Everything a caller chooses is already an argument: `kind` picks the SHA-2
variant, `curve` the ECDSA curve, `digest` and `scheme` the RSA padding and its
hash, `salt` and `info` the HKDF inputs, and `Pss(salt=32)` carries its own salt
length rather than assuming one.

What is not an argument is what a specification fixes: HMAC's inner and outer
pads, MD5's constants, SHA-2's round constants and initial values, the curve
parameters, Ed25519's field constants. Those are not configuration, and making
them settable would only let a caller compute something that is not the
algorithm.

Two things have deliberately **no** default:

| Setting | Why there is no default |
|:--:|:--|
| `pbkdf2.key(rounds~)` | The iteration count is the whole security argument and goes out of date silently. Python's `hashlib.pbkdf2_hmac`, Go's `pbkdf2.Key` and Node's `crypto.pbkdf2` all require it, so requiring it *is* the mainstream default |
| `len~` on both KDFs | How many bytes of key are wanted is a property of what the key is for |
| `gcm.Gcm::new(tag~)` | 16 | The full 128-bit tag, the only length SP 800-38D appendix C leaves unqualified. The shorter ones it defines are there, and each costs forgery resistance the appendix works out |

Two things are deliberately **not** knobs. `aes.Cipher::new` reads the variant off
the key length rather than taking one, because the length is what distinguishes
the three and a key that disagrees with a named variant would be a second way to
be wrong. `x25519.shared` always refuses a low-order point: the check is a MAY in
RFC 7748 §6.1 and a MUST in TLS 1.3, every implementation in use makes it, and a
switch to turn it off would only make the dangerous call the short one.

The aborts in this library are programming errors rather than runtime
conditions: fewer than one PBKDF2 round, a negative key length, more than 255
HKDF digests from one key, a modulus too small for the digest it must carry.
None of them can arise from input, so none of them is a `raise` a caller could
usefully catch.

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
