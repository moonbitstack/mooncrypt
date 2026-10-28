# mooncrypt

Cryptographic algorithms for MoonBit, one algorithm to a package.

```moonbit
let sha256 = fn() -> &@spec.Hash { @sha2.Hasher::new() }

// A digest, a MAC, and a key derived from a password.
let digest = @sha2.hash(b"the quick brown fox"[:])
let tag = @hmac.mac(b"shared secret"[:], b"the quick brown fox"[:], sha256)
let key = @pbkdf2.key(b"correct horse"[:], b"battery staple"[:], sha256,
                      rounds=600000, len=32)

// Authenticated encryption, over any 128-bit block cipher.
let box = @sm4gcm.new(key[0:16])
let sealed = box.seal(nonce=nonce[:], plain=b"the quick brown fox"[:], aad=b"v1"[:])
box.open(nonce=nonce[:], cipher=sealed[:], aad=b"v1"[:])  // the plaintext, or a raise

// A signature. Both schemes here are deterministic: the same key and message
// always give the same bytes, so there is no entropy source to get wrong.
let sk = @ed25519.PrivateKey::new(seed[:])
let sig = sk.sign(b"the quick brown fox"[:])
sk.public().verify(b"the quick brown fox"[:], sig[:])  // true
```

Run `moon run src/examples/tour` for the whole surface in one go — fifty-odd
algorithms, each reached through the same handful of traits.

## Packages

Import the ones you use. A package nothing imports is not linked, which is what
`features` buys in other languages, without a build-time switch.

| Package | What | Specification |
|:--:|:--|:--|
| `spec` | The `Hash`, `Mac`, `Block`, `Aead`, `Signer` and `Verifier` traits, constant-time comparison, erasure | — |
| `hash/sha2` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | FIPS 180-4 |
| `hash/sha1` | SHA-1 — legacy: collisions are cheap enough to be routine | FIPS 180-4 |
| `hash/sha3` | SHA3-224/256/384/512, SHAKE128 and SHAKE256, and the cSHAKE encoding rules KMAC is built from | FIPS 202, SP 800-185 |
| `hash/blake2` | BLAKE2b and BLAKE2s, with key, salt and personalisation | RFC 7693 |
| `hash/blake3` | BLAKE3, including keyed and derive-key modes and the extendable output | BLAKE3 spec |
| `hash/sm3` | SM3 | GB/T 32905-2016 |
| `hash/md5` | MD5 — legacy, and broken for anything adversarial | RFC 1321 |
| `hash/ripemd` | RIPEMD-160 — legacy: a 1996 design kept for the data that already uses it | Dobbertin–Bosselaers–Preneel |
| `mac/hmac` | HMAC over any `Hash` | RFC 2104, FIPS 198-1 |
| `mac/poly1305` | Poly1305, the one-time authenticator | RFC 8439 §2.5 |
| `mac/cmac` | CMAC over any `Block`, any tag length up to the block size | SP 800-38B |
| `mac/gmac` | GMAC, GCM's authenticator on its own | SP 800-38D |
| `mac/kmac` | KMAC128 and KMAC256, and the XOF form | SP 800-185 §4 |
| `mac/siphash` | SipHash-2-4, a 64-bit keyed hash | Aumasson & Bernstein 2012 |
| `sum/crc32` | CRC-32 and CRC-32C | IEEE 802.3, RFC 3720 |
| `sum/crc16` | The common CRC-16 variants | CRC catalogue |
| `sum/adler32` | Adler-32 | RFC 1950 §9 |
| `sum/fnv` | FNV-1 and FNV-1a, 32 and 64 bit | Fowler–Noll–Vo |
| `sum/xxhash` | XXH32 and XXH64, with a seed | xxHash spec |
| `sum/murmur3` | MurmurHash3 x86_32 and x64_128 | Appleby |
| `kdf/hkdf` | HKDF, extract and expand separately | RFC 5869 |
| `kdf/pbkdf2` | PBKDF2 | RFC 8018 §5.2 |
| `kdf/scrypt` | scrypt, with presets for interactive and sensitive use, and the parameter check | RFC 7914 |
| `kdf/argon2` | Argon2d, Argon2i and Argon2id, with secret and associated data | RFC 9106 |
| `kdf/bcrypt` | bcrypt, the `$2b$` text format and a constant-time verify | Provos & Mazières 1999 |
| `kdf/concat` | The Concat KDF, as a NIST key agreement derives from a shared secret | SP 800-56A §5.8.1 |
| `curve` | The curves an EC key can live on — P-256, P-384, P-521, secp256k1 — and their coordinate width; `sign/ecdsa` and `kex/ecdh` re-export it, import it to name a curve | FIPS 186-4, SEC 2 |
| `sign/ed25519` | Ed25519 | RFC 8032 |
| `sign/ed448` | Ed448, with context and the prehash form | RFC 8032 |
| `sign/ecdsa` | ECDSA over P-256, P-384, P-521 and secp256k1, with RFC 6979 nonces | FIPS 186-4, RFC 6979 |
| `sign/schnorr` | Schnorr over secp256k1, x-only keys and all | BIP 340 |
| `sign/sm2` | SM2, with the signer identity mixed into the hash | GB/T 32918.2-2016 |
| `rsa` | RSA PKCS#1 v1.5 and PSS signatures, OAEP encryption | RFC 8017 |
| `cipher/aes` | AES-128, AES-192 and AES-256, both directions | FIPS 197 |
| `cipher/sm4` | SM4 | GB/T 32907-2016 |
| `cipher/camellia` | Camellia-128/192/256 | RFC 3713 |
| `cipher/mode` | CBC and CTR over any `Block`, with PKCS#7 padding | SP 800-38A |
| `cipher/chacha20` | ChaCha20 with the 96-bit nonce, and one block on its own for QUIC's header protection | RFC 8439 §2.3–2.4 |
| `cipher/xchacha20` | XChaCha20, the 192-bit nonce form | draft-irtf-cfrg-xchacha |
| `cipher/blowfish` | Blowfish — legacy, and the core of bcrypt | Schneier 1993 |
| `cipher/des` | DES and triple DES, E-D-E in both key forms — legacy: a 56-bit key | FIPS 46-3 |
| `cipher/rc4` | RC4 and its keystream — legacy: the first bytes are biased | — |
| `cipher/salsa20` | Salsa20 — legacy: superseded by ChaCha20 | Bernstein 2005 |
| `aead/gcm` | GCM over any 128-bit block cipher, any nonce length, the seven tag lengths | SP 800-38D |
| `aead/chachapoly` | ChaCha20-Poly1305 | RFC 8439 §2.8 |
| `aead/sm4gcm` | SM4-GCM | SP 800-38D, GB/T 32907 |
| `aead/ccm` | CCM over any 128-bit block cipher, any even tag length from 4 to 16 bytes | SP 800-38C, RFC 3610 |
| `aead/siv` | AES-SIV, nonce misuse resistant, with the multi-AD form | RFC 5297 |
| `kex/x25519` | X25519, with a low-order point refused | RFC 7748 |
| `kex/x448` | X448, with the same refusal | RFC 7748 |
| `kex/ecdh` | ECDH over P-256, P-384, P-521 and secp256k1, with an off-curve point refused | SEC 1 §3.3.1 |
| `kex/dh` | Finite-field Diffie-Hellman over the five ffdhe groups, with a range check on the peer's share | RFC 7919 |
| `otp` | HOTP and TOTP, 6 to 9 digits, with a clock skew window | RFC 4226, RFC 6238 |
| `key` | Key files: PEM around DER, in PKCS#1, PKCS#8, SPKI and SEC1 shapes | RFC 7468, RFC 8017, RFC 5958, RFC 5915 |
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

Everything a caller chooses is already an argument: `kind` picks the SHA-2, SHA-3,
BLAKE2, KMAC or xxHash variant, `curve` the ECDSA curve, `digest` and `scheme`
the RSA padding and its hash, `salt` and `info` the HKDF inputs, `params` the
scrypt and Argon2 cost, `cost` bcrypt's, `tag` the CCM, SIV and GMAC tag length,
`group` the RFC 7919 group, `digits` the one-time password length, and
`Pss(salt=32)` carries its own salt length rather than assuming one.

What is not an argument is what a specification fixes: HMAC's inner and outer
pads, MD5's constants, SHA-2's round constants and initial values, the curve
parameters, Ed25519's field constants. Those are not configuration, and making
them settable would only let a caller compute something that is not the
algorithm.

Three things have deliberately **no** default:

| Setting | Why there is no default |
|:--:|:--|
| `pbkdf2.key(rounds~)` | The iteration count is the whole security argument and goes out of date silently. Python's `hashlib.pbkdf2_hmac`, Go's `pbkdf2.Key` and Node's `crypto.pbkdf2` all require it, so requiring it *is* the mainstream default |
| `len~` on HKDF and PBKDF2 | How many bytes of key are wanted is a property of what the key is for |
| `gcm.Gcm::new(tag~)` | 16 — the full 128-bit tag, the only length SP 800-38D appendix C leaves unqualified. The shorter ones it defines are there, and each costs forgery resistance the appendix works out |

The checks that could have been switches are not. `aes.Cipher::new` and
`camellia.Cipher::new` read the variant off the key length rather than taking one,
because the length is what distinguishes the variants and a key that disagrees
with a named variant would be a second way to be wrong. `x25519.shared` and
`x448.shared` always refuse a low-order point: the check is a MAY in RFC 7748
§6.1 and a MUST in TLS 1.3, and a switch to turn it off would only make the
dangerous call the short one. `dh.Private::shared` always refuses a peer share
outside `[2, p-2]` for the same reason, and every AEAD's `open` raises rather than
returning an empty plaintext when the tag does not match.

The aborts in this library are programming errors rather than runtime
conditions: fewer than one PBKDF2 round, a negative key length, more than 255
HKDF digests from one key, a modulus too small for the digest it must carry.
None of them can arise from input, so none of them is a `raise` a caller could
usefully catch.

## What is checked

Every algorithm is tested against the vectors its specification publishes —
FIPS 180-4's worked examples, RFC 4231, RFC 5869 appendix A, RFC 6070, RFC 8032
§7.1, RFC 6979 §A.2.5, RFC 3713 appendix A, RFC 6229, RFC 9106 §5, RFC 7914 §12,
RFC 4226 appendix D, RFC 6238 appendix B, BIP 340's CSV, and the CAVP response
files where NIST publishes them — and, where a specification publishes none,
against signatures produced by a third-party implementation. The curve
parameters were derived from a third-party library rather than transcribed, and
checked: the generator on the curve, the order annihilating it.

Where a generator exists in `scripts/`, it is held to two conditions before it
will emit a row: it must first reproduce a published answer, and then agree with
an independent implementation. A misread specification breaks the first; a
shared mistake with the reference breaks the second. Between them they caught two
real bugs during this work — a wrong RIPEMD-160 finalisation and a Schnorr tag
hash that concatenated its prefix without hashing the result.

Beyond the vectors, each hash is checked for agreement between one-shot and
chunked writes at every split around a block boundary, and each signature scheme
is checked to refuse a bent byte, a truncated signature, a foreign key and an
out-of-range scalar. Each AEAD is checked at the tag lengths it defines and with
and without associated data, and each block cipher at every key length it takes,
because those are the branches a vector copied straight from a specification
never reaches.

## What is not here

Post-quantum schemes, and a random-number generator. Those two are the rest of
the plan; the tracking list lives with the project.

Certificates and tokens are not cryptography and live in `mooncred`; protocols
live in `moonhttp`, `moontls` and `moonquic`; encodings live in `moonbase`.

## Legacy algorithms

Five packages implement things no new design should start with, and each says so
at the top of its module: `hash/md5`, `hash/sha1`, `cipher/des`, `cipher/rc4`
and `cipher/salsa20`, along with the older entries in `hash/ripemd` and
`cipher/blowfish`. They are here because data encrypted or signed with them
still has to be read, and because a protocol in use may still mandate one.

They are not deprecated past the point of working: each passes the same vectors
as everything else, and MD5's and SHA-1's documentation say what they are still
good for (nothing that involves an adversary choosing the input) and what they
are not.

## Install

```bash
moon add moonbitstack/mooncrypt
```

## Licence

Apache-2.0.
