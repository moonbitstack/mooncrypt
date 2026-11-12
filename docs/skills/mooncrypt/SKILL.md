---
name: mooncrypt
description: "Cryptographic algorithms for MoonBit, one per package: hashes, symmetric and public-key cryptography, message authentication, key exchange, key derivation, and post-quantum primitives. Use it whenever code needs to hash, encrypt, sign, MAC, derive keys, or do Diffie-Hellman rather than reach for a platform library."
---

# mooncrypt

Cryptographic algorithms for MoonBit, one per package. Add it and import the
packages you need; nothing is pulled in unless the code names it.

```mbt
import {
  "moonbitstack/mooncrypt/hash/sha2",
  "moonbitstack/mooncrypt/aead/chachapoly",
  "moonbitstack/mooncrypt/sign/ed25519",
}
```

## Hash a message

```mbt
let digest = @sha2.hash(b"the quick brown fox"[:])
assert_eq(digest.length(), 32)
```

## Seal and open a message

An AEAD binds the message to a nonce and any associated data; opening with the
wrong tag or the wrong nonce fails.

```mbt
let aead = @chachapoly.ChaChaPoly::new(@base16.decode("2b7e151628aed2a6abf7158809cf4f3c")[:])
let nonce = b"0123456789abcdef"[:]
let sealed = aead.seal(nonce~, plain=b"meet at dawn"[:], aad=b"context"[:])
let opened = aead.open(nonce~, cipher=sealed[:], aad=b"context"[:])
assert_eq(opened, b"meet at dawn")
```

## Sign and verify

A private key signs and its public half verifies; a bent message or a truncated
signature is refused.

```mbt
let sk = @ed25519.PrivateKey::generate(@system.source)
let sig = sk.sign(b"the quick brown fox"[:])
assert_true(sk.public().verify(b"the quick brown fox"[:], sig[:]))
assert_false(sk.public().verify(b"the quick brown fox!"[:], sig[:]))
```

## Sign with RSA, and name the salt

RSA is one key doing two jobs. `Pkcs1` is what certificates already carry; `Pss`
is what a new design should use. `Pss(salt=Auto)` signs at the digest's own
length — what TLS 1.3 and JOSE's PS256 require — and reads the length back out
of the block when verifying, so a signature a peer made with its own salt still
verifies. `Pss(salt=Exact(32))` holds both directions to the number given.

```mbt
let sk = @rsa.PrivateKey::generate(@system.source, scheme=@rsa.Pss(salt=@rsa.Auto))
let sig = sk.sign(b"the quick brown fox"[:])
assert_eq(sig.length(), 256)
assert_true(sk.public().verify(b"the quick brown fox"[:], sig[:]))
let strict = sk.public().with_scheme(digest=@rsa.Sha256, scheme=@rsa.Pss(salt=@rsa.Exact(16)))
assert_false(strict.verify(b"the quick brown fox"[:], sig[:]))
```

The digest is one of the names `Digest` carries — SHA-1, SHA-2 including
SHA-512/224 and SHA-512/256, and SHA-3 in four widths — because PKCS#1 v1.5
writes an ASN.1 identifier into the block it signs. PSS masks with the message
digest unless `PssMgf` names another:

```mbt
let mask = @rsa.PssMgf(salt=@rsa.Exact(20), mgf=@rsa.Sha1)
let peer = sk.public().with_scheme(digest=@rsa.Sha256, scheme=mask)
assert_true(peer.verify(b"the quick brown fox"[:], sk.with_scheme(
  digest=@rsa.Sha256,
  scheme=mask,
).sign(b"the quick brown fox"[:])[:]))
```

RFC 8702 is the same scheme over a SHAKE: `PssShake` names the variant, and the
mask is that SHAKE run natively over the seed rather than MGF1's counter over
it. The digest lengths are the profile's — 32 octets from SHAKE128, 64 from
SHAKE256 — and `Auto` signs at them.

```mbt
let shake = @rsa.PssShake(salt=@rsa.Auto, xof=@rsa.Shake128)
let signer = sk.with_scheme(digest=@rsa.Sha256, scheme=shake)
let shake_sig = signer.sign(b"the quick brown fox"[:])
assert_eq(shake_sig.length(), 256)
assert_true(signer.public().verify(b"the quick brown fox"[:], shake_sig[:]))
```

Encryption is OAEP — `encrypt` takes the seed OAEP masks with, because the
library holds no entropy source of its own — or RSAES-PKCS1-v1_5 through
`encrypt_pkcs1` and `decrypt_pkcs1` for the older data that still uses it.

A key with three primes signs and decrypts exactly as one with two: read it with
`@key.parse_rsa_private_multi`, which returns the nine fields and the primes
beyond them, then hand the third to `@rsa.PrivateKey::new_crt3`. The public half
and every wire format are the same — the factor count is the key's own business.

## Rules that catch people out

- **Nonces are consumed.** Draw a fresh nonce from a CSPRNG for every message;
  reusing one with the same key under a stream-based AEAD hands over the
  plaintext. `@system.source` is the platform's entropy source.
- **A signature is compared, not parsed.** A verifier that looks at the bytes
  instead of comparing them is where forgeries get in; the verify methods
  compare, and a bent byte or a truncated tag is refused.
- **A PSS salt length is a setting, not a guess.** `Auto` is the one to use
  unless a protocol names a number; a verifier built with `Exact(n)` refuses a
  signature whose salt is any other length, which is what RFC 8017 section 9.1.2
  asks for. Zero is a salt of no bytes, not a wildcard.
- **A SHAKE is named, not derived from a digest.** `PssShake` takes an `Xof`, and
  the two variants do not verify for each other: a block made under SHAKE128 is
  not a block under SHAKE256, and neither is a block under SHA-256.
- **The padding and the hash travel together.** A signature under SHA-256 does
  not verify under SHA-1 with the same key, and the same key signs under
  whichever digest it is asked to. If a peer masks with a hash of its own, say
  so with `PssMgf`; a plain `Pss` will read that block as broken.
- **Post-quantum keys are wide.** An ML-KEM or ML-DSA key is hundreds of
  bytes, not the 32 an elliptic-curve key is; size buffers for that before
  putting them on the wire.
