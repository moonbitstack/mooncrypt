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

## Rules that catch people out

- **Nonces are consumed.** Draw a fresh nonce from a CSPRNG for every message;
  reusing one with the same key under a stream-based AEAD hands over the
  plaintext. `@system.source` is the platform's entropy source.
- **A signature is compared, not parsed.** A verifier that looks at the bytes
  instead of comparing them is where forgeries get in; the verify methods
  compare, and a bent byte or a truncated tag is refused.
- **The padding and the hash travel together.** A signature under SHA-256 does
  not verify under SHA-1 with the same key, and the same key signs under
  whichever digest it is asked to.
- **Post-quantum keys are wide.** An ML-KEM or ML-DSA key is hundreds of
  bytes, not the 32 an elliptic-curve key is; size buffers for that before
  putting them on the wire.
