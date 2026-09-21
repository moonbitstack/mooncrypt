// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Every corner of mooncrypt in one run: a digest, a MAC over that digest, two
/// key derivations, and the two signature schemes — each one reached through the
/// same small set of traits.
///
///     moon run examples/tour
#coverage.skip
fn main raise {
  let sha256 = fn() -> &@spec.Hash { @sha2.Hasher::new() }
  let msg = b"the quick brown fox"

  // A digest, one shot and streamed. The streamed one is how a large body is
  // hashed without holding it.
  println("sha256      -> \{@base16.encode(@sha2.hash(msg[:]))}")
  let running = @sha2.Hasher::new(kind=Sha512)
  running.write(b"the quick "[:])
  running.write(b"brown fox"[:])
  println("sha512      -> \{@base16.encode(running.finish()[:])[0:32]}…")

  // A MAC. The hash goes in as a factory, so the same HMAC serves every digest.
  let tag = @hmac.mac(b"shared secret"[:], msg[:], sha256)
  println("hmac-sha256 -> \{@base16.encode(tag[:])}")
  println("constant-time compare -> \{@spec.eq(tag[:], tag[:])}")

  // Two key derivations: one for a handshake secret, one for a password.
  let key = @hkdf.key(
    b"input keying material"[:],
    sha256,
    salt=b"salt"[:],
    info=b"client write key"[:],
    len=32,
  )
  println("hkdf        -> \{@base16.encode(key[:])}")
  let stretched = @pbkdf2.key(
    b"correct horse"[:],
    b"battery staple"[:],
    sha256,
    rounds=4096,
    len=32,
  )
  println("pbkdf2      -> \{@base16.encode(stretched[:])}")

  // Ed25519: the key is a 32-byte seed and signing is deterministic.
  let seed = @base16.decode_lossy(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let ed = @ed25519.PrivateKey::new(seed[:])
  let ed_sig = ed.sign(msg[:])
  println("ed25519 key -> \{@base16.encode(ed.public().bytes()[:])}")
  println("ed25519 ok  -> \{ed.public().verify(msg[:], ed_sig[:])}")

  // ECDSA over P-256, with the RFC 6979 nonce — also deterministic.
  let scalar = @base16.decode_lossy(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let ec = @ecdsa.PrivateKey::new(scalar[:])
  let ec_sig = ec.sign(msg[:])
  println("ecdsa p-256 -> \{@base16.encode(ec_sig[:])[0:32]}…")
  println("ecdsa ok    -> \{ec.public().verify(msg[:], ec_sig[:])}")
  println(
    "ecdsa bent  -> \{ec.public().verify(b"the quick brown fix"[:], ec_sig[:])}",
  )
}
