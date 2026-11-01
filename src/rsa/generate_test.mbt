// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A deterministic source, so a generated key is reproducible: the same seed
/// gives the same primes and the same modulus on every run.
fn seeded() -> @drbg.HmacDrbg {
  @drbg.HmacDrbg::new(
    fn() { @sha2.Hasher::new() },
    entropy=b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"[:],
    nonce=b"\x00\x01\x02\x03\x04\x05\x06\x07"[:],
    personalization=b"rsa-keygen-test"[:],
  )
}

///|
test "RSA generates a 512-bit key that signs and verifies" {
  let key = @rsa.PrivateKey::generate(seeded(), bits=512) catch {
    _ => abort("rsa: a generator must never exhaust")
  }
  assert_eq(key.size(), 64)
  let msg = b"a message for the generated key"[:]
  let sig = key.sign(msg)
  assert_eq(sig.length(), 64)
  assert_true(key.public().verify(msg, sig[:]))
}

///|
test "RSA generation is reproducible from the same seed" {
  let a = @rsa.PrivateKey::generate(seeded(), bits=512) catch {
    _ => abort("rsa: a generator must never exhaust")
  }
  let b = @rsa.PrivateKey::generate(seeded(), bits=512) catch {
    _ => abort("rsa: a generator must never exhaust")
  }
  assert_eq(a.public().modulus(), b.public().modulus())
}
