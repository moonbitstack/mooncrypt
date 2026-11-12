// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A deterministic source, so the key in these tests is the same on every run
/// and on every backend — the wasm targets have no entropy to draw from.
fn mgf_seeded() -> @drbg.HmacDrbg {
  @drbg.HmacDrbg::new(
    fn() { @sha2.Hasher::new() },
    entropy=b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"[:],
    nonce=b"\x20\x21\x22\x23\x24\x25\x26\x27"[:],
    personalization=b"rsa-pss-mgf-test"[:],
  )
}

///|
/// A key that signs with a mask hash of its own: the block it makes is the one
/// the same scheme decodes, and no other setting decodes it.
///
/// This is the direction the vectors cannot cover. OpenSSL's block with MGF1-SHA-1
/// under a SHA-256 message is a signature to verify, made with a salt it drew at
/// random; nothing here can reproduce those bytes, so what a signature under
/// `PssMgf` must be is checked by making one and decoding it — with the mask
/// hash, with the message hash, and with a third one, and only the first is
/// right.
test "a PSS block masked with a hash of its own decodes under that hash alone" {
  let msg = b"the quick brown fox jumps over the lazy dog"[:]
  let sk = @rsa.PrivateKey::generate(
    mgf_seeded(),
    bits=1024,
    digest=Sha256,
    scheme=@rsa.PssMgf(salt=@rsa.Auto, mgf=Sha1),
  ) catch {
    _ => abort("rsa: a generator must never exhaust")
  }
  let sig = sk.sign(msg)
  let pk = sk.public()
  assert_true(pk.verify(msg, sig[:]))
  // The mask is SHA-1's. A key that masks with the message digest reads the
  // same block as broken, and so does one that masks with SHA-384 — which is
  // what makes the two parameters two parameters.
  for mgf in [@rsa.Sha256, @rsa.Sha384] {
    let other = pk.with_scheme(
      digest=Sha256,
      scheme=@rsa.PssMgf(salt=@rsa.Auto, mgf~),
    )
    assert_false(other.verify(msg, sig[:]))
  }
  // A plain `Pss` is `PssMgf` with the two alike, and this is not that.
  let plain = pk.with_scheme(digest=Sha256, scheme=@rsa.Pss(salt=@rsa.Auto))
  assert_false(plain.verify(msg, sig[:]))
  // The salt is derived rather than drawn, so the signature is reproducible.
  assert_eq(@spec.eq(sk.sign(msg)[:], sig[:]), true)
  assert_false(pk.verify(b"another message"[:], sig[:]))
}

///|
/// The salt length a signing key is built with is the length its block carries,
/// and a verifier that named another number refuses it.
test "a PSS-MGF salt of the caller's length is the block's length" {
  let msg = b"the quick brown fox jumps over the lazy dog"[:]
  let sk = @rsa.PrivateKey::generate(
    mgf_seeded(),
    bits=1024,
    digest=Sha256,
    scheme=@rsa.PssMgf(salt=@rsa.Exact(20), mgf=Sha1),
  ) catch {
    _ => abort("rsa: a generator must never exhaust")
  }
  let sig = sk.sign(msg)
  let pk = sk.public()
  let twenty = pk.with_scheme(
    digest=Sha256,
    scheme=@rsa.PssMgf(salt=@rsa.Exact(20), mgf=Sha1),
  )
  let thirtytwo = pk.with_scheme(
    digest=Sha256,
    scheme=@rsa.PssMgf(salt=@rsa.Exact(32), mgf=Sha1),
  )
  assert_true(twenty.verify(msg, sig[:]))
  assert_false(thirtytwo.verify(msg, sig[:]))
  // And under `Auto`, which reads the length back out of the block, it verifies
  // either way — that is what lets a peer that chose its own salt be read.
  assert_true(
    pk
    .with_scheme(digest=Sha256, scheme=@rsa.PssMgf(salt=@rsa.Auto, mgf=Sha1))
    .verify(msg, sig[:]),
  )
}
