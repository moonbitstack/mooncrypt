// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn seed_of(kind : @mldsa.Kind) -> Bytes {
  match kind {
    @mldsa.D44 =>
      @base16.decode_lossy(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      )
    @mldsa.D65 =>
      @base16.decode_lossy(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      )
    _ =>
      @base16.decode_lossy(
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
      )
  }
}

///|
test "a signature verifies, and only under the message it was made for" {
  for kind in [@mldsa.D44, @mldsa.D65, @mldsa.D87] {
    let key = @mldsa.PrivateKey::from_seed(kind~, seed_of(kind)[:])
    let public = key.public_key()
    assert_eq(key.bytes().length(), kind.private_key())
    assert_eq(public.bytes().length(), kind.public_key())
    let msg = b"the quick brown fox jumps over the lazy dog"
    let sig = key.sign(msg[:])
    assert_eq(sig.length(), kind.signature())
    assert_true(public.verify(msg[:], sig[:]))
    assert_false(
      public.verify(b"the quick brown fox jumps over the lazy cog"[:], sig[:]),
    )
  }
}

///|
test "the deterministic variant repeats and a context separates the two uses" {
  let key = @mldsa.PrivateKey::from_seed(
    kind=@mldsa.D44,
    seed_of(@mldsa.D44)[:],
  )
  let msg = b"a message signed twice"
  let first = key.sign(msg[:])
  let again = key.sign(msg[:])
  assert_eq(first, again)
  let other = key.sign(msg[:], context=b"another protocol"[:])
  assert_true(other != first)
  assert_true(
    key.public_key().verify(msg[:], other[:], context=b"another protocol"[:]),
  )
  assert_false(key.public_key().verify(msg[:], other[:]))
}

///|
test "the hedged variant draws fresh randomness and still verifies" {
  let key = @mldsa.PrivateKey::from_seed(
    kind=@mldsa.D44,
    seed_of(@mldsa.D44)[:],
  )
  let msg = b"a message worth hedging"
  let source = @moonseed.Replay::new(
    @base16.decode_lossy(
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
    ),
  )
  let sig = key.sign_randomized(msg[:], source)
  assert_true(key.public_key().verify(msg[:], sig[:]))
  assert_false(@spec.eq(sig, key.sign(msg[:])))
}

///|
test "a signature that was tampered with does not verify" {
  let key = @mldsa.PrivateKey::from_seed(
    kind=@mldsa.D44,
    seed_of(@mldsa.D44)[:],
  )
  let msg = b"a message under attack"
  let sig = key.sign(msg[:])
  let bad = sig.to_array()
  bad[0] = (bad[0].to_int() ^ 1).to_byte()
  assert_false(key.public_key().verify(msg[:], Bytes::from_array(bad)[:]))
  // A signature of the wrong length is refused without reading past its end.
  assert_false(key.public_key().verify(msg[:], sig[0:10]))
}

///|
test "a pre-hashed signature is not a plain one and does not verify as such" {
  let key = @mldsa.PrivateKey::from_seed(
    kind=@mldsa.D65,
    seed_of(@mldsa.D65)[:],
  )
  let msg = b"a message that arrives already digested"
  let sig = key.sign(msg[:], prehash=@mldsa.Sha2_256)
  assert_true(key.public_key().verify(msg[:], sig[:], prehash=@mldsa.Sha2_256))
  assert_false(key.public_key().verify(msg[:], sig[:]))
  // Each pre-hash names itself, so one cannot stand in for another.
  assert_false(key.public_key().verify(msg[:], sig[:], prehash=@mldsa.Sha2_512))
}

///|
test "the two traits carry a plain signature with an empty context" {
  let key = @mldsa.PrivateKey::from_seed(
    kind=@mldsa.D44,
    seed_of(@mldsa.D44)[:],
  )
  let signer : &@spec.Signer = key
  let verifier : &@spec.Verifier = key.public_key()
  let msg = b"through the traits"
  let sig = signer.sign(msg[:])
  assert_true(verifier.verify(msg[:], sig[:]))
  assert_eq(sig, key.sign(msg[:]))
}

///|
test "panic on a context longer than the standard allows" {
  let key = @mldsa.PrivateKey::from_seed(
    kind=@mldsa.D44,
    seed_of(@mldsa.D44)[:],
  )
  let long = Bytes::makei(256, fn(i) { (i & 0xFF).to_byte() })
  ignore(key.sign(b"a message"[:], context=long[:]))
}

///|
test "panic on a seed of the wrong length" {
  ignore(@mldsa.PrivateKey::from_seed(kind=@mldsa.D44, b"\x00"))
}

///|
test "a signing key read from its bytes signs what it signed before" {
  let key = @mldsa.PrivateKey::from_seed(
    kind=@mldsa.D44,
    seed_of(@mldsa.D44)[:],
  )
  let reread = @mldsa.PrivateKey::new(kind=@mldsa.D44, key.bytes()[:])
  let msg = b"the same key, read twice"
  assert_eq(reread.sign(msg[:]), key.sign(msg[:]))
  assert_eq(reread.public_key().bytes(), key.public_key().bytes())
}
