// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A seed of three `n`-byte values, the same for every set.
fn seed_of(kind : @slhdsa.Kind) -> Bytes {
  let len = kind.seeds()
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = (i & 0xFF).to_byte()
  }
  Bytes::from_array(out)
}

///|
test "a signature verifies, and only under the message it was made for" {
  for kind in [@slhdsa.Sha2_128f, @slhdsa.Shake_128f, @slhdsa.Sha2_192f] {
    let key = @slhdsa.PrivateKey::from_seed(kind~, seed_of(kind)[:])
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
test "the slow sets sign and verify too" {
  let kind = @slhdsa.Sha2_128s
  let key = @slhdsa.PrivateKey::from_seed(kind~, seed_of(kind)[:])
  let msg = b"a message worth a slow signature"
  let sig = key.sign(msg[:])
  assert_eq(sig.length(), kind.signature())
  assert_true(key.public_key().verify(msg[:], sig[:]))
  assert_false(key.public_key().verify(b"a different message"[:], sig[:]))
}

///|
test "a context separates two uses of one key" {
  let key = @slhdsa.PrivateKey::from_seed(
    kind=@slhdsa.Sha2_128f,
    seed_of(@slhdsa.Sha2_128f)[:],
  )
  let msg = b"a message under two contexts"
  let first = key.sign(msg[:], context=b"one"[:])
  let second = key.sign(msg[:], context=b"two"[:])
  assert_true(@spec.eq(first, second) == false)
  assert_true(key.public_key().verify(msg[:], first[:], context=b"one"[:]))
  assert_false(key.public_key().verify(msg[:], first[:], context=b"two"[:]))
  assert_false(key.public_key().verify(msg[:], first[:]))
}

///|
test "a pre-hashed signature is not a plain one" {
  let key = @slhdsa.PrivateKey::from_seed(
    kind=@slhdsa.Sha2_128f,
    seed_of(@slhdsa.Sha2_128f)[:],
  )
  let msg = b"a message that arrives already digested"
  let sig = key.sign(msg[:], prehash=@slhdsa.Sha3_256)
  assert_true(key.public_key().verify(msg[:], sig[:], prehash=@slhdsa.Sha3_256))
  assert_false(key.public_key().verify(msg[:], sig[:]))
}

///|
test "a signature that was tampered with does not verify" {
  let key = @slhdsa.PrivateKey::from_seed(
    kind=@slhdsa.Shake_128f,
    seed_of(@slhdsa.Shake_128f)[:],
  )
  let msg = b"a message under attack"
  let sig = key.sign(msg[:])
  let bad = sig.to_array()
  // The last byte is inside the hypertree signature, so a change there has to
  // reach the root check rather than being caught by a length test.
  bad[bad.length() - 1] = (bad[bad.length() - 1].to_int() ^ 1).to_byte()
  assert_false(key.public_key().verify(msg[:], Bytes::from_array(bad)[:]))
  assert_false(key.public_key().verify(msg[:], sig[0:10]))
}

///|
test "the two traits carry a plain signature with an empty context" {
  let key = @slhdsa.PrivateKey::from_seed(
    kind=@slhdsa.Sha2_128f,
    seed_of(@slhdsa.Sha2_128f)[:],
  )
  let signer : &@spec.Signer = key
  let verifier : &@spec.Verifier = key.public_key()
  let msg = b"through the traits"
  let sig = signer.sign(msg[:])
  assert_true(verifier.verify(msg[:], sig[:]))
  assert_eq(sig, key.sign(msg[:]))
}

///|
test "a signing key read from its bytes signs what it signed before" {
  let key = @slhdsa.PrivateKey::from_seed(
    kind=@slhdsa.Shake_128f,
    seed_of(@slhdsa.Shake_128f)[:],
  )
  let reread = @slhdsa.PrivateKey::new(kind=@slhdsa.Shake_128f, key.bytes()[:])
  let msg = b"the same key, read twice"
  assert_eq(reread.sign(msg[:]), key.sign(msg[:]))
  assert_eq(reread.public_key().bytes(), key.public_key().bytes())
}

///|
test "panic on a seed of the wrong length" {
  ignore(@slhdsa.PrivateKey::from_seed(kind=@slhdsa.Sha2_128f, b"\x00"))
}
