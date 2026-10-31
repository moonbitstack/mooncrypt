// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
fn ascii(s : String) -> Bytes {
  @utf8.encode(s)
}

///|
/// A key of `n` bytes, counting up from zero — the shape the BLAKE2 KAT files
/// use for their keys.
fn ramp(n : Int32) -> Bytes {
  Bytes::from_array(Array::make(n, 0).mapi(fn(i, _) { i.to_byte() }))
}

///|
/// The worked example in RFC 7693 §A, and the empty message, which is the one
/// block that never fills.
test "BLAKE2b and BLAKE2s match the RFC 7693 examples" {
  assert_eq(
    hex(@blake2.hash(b"abc"[:])),
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
  )
  assert_eq(
    hex(@blake2.hash(b"abc"[:], kind=Blake2s)),
    "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
  )
  assert_eq(
    hex(@blake2.hash(b""[:])),
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
  )
}

///|
/// A shorter digest is a different function, not a truncation: the length is
/// folded into the parameter block.
test "BLAKE2 takes the digest length from the parameter block" {
  assert_eq(
    hex(@blake2.hash(b"abc"[:], len=32)),
    "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
  )
  let h = @blake2.Hasher::new(kind=Blake2s, len=16)
  assert_eq(h.size(), 16)
  assert_eq(h.block(), 64)
  assert_eq(@blake2.Hasher::new().block(), 128)
}

///|
/// The block boundary: one byte past a whole block is where the held-back block
/// finally gets compressed.
test "BLAKE2 holds the last block back" {
  let long = Bytes::from_array(Array::make(129, b'a'))
  assert_eq(
    hex(@blake2.hash(long[:])),
    "55e6e0eb418149a8af92fd9ddc99254781b2f522a131b4f4d984404b71a00e1167b8124d5dcddd4c6977b299392335d6edd303da6d344d74bbef2d38101b232b",
  )
  let short = Bytes::from_array(Array::make(65, b'a'))
  assert_eq(
    hex(@blake2.hash(short[:], kind=Blake2s)),
    "045f8ae18932119bd051ac7ba5c73db59892055fad5c32f82d79a6543d92a497",
  )
}

///|
/// Keying is a field of the parameter block, so a keyed digest is unrelated to
/// the unkeyed one over the same message.
test "BLAKE2 keys, and a reset keeps the key" {
  let key = ramp(64)
  assert_eq(
    hex(@blake2.hash(b"abc"[:], key=key[:])),
    "06bbc3dedf13a31139498655251b7588ccd3bb5aaa071b2d44d8e0a04095579ed590fbfdcf941f4370ce5ce623624e7a76d33e7a8109dcda9b57d72f8f8efa51",
  )
  assert_eq(
    hex(@blake2.hash(b"abc"[:], kind=Blake2s, key=ramp(32)[:])),
    "a281f725754969a702f6fe36fc591b7def866e4b70173ece402fc01c064d6b65",
  )
  let long = Bytes::from_array(Array::make(128, b'a'))
  assert_eq(
    hex(@blake2.hash(long[:], key=key[:])),
    "9792d5d15fd64e3604791412c384bd664158fd0d4d91f9798201ac1b71108e4762baf64472d6a682b2a40e51133b570e2379e0654a4e2c2ffe6c4240c123a87c",
  )
  // The same key again after a reset must give the same digest: the key block
  // has to come back, not just the initial vector.
  let h = @blake2.Hasher::new(key=key[:])
  h.write(b"abc"[:])
  let first = h.finish()
  h.reset()
  h.write(b"abc"[:])
  assert_eq(hex(h.finish()), hex(first))
  assert_eq(hex(@blake2.mac(key[:], b"abc"[:])), hex(first))
}

///|
/// Salt and personalisation sit in the parameter block beside the key.
test "BLAKE2 salts and personalises" {
  let salt = ramp(16)
  let person : Bytes = Bytes::from_array(
    Array::make(16, 0).mapi(fn(i, _) { (0x10 + i).to_byte() }),
  )
  assert_eq(
    hex(@blake2.hash(b"abc"[:], salt=salt[:], person=person[:])),
    "4c250e3899299f4705d220d1d0393a7407554308252e36ee3b5a9657854682ceaff1bedc20a2d5240326843632d474dcf854356c11601f348e67b334603df08c",
  )
  let s8 = ramp(8)
  let p8 : Bytes = Bytes::from_array(
    Array::make(8, 0).mapi(fn(i, _) { (8 + i).to_byte() }),
  )
  assert_eq(
    hex(@blake2.hash(b"abc"[:], kind=Blake2s, salt=s8[:], person=p8[:])),
    "068d368ee868f22aa89568c8de5f141ddb4c6a01e1c9460b6796a6a3b4b79257",
  )
  assert_eq(@blake2.Kind::salt_size(Blake2b), 16)
  assert_eq(@blake2.Kind::salt_size(Blake2s), 8)
}

///|
/// A message in pieces is the same message, and reading twice answers the same
/// digest.
test "BLAKE2 streams and reads twice" {
  let whole = @blake2.hash(ascii("the quick brown fox")[:])
  let h = @blake2.Hasher::new()
  h.write(b"the quick "[:])
  h.write(b"brown fox"[:])
  assert_eq(hex(h.finish()), hex(whole))
  assert_eq(hex(h.finish()), hex(whole))
  h.reset()
  h.write(ascii("the quick brown fox")[:])
  assert_eq(hex(h.finish()), hex(whole))
}
