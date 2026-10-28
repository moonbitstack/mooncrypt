// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// The input every published vector is taken over: byte `i` is `i mod 251`, so
/// a long message has no repeating period to hide a discontinuity.
fn pattern(n : Int32) -> Bytes {
  Bytes::from_array(Array::make(n, 0).mapi(fn(i, _) { (i % 251).to_byte() }))
}

///|
/// Every published case, in all three modes, at the published length of 131
/// bytes. The lengths straddle every boundary that matters: one byte either
/// side of a block (64), of a chunk (1024) and of the powers of two the tree
/// doubles at.
test "BLAKE3 matches the published test vectors" {
  let key = @moonbase.ascii(vector_key)
  let context = @moonbase.ascii(vector_context)
  for case in vector_cases {
    let (len, plain, keyed, derived) = case
    let input = pattern(len)
    assert_eq(hex(@blake3.blake3(input[:], len=131)), plain)
    assert_eq(hex(@blake3.keyed_hash(key[:], input[:], len=131)), keyed)
    assert_eq(hex(@blake3.derive_key(context[:], input[:], len=131)), derived)
  }
}

///|
/// The reference vectors are the same function read at a different length, so a
/// 64-byte digest is the first 64 bytes of the 131-byte one.
test "BLAKE3 reads to any length" {
  let input = pattern(4096)
  let long = @blake3.blake3(input[:], len=131)
  assert_eq(hex(@blake3.hash(input[:])), hex(long[0:32]))
  assert_eq(hex(@blake3.blake3(input[:], len=64)), hex(long[0:64]))
  assert_eq(hex(@blake3.blake3(input[:], len=1)), hex(long[0:1]))
  // Reading twice from one hasher answers the same bytes.
  let h = @blake3.Hasher::new()
  h.write(input[:])
  assert_eq(hex(h.read(32)), hex(long[0:32]))
  assert_eq(hex(h.read(32)), hex(long[0:32]))
}

///|
/// The tree is built as the message arrives, so chunking the input differently
/// must not change the answer — this is the property the whole design rests on.
test "BLAKE3 does not care how the message is split" {
  let whole = pattern(3000)
  let want = hex(@blake3.hash(whole[:]))
  let h = @blake3.Hasher::new()
  for i in 0..<3000 {
    h.write(whole[i:i + 1])
  }
  assert_eq(hex(h.finish()), want)
  let g = @blake3.Hasher::new()
  g.write(whole[0:1023])
  g.write(whole[1023:1024])
  g.write(whole[1024:1025])
  g.write(whole[1025:3000])
  assert_eq(hex(g.finish()), want)
}

///|
/// A key is 32 bytes and nothing else; a wrong length is refused rather than
/// quietly hashed.
test "BLAKE3 refuses a key of the wrong length" {
  let short : Bytes = b"too short"
  try @blake3.keyed_hash(short[:], b"abc"[:]) |> ignore catch {
    e => assert_eq(e, @spec.Size(want=32, got=9))
  } noraise {
    _ => fail("a nine-byte key was accepted")
  }
  try @blake3.Hasher::keyed(short[:]) |> ignore catch {
    e => assert_eq(e, @spec.Size(want=32, got=9))
  } noraise {
    _ => fail("a nine-byte key built a hasher")
  }
}

///|
/// The hasher satisfies the trait, and a reset keeps its mode.
test "BLAKE3 reports its sizes and resets in place" {
  let h = @blake3.Hasher::new()
  let as_hash : &@spec.Hash = h
  assert_eq(as_hash.size(), 32)
  assert_eq(as_hash.block(), 64)
  let keyed = @blake3.Hasher::keyed(@moonbase.ascii(vector_key))
  keyed.write(b"abc"[:])
  let first = keyed.finish()
  keyed.reset()
  keyed.write(b"abc"[:])
  assert_eq(hex(keyed.finish()), hex(first))
}
