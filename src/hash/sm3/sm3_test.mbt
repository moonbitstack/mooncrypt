// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
fn ascii(s : String) -> Bytes {
  @moonbase.ascii(s)
}

///|
/// GB/T 32905's own worked examples: "abc", and the sixty-four-byte message
/// that fills a block exactly and so forces the padding into a second one.
test "SM3 matches the GB/T 32905 examples" {
  assert_eq(
    hex(@sm3.hash(ascii("abc")[:])),
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
  let abcd = Bytes::from_array(
    Array::make(64, 0).mapi(fn(i, _) { (97 + i % 4).to_byte() }),
  )
  assert_eq(
    hex(@sm3.hash(abcd[:])),
    "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
  )
  assert_eq(
    hex(@sm3.hash(b""[:])),
    "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
  )
}

///|
/// A message in pieces is the same message, and reading twice answers the same
/// digest while the hasher can still be written to.
test "SM3 streams and reads twice" {
  let whole = @sm3.hash(ascii("the quick brown fox")[:])
  let h = @sm3.Hasher::new()
  h.write(b"the quick "[:])
  h.write(b"brown fox"[:])
  assert_eq(hex(h.finish()), hex(whole))
  assert_eq(hex(h.finish()), hex(whole))
  h.write(b" jumps"[:])
  assert_eq(
    hex(h.finish()),
    hex(@sm3.hash(ascii("the quick brown fox jumps")[:])),
  )
  h.reset()
  assert_eq(hex(h.finish()), hex(@sm3.hash(b""[:])))
}

///|
test "SM3 reports its sizes and satisfies the Hash contract" {
  let h = @sm3.Hasher::new()
  let as_hash : &@spec.Hash = h
  assert_eq(as_hash.size(), 32)
  assert_eq(as_hash.block(), 64)
  assert_eq(@sm3.size, 32)
  assert_eq(@sm3.block, 64)
}
