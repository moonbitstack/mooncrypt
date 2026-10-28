// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One case: the message in hex and its checksum.
struct Case {
  data : String
  expected : UInt32
}

///|
/// From `scripts/gen_checksum_vectors.py`, which compares every one of these
/// against `zlib.adler32`.
///
/// The messages are chosen for what they catch: empty (the initial value), one
/// byte, a mix of `00` and `ff` (the two ends of the addition), and a long
/// message — which is the only one that reaches the 5552-byte batch and would
/// catch an accumulation that overflows instead of reducing.
let cases : Array[Case] = [
  { data: "", expected: 0x00000001, },
  { data: "61", expected: 0x00620062, },
  { data: "616263", expected: 0x024D0127, },
  { data: "666f6f", expected: 0x02820145, },
  { data: "666f6f626172", expected: 0x08AB027A, },
  { data: "313233343536373839", expected: 0x091E01DE, },
  { data: "6d6f6f6e6372797074", expected: 0x136903EC, },
  { data: "00", expected: 0x00010001, },
  { data: "ffffffff", expected: 0x09FA03FD, },
  { data: "00ff00ff00ff00ff", expected: 0x0FF803FD, },
  {
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0x5BDC0FDA,
  },
]

///|
/// `"Wikipedia"` is the example RFC 1950 and every article uses, and it is the
/// one published value this has.
test "adler32 matches the published example" {
  assert_eq(@adler32.adler32(b"Wikipedia"[:]), 0x11E60398)
  assert_eq(@adler32.adler32(raw("")[:]), 1)
}

///|
/// Every case, through the one-shot form and through a state fed a few bytes at
/// a time.
test "adler32 matches zlib" {
  for case in cases {
    let data = raw(case.data)
    assert_eq(@adler32.adler32(data[:]), case.expected)
    let state = @adler32.Adler32::new()
    let mut at = 0
    while at < data.length() {
      let take = if data.length() - at < 7 { data.length() - at } else { 7 }
      state.update(data[at:at + take])
      at = at + take
    }
    assert_eq(state.value(), case.expected)
  }
}

///|
/// A message longer than one batch, which is where an accumulator that does not
/// reduce would overflow. Twenty thousand bytes is four batches of 5552.
test "adler32 across batch boundaries" {
  let bytes : FixedArray[Byte] = FixedArray::make(20000, b'\x00')
  for i in 0..<20000 {
    bytes[i] = ((i * 31 + 7) % 256).to_byte()
  }
  let data = Bytes::from_array(bytes)
  let want = @adler32.adler32(data[:])
  // The same bytes fed in batches of exactly 5552 must give the same answer, and
  // so must bytes fed one at a time.
  let exact = @adler32.Adler32::new()
  let mut at = 0
  while at < data.length() {
    let take = if data.length() - at < 5552 { data.length() - at } else { 5552 }
    exact.update(data[at:at + take])
    at = at + take
  }
  assert_eq(exact.value(), want)
  let slow = @adler32.Adler32::new()
  for i in 0..<data.length() {
    slow.update(data[i:i + 1])
  }
  assert_eq(slow.value(), want)
  // And a batch boundary one byte either side must not change it either.
  let odd = @adler32.Adler32::new()
  odd.update(data[0:5551])
  odd.update(data[5551:])
  assert_eq(odd.value(), want)
}

///|
/// The [`@spec.Hash`] form is four bytes big-endian, the order zlib writes it
/// in, and the state can be reset and reused.
test "adler32 through the Hash trait" {
  let data = b"Wikipedia"
  let state = @adler32.Adler32::new()
  @spec.Hash::write(state, data[:])
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "11e60398")
  assert_eq(@spec.Hash::size(state), 4)
  assert_eq(@spec.Hash::block(state), 1)
  assert_eq(@adler32.size, 4)
  @spec.Hash::reset(state)
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "00000001")
  @spec.Hash::write(state, data[:])
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "11e60398")
}
