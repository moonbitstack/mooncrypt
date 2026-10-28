// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One case: the variant, the message in hex, and the digest.
struct Case {
  kind : @fnv.Kind
  data : String
  expected : UInt64
}

///|
/// Four variants over a set of messages, from `scripts/gen_checksum_vectors.py`,
/// which asserts the published FNV vectors before emitting anything.
let cases : Array[Case] = [
  { kind: @fnv.Fnv1_32, data: "", expected: 0x811C9DC5UL, },
  { kind: @fnv.Fnv1_32, data: "61", expected: 0x050C5D7EUL, },
  { kind: @fnv.Fnv1_32, data: "616263", expected: 0x439C2F4BUL, },
  { kind: @fnv.Fnv1_32, data: "666f6f", expected: 0x408F5E13UL, },
  { kind: @fnv.Fnv1_32, data: "666f6f626172", expected: 0x31F0B262UL, },
  { kind: @fnv.Fnv1_32, data: "313233343536373839", expected: 0x24148816UL, },
  { kind: @fnv.Fnv1_32, data: "6d6f6f6e6372797074", expected: 0xC833A8EAUL, },
  { kind: @fnv.Fnv1_32, data: "00", expected: 0x050C5D1FUL, },
  { kind: @fnv.Fnv1_32, data: "ffffffff", expected: 0xF5E1E189UL, },
  { kind: @fnv.Fnv1_32, data: "00ff00ff00ff00ff", expected: 0xA21904B5UL, },
  {
    kind: @fnv.Fnv1_32,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0xE9C86C6EUL,
  },
  { kind: @fnv.Fnv1a_32, data: "", expected: 0x811C9DC5UL, },
  { kind: @fnv.Fnv1a_32, data: "61", expected: 0xE40C292CUL, },
  { kind: @fnv.Fnv1a_32, data: "616263", expected: 0x1A47E90BUL, },
  { kind: @fnv.Fnv1a_32, data: "666f6f", expected: 0xA9F37ED7UL, },
  { kind: @fnv.Fnv1a_32, data: "666f6f626172", expected: 0xBF9CF968UL, },
  { kind: @fnv.Fnv1a_32, data: "313233343536373839", expected: 0xBB86B11CUL, },
  { kind: @fnv.Fnv1a_32, data: "6d6f6f6e6372797074", expected: 0xC58463A4UL, },
  { kind: @fnv.Fnv1a_32, data: "00", expected: 0x050C5D1FUL, },
  { kind: @fnv.Fnv1a_32, data: "ffffffff", expected: 0xE3160FB1UL, },
  { kind: @fnv.Fnv1a_32, data: "00ff00ff00ff00ff", expected: 0x75179855UL, },
  {
    kind: @fnv.Fnv1a_32,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0x048FFF90UL,
  },
  { kind: @fnv.Fnv1_64, data: "", expected: 0xCBF29CE484222325UL, },
  { kind: @fnv.Fnv1_64, data: "61", expected: 0xAF63BD4C8601B7BEUL, },
  { kind: @fnv.Fnv1_64, data: "616263", expected: 0xD8DCCA186BAFADCBUL, },
  { kind: @fnv.Fnv1_64, data: "666f6f", expected: 0xD8CBC7186BA13533UL, },
  { kind: @fnv.Fnv1_64, data: "666f6f626172", expected: 0x340D8765A4DDA9C2UL, },
  {
    kind: @fnv.Fnv1_64,
    data: "313233343536373839",
    expected: 0xA72FFC362BF916D6UL,
  },
  {
    kind: @fnv.Fnv1_64,
    data: "6d6f6f6e6372797074",
    expected: 0x86E26F6585A3B54AUL,
  },
  { kind: @fnv.Fnv1_64, data: "00", expected: 0xAF63BD4C8601B7DFUL, },
  { kind: @fnv.Fnv1_64, data: "ffffffff", expected: 0xD789707BF56E1129UL, },
  {
    kind: @fnv.Fnv1_64,
    data: "00ff00ff00ff00ff",
    expected: 0xD73AFC364212FE95UL,
  },
  {
    kind: @fnv.Fnv1_64,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0xA8B2F3117DE37ACEUL,
  },
  { kind: @fnv.Fnv1a_64, data: "", expected: 0xCBF29CE484222325UL, },
  { kind: @fnv.Fnv1a_64, data: "61", expected: 0xAF63DC4C8601EC8CUL, },
  { kind: @fnv.Fnv1a_64, data: "616263", expected: 0xE71FA2190541574BUL, },
  { kind: @fnv.Fnv1a_64, data: "666f6f", expected: 0xDCB27518FED9D577UL, },
  { kind: @fnv.Fnv1a_64, data: "666f6f626172", expected: 0x85944171F73967E8UL, },
  {
    kind: @fnv.Fnv1a_64,
    data: "313233343536373839",
    expected: 0x06D5573923C6CDFCUL,
  },
  {
    kind: @fnv.Fnv1a_64,
    data: "6d6f6f6e6372797074",
    expected: 0x068C80DFE4D1BAE4UL,
  },
  { kind: @fnv.Fnv1a_64, data: "00", expected: 0xAF63BD4C8601B7DFUL, },
  { kind: @fnv.Fnv1a_64, data: "ffffffff", expected: 0x994F76653E2A3951UL, },
  {
    kind: @fnv.Fnv1a_64,
    data: "00ff00ff00ff00ff",
    expected: 0x253CE2B078B8BF35UL,
  },
  {
    kind: @fnv.Fnv1a_64,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0xF3F9B7F5E7E47110UL,
  },
]

///|
/// The published vectors, asserted separately so that a failure names the
/// variant: the empty string gives the offset basis and one byte gives the
/// prime, so together they pin both constants.
test "fnv matches the published vectors" {
  assert_eq(@fnv.fnv(raw("")[:], kind=@fnv.Fnv1_32), 0x811C9DC5UL)
  assert_eq(@fnv.fnv(raw("61")[:], kind=@fnv.Fnv1_32), 0x050C5D7EUL)
  assert_eq(@fnv.fnv(raw("")[:], kind=@fnv.Fnv1a_32), 0x811C9DC5UL)
  assert_eq(@fnv.fnv(raw("61")[:], kind=@fnv.Fnv1a_32), 0xE40C292CUL)
  assert_eq(@fnv.fnv(raw("666f6f626172")[:], kind=@fnv.Fnv1a_32), 0xBF9CF968UL)
  assert_eq(@fnv.fnv(raw("")[:], kind=@fnv.Fnv1_64), 0xCBF29CE484222325UL)
  assert_eq(@fnv.fnv(raw("61")[:], kind=@fnv.Fnv1_64), 0xAF63BD4C8601B7BEUL)
  assert_eq(@fnv.fnv(raw("")[:], kind=@fnv.Fnv1a_64), 0xCBF29CE484222325UL)
  assert_eq(@fnv.fnv(raw("61")[:], kind=@fnv.Fnv1a_64), 0xAF63DC4C8601EC8CUL)
}

///|
/// Every case, through the one-shot form and a state fed one byte at a time.
test "fnv matches the reference" {
  for case in cases {
    let data = raw(case.data)
    assert_eq(@fnv.fnv(data[:], kind=case.kind), case.expected)
    let state = @fnv.Fnv::new(kind=case.kind)
    for i in 0..<data.length() {
      state.update(data[i:i + 1])
    }
    assert_eq(state.value(), case.expected)
  }
}

///|
/// The four variants really are four different functions, which is the whole
/// reason the kind is a parameter rather than a constant.
test "the variants are distinguishable" {
  let data = raw("666f6f")
  let all = [
    @fnv.fnv(data[:], kind=@fnv.Fnv1_32),
    @fnv.fnv(data[:], kind=@fnv.Fnv1a_32),
    @fnv.fnv(data[:], kind=@fnv.Fnv1_64),
    @fnv.fnv(data[:], kind=@fnv.Fnv1a_64),
  ]
  for i in 0..<4 {
    for j in (i + 1)..<4 {
      assert_true(all[i] != all[j])
    }
  }
}

///|
/// The [`@spec.Hash`] form is the digest big-endian in four or eight bytes, and
/// the 32-bit kinds really are truncated to 32 bits rather than carrying the
/// high half of the multiply.
test "fnv through the Hash trait" {
  let data = raw("61")
  let state = @fnv.Fnv::new(kind=@fnv.Fnv1a_32)
  @spec.Hash::write(state, data[:])
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "e40c292c")
  assert_eq(@spec.Hash::size(state), 4)
  let wide = @fnv.Fnv::new()
  assert_eq(@spec.Hash::size(wide), 8)
  @spec.Hash::write(wide, data[:])
  assert_eq(@base16.encode(@spec.Hash::finish(wide)[:]), "af63dc4c8601ec8c")
  @spec.Hash::reset(wide)
  assert_eq(@base16.encode(@spec.Hash::finish(wide)[:]), "cbf29ce484222325")
}
