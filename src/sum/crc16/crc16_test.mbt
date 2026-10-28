// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One case: the variant, the message in hex, and the checksum.
struct Case {
  kind : @crc16.Kind
  data : String
  expected : UInt32
}

///|
/// Six variants over nine messages, from `scripts/gen_crc_vectors.py`, which
/// asserts each variant's published check value before emitting anything.
///
/// The messages are chosen for what they catch: the empty string tells the
/// initial value apart from zero, a single `00` tells a reflected machine from a
/// straight one, and a single `ff` catches a table whose high byte is dropped.
let cases : Array[Case] = [
  { kind: @crc16.Arc, data: "", expected: 0x0000, },
  { kind: @crc16.Arc, data: "313233343536373839", expected: 0xBB3D, },
  { kind: @crc16.Arc, data: "61", expected: 0xE8C1, },
  { kind: @crc16.Arc, data: "616263", expected: 0x9738, },
  {
    kind: @crc16.Arc,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0xFCDF,
  },
  { kind: @crc16.Arc, data: "6d6f6f6e6372797074", expected: 0x3C0A, },
  { kind: @crc16.Arc, data: "deadbeef", expected: 0xE59B, },
  { kind: @crc16.Arc, data: "00", expected: 0x0000, },
  { kind: @crc16.Arc, data: "ff", expected: 0x4040, },
  { kind: @crc16.CcittFalse, data: "", expected: 0xFFFF, },
  { kind: @crc16.CcittFalse, data: "313233343536373839", expected: 0x29B1, },
  { kind: @crc16.CcittFalse, data: "61", expected: 0x9D77, },
  { kind: @crc16.CcittFalse, data: "616263", expected: 0x514A, },
  {
    kind: @crc16.CcittFalse,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0x8FDD,
  },
  { kind: @crc16.CcittFalse, data: "6d6f6f6e6372797074", expected: 0x2496, },
  { kind: @crc16.CcittFalse, data: "deadbeef", expected: 0x4097, },
  { kind: @crc16.CcittFalse, data: "00", expected: 0xE1F0, },
  { kind: @crc16.CcittFalse, data: "ff", expected: 0xFF00, },
  { kind: @crc16.Xmodem, data: "", expected: 0x0000, },
  { kind: @crc16.Xmodem, data: "313233343536373839", expected: 0x31C3, },
  { kind: @crc16.Xmodem, data: "61", expected: 0x7C87, },
  { kind: @crc16.Xmodem, data: "616263", expected: 0x9DD6, },
  {
    kind: @crc16.Xmodem,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0xF0C8,
  },
  { kind: @crc16.Xmodem, data: "6d6f6f6e6372797074", expected: 0x3CE4, },
  { kind: @crc16.Xmodem, data: "deadbeef", expected: 0xC457, },
  { kind: @crc16.Xmodem, data: "00", expected: 0x0000, },
  { kind: @crc16.Xmodem, data: "ff", expected: 0x1EF0, },
  { kind: @crc16.Kermit, data: "", expected: 0x0000, },
  { kind: @crc16.Kermit, data: "313233343536373839", expected: 0x2189, },
  { kind: @crc16.Kermit, data: "61", expected: 0x728F, },
  { kind: @crc16.Kermit, data: "616263", expected: 0x58E9, },
  {
    kind: @crc16.Kermit,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0xC459,
  },
  { kind: @crc16.Kermit, data: "6d6f6f6e6372797074", expected: 0x7BB4, },
  { kind: @crc16.Kermit, data: "deadbeef", expected: 0x1915, },
  { kind: @crc16.Kermit, data: "00", expected: 0x0000, },
  { kind: @crc16.Kermit, data: "ff", expected: 0x0F78, },
  { kind: @crc16.X25, data: "", expected: 0x0000, },
  { kind: @crc16.X25, data: "313233343536373839", expected: 0x906E, },
  { kind: @crc16.X25, data: "61", expected: 0x82F7, },
  { kind: @crc16.X25, data: "616263", expected: 0x9E25, },
  {
    kind: @crc16.X25,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0x9358,
  },
  { kind: @crc16.X25, data: "6d6f6f6e6372797074", expected: 0xCA53, },
  { kind: @crc16.X25, data: "deadbeef", expected: 0xE5CB, },
  { kind: @crc16.X25, data: "00", expected: 0xF078, },
  { kind: @crc16.X25, data: "ff", expected: 0xFF00, },
  { kind: @crc16.Modbus, data: "", expected: 0xFFFF, },
  { kind: @crc16.Modbus, data: "313233343536373839", expected: 0x4B37, },
  { kind: @crc16.Modbus, data: "61", expected: 0xA87E, },
  { kind: @crc16.Modbus, data: "616263", expected: 0x5749, },
  {
    kind: @crc16.Modbus,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0xA89C,
  },
  { kind: @crc16.Modbus, data: "6d6f6f6e6372797074", expected: 0xCC00, },
  { kind: @crc16.Modbus, data: "deadbeef", expected: 0xC19B, },
  { kind: @crc16.Modbus, data: "00", expected: 0x40BF, },
  { kind: @crc16.Modbus, data: "ff", expected: 0x00FF, },
]

///|
/// The published check value of each variant, asserted separately so that a
/// failure names the variant rather than pointing at a row of a table.
test "crc16 matches the published check values" {
  let check = raw("313233343536373839")
  assert_eq(@crc16.crc16(check[:], kind=@crc16.Arc), 0xBB3D)
  assert_eq(@crc16.crc16(check[:], kind=@crc16.CcittFalse), 0x29B1)
  assert_eq(@crc16.crc16(check[:], kind=@crc16.Xmodem), 0x31C3)
  assert_eq(@crc16.crc16(check[:], kind=@crc16.Kermit), 0x2189)
  assert_eq(@crc16.crc16(check[:], kind=@crc16.X25), 0x906E)
  assert_eq(@crc16.crc16(check[:], kind=@crc16.Modbus), 0x4B37)
}

///|
/// Every case, through the one-shot form and through a state fed one byte at a
/// time.
test "crc16 matches the reference" {
  for case in cases {
    let data = raw(case.data)
    assert_eq(@crc16.crc16(data[:], kind=case.kind), case.expected)
    let state = @crc16.Crc16::new(kind=case.kind)
    for i in 0..<data.length() {
      state.update(data[i:i + 1])
    }
    assert_eq(state.value(), case.expected)
  }
}

///|
/// The [`@spec.Hash`] form gives the number big-endian in two bytes, and the
/// state can be reset and reused.
test "crc16 through the Hash trait" {
  let data = raw("313233343536373839")
  let state = @crc16.Crc16::new()
  @spec.Hash::write(state, data[:])
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "bb3d")
  assert_eq(@spec.Hash::size(state), 2)
  assert_eq(@spec.Hash::block(state), 1)
  @spec.Hash::reset(state)
  assert_eq(@spec.Hash::finish(state)[:], raw("0000")[:])
  @spec.Hash::write(state, data[:])
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "bb3d")
  assert_eq(@base16.encode(@spec.digest(state, data[:])[:]), "bb3d")
}

///|
/// The reflected and straight machines really are different, and the variants
/// that differ only in their initial value differ even on an empty message.
test "the variants are distinguishable" {
  let empty = raw("")
  assert_eq(@crc16.crc16(empty[:], kind=@crc16.CcittFalse), 0xFFFF)
  assert_eq(@crc16.crc16(empty[:], kind=@crc16.Xmodem), 0x0000)
  assert_eq(@crc16.crc16(empty[:], kind=@crc16.Modbus), 0xFFFF)
  assert_eq(@crc16.crc16(empty[:], kind=@crc16.X25), 0x0000)
  // Kermit and XMODEM are the same polynomial both ways round; they must not
  // agree.
  let data = raw("313233343536373839")
  assert_true(
    @crc16.crc16(data[:], kind=@crc16.Kermit) !=
    @crc16.crc16(data[:], kind=@crc16.Xmodem),
  )
}
