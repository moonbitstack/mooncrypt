// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One case: the width, the seed, the message in hex, and the digest.
struct Case {
  width : Int32
  seed : UInt64
  data : String
  expected : UInt64
}

///|
/// Every row here was produced by `scripts/gen_xxhash_vectors.py`, which writes
/// its own XXH32 and XXH64 from the specification and then refuses to emit
/// anything unless all of them agree with the `xxhash` C extension.
///
/// The lengths are the point: XXH32 switches from the short path to the four-lane
/// path at 16 bytes and XXH64 at 32, so there is a case just below and just above
/// each threshold, and one that is several stripes long.
let cases : Array[Case] = [
  { width: 32, seed: 0x00000000UL, data: "", expected: 0x02CC5D05UL, },
  { width: 32, seed: 0x00000000UL, data: "61", expected: 0x550D7456UL, },
  { width: 32, seed: 0x00000000UL, data: "616263", expected: 0x32D153FFUL, },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "6162636465666768696a6b6c6d6e6f",
    expected: 0xB918A375UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "313233343536373839",
    expected: 0x937BAD67UL,
  },
  { width: 32, seed: 0x00000000UL, data: "00", expected: 0xCF65B03EUL, },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f",
    expected: 0xB72837F4UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f10",
    expected: 0x7C77ADC2UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    expected: 0x830741C1UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    expected: 0xF1E6A545UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "6d65737361676520646967657374",
    expected: 0x7C948494UL,
  },
  { width: 32, seed: 0x00000000UL, data: "666f6f", expected: 0xE20F0DD9UL, },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "666f6f626172",
    expected: 0xEDA34AAFUL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "6d6f6f6e6372797074",
    expected: 0xC6610656UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    expected: 0x2B0A3D64UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0xE85EA4DEUL,
  },
  { width: 64, seed: 0x00000000UL, data: "", expected: 0xEF46DB3751D8E999UL, },
  { width: 64, seed: 0x00000000UL, data: "61", expected: 0xD24EC4F1A98C6E5BUL, },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "616263",
    expected: 0x44BC2CF5AD770999UL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "6162636465666768696a6b6c6d6e6f",
    expected: 0x2E1218A2B1375068UL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "313233343536373839",
    expected: 0x8CB841DB40E6AE83UL,
  },
  { width: 64, seed: 0x00000000UL, data: "00", expected: 0xE934A84ADB052768UL, },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f",
    expected: 0x44B6EF2FB84169F7UL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f10",
    expected: 0x5603E60C527599B6UL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    expected: 0xCBF59C5116FF32B4UL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    expected: 0x0C535D1ACAFB8EADUL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "6d65737361676520646967657374",
    expected: 0x066ED728FCEEB3BEUL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "666f6f",
    expected: 0x33BF00A859C4BA3FUL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "666f6f626172",
    expected: 0xA2AA05ED9085AAF9UL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "6d6f6f6e6372797074",
    expected: 0x860BFFB727E727B1UL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    expected: 0x2E54FAE2959DBB84UL,
  },
  {
    width: 64,
    seed: 0x00000000UL,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0x0B242D361FDA71BCUL,
  },
  { width: 32, seed: 0x00000001UL, data: "", expected: 0x0B2CB792UL, },
  { width: 64, seed: 0x00000001UL, data: "", expected: 0xD5AFBA1336A3BE4BUL, },
  { width: 32, seed: 0x00000001UL, data: "61", expected: 0xF514706FUL, },
  { width: 64, seed: 0x00000001UL, data: "61", expected: 0xDEC2BC81C3CD46C6UL, },
  { width: 32, seed: 0x00000001UL, data: "616263", expected: 0xAA3DA8FFUL, },
  {
    width: 64,
    seed: 0x00000001UL,
    data: "616263",
    expected: 0xBEA9CA8199328908UL,
  },
  {
    width: 32,
    seed: 0x00000001UL,
    data: "6162636465666768696a6b6c6d6e6f",
    expected: 0xD34CE54AUL,
  },
  {
    width: 64,
    seed: 0x00000001UL,
    data: "6162636465666768696a6b6c6d6e6f",
    expected: 0x6847BBCBF5DCE993UL,
  },
  {
    width: 32,
    seed: 0x00000001UL,
    data: "313233343536373839",
    expected: 0xF261918CUL,
  },
  {
    width: 64,
    seed: 0x00000001UL,
    data: "313233343536373839",
    expected: 0x1A4CC2C9E8079790UL,
  },
  { width: 32, seed: 0x00000001UL, data: "00", expected: 0x02DB596BUL, },
  { width: 64, seed: 0x00000001UL, data: "00", expected: 0x771917C7F6EE2451UL, },
  { width: 32, seed: 0x9E3779B1UL, data: "", expected: 0x36B78AE7UL, },
  { width: 64, seed: 0x9E3779B1UL, data: "", expected: 0xAC75FDA2929B17EFUL, },
  { width: 32, seed: 0x9E3779B1UL, data: "61", expected: 0x9E1633E4UL, },
  { width: 64, seed: 0x9E3779B1UL, data: "61", expected: 0x393DA8B78992279BUL, },
  { width: 32, seed: 0x9E3779B1UL, data: "616263", expected: 0xA1AE7709UL, },
  {
    width: 64,
    seed: 0x9E3779B1UL,
    data: "616263",
    expected: 0x1318DF30094A85FDUL,
  },
  {
    width: 32,
    seed: 0x9E3779B1UL,
    data: "6162636465666768696a6b6c6d6e6f",
    expected: 0xC8637718UL,
  },
  {
    width: 64,
    seed: 0x9E3779B1UL,
    data: "6162636465666768696a6b6c6d6e6f",
    expected: 0x7055F56019DE2238UL,
  },
  {
    width: 32,
    seed: 0x9E3779B1UL,
    data: "313233343536373839",
    expected: 0x9355E7ECUL,
  },
  {
    width: 64,
    seed: 0x9E3779B1UL,
    data: "313233343536373839",
    expected: 0x6BC432BF21C3E5E2UL,
  },
  { width: 32, seed: 0x9E3779B1UL, data: "00", expected: 0xB4545AA4UL, },
  { width: 64, seed: 0x9E3779B1UL, data: "00", expected: 0x5014607643A9B4C3UL, },
  { width: 32, seed: 0xFFFFFFFFUL, data: "", expected: 0x9061DA9DUL, },
  { width: 64, seed: 0xFFFFFFFFUL, data: "", expected: 0x39554C1E3DB747E7UL, },
  { width: 32, seed: 0xFFFFFFFFUL, data: "61", expected: 0xCD42752DUL, },
  { width: 64, seed: 0xFFFFFFFFUL, data: "61", expected: 0x9B69AE9432026B4BUL, },
  { width: 32, seed: 0xFFFFFFFFUL, data: "616263", expected: 0xB22B1420UL, },
  {
    width: 64,
    seed: 0xFFFFFFFFUL,
    data: "616263",
    expected: 0x453354140EE73869UL,
  },
  {
    width: 32,
    seed: 0xFFFFFFFFUL,
    data: "6162636465666768696a6b6c6d6e6f",
    expected: 0x023E0D43UL,
  },
  {
    width: 64,
    seed: 0xFFFFFFFFUL,
    data: "6162636465666768696a6b6c6d6e6f",
    expected: 0xC97C32AA95D0663FUL,
  },
  {
    width: 32,
    seed: 0xFFFFFFFFUL,
    data: "313233343536373839",
    expected: 0x500C2211UL,
  },
  {
    width: 64,
    seed: 0xFFFFFFFFUL,
    data: "313233343536373839",
    expected: 0x9397987969776B46UL,
  },
  { width: 32, seed: 0xFFFFFFFFUL, data: "00", expected: 0x36705D21UL, },
  { width: 64, seed: 0xFFFFFFFFUL, data: "00", expected: 0xD428894A7EE9F0E4UL, },
]

///|
fn kind_of(width : Int32) -> @xxhash.Kind {
  if width == 32 {
    @xxhash.Xxh32
  } else {
    @xxhash.Xxh64
  }
}

///|
/// Every case, one-shot, and again through a state fed a byte at a time — the
/// buffering only shows up as a bug when the stripe boundary falls in the middle
/// of a write, which feeding one byte at a time guarantees.
test "xxhash matches the reference" {
  for case in cases {
    let data = raw(case.data)
    let kind = kind_of(case.width)
    assert_eq(@xxhash.xxhash(data[:], kind~, seed=case.seed), case.expected)
    let state = @xxhash.Xxh::new(kind~, seed=case.seed)
    for i in 0..<data.length() {
      state.update(data[i:i + 1])
    }
    assert_eq(state.value(), case.expected)
  }
}

///|
/// The same message split at every possible point must give the same digest, so
/// no split point can be the one that breaks the buffer.
test "xxhash does not depend on how the input is split" {
  let data = raw(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
  )
  let want32 = @xxhash.xxhash(data[:], kind=@xxhash.Xxh32)
  let want64 = @xxhash.xxhash(data[:], kind=@xxhash.Xxh64)
  for cut in 0..<=data.length() {
    let a = @xxhash.Xxh::new(kind=@xxhash.Xxh32)
    a.update(data[0:cut])
    a.update(data[cut:])
    assert_eq(a.value(), want32)
    let b = @xxhash.Xxh::new(kind=@xxhash.Xxh64)
    b.update(data[0:cut])
    b.update(data[cut:])
    assert_eq(b.value(), want64)
  }
}

///|
/// The seed is not decoration: it has to change the digest of every message,
/// including the empty one, where there is no message to mix it with.
test "the seed changes the digest" {
  let data = raw("666f6f")
  for kind in [@xxhash.Xxh32, @xxhash.Xxh64] {
    let plain = @xxhash.xxhash(data[:], kind~)
    let seeded = @xxhash.xxhash(data[:], kind~, seed=1)
    assert_true(plain != seeded)
    assert_true(
      @xxhash.xxhash(b""[:], kind~) != @xxhash.xxhash(b""[:], kind~, seed=1),
    )
  }
}

///|
/// The two widths are separate algorithms, not one truncated: XXH32 of a message
/// is not the low half of its XXH64.
test "the two widths disagree" {
  let data = raw("54686520717569636b2062726f776e20666f78")
  let narrow = @xxhash.xxhash(data[:], kind=@xxhash.Xxh32)
  let wide = @xxhash.xxhash(data[:], kind=@xxhash.Xxh64)
  assert_true(narrow != (wide & 0xFFFF_FFFFUL))
}

///|
/// The [`@spec.Hash`] form is the digest big-endian in four or eight bytes, and
/// the reported size and block follow the width.
test "xxhash through the Hash trait" {
  let state = @xxhash.Xxh::new(kind=@xxhash.Xxh32)
  assert_eq(@spec.Hash::size(state), 4)
  assert_eq(@spec.Hash::block(state), 16)
  @spec.Hash::write(state, b"abc"[:])
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "32d153ff")
  let wide = @xxhash.Xxh::new()
  assert_eq(@spec.Hash::size(wide), 8)
  assert_eq(@spec.Hash::block(wide), 32)
  @spec.Hash::write(wide, b"abc"[:])
  assert_eq(@base16.encode(@spec.Hash::finish(wide)[:]), "44bc2cf5ad770999")
  // Reset keeps the seed and the kind, and yields the seeded empty digest.
  let seeded = @xxhash.Xxh::new(kind=@xxhash.Xxh32, seed=1)
  @spec.Hash::write(seeded, b"abc"[:])
  @spec.Hash::reset(seeded)
  assert_eq(@spec.Hash::size(seeded), 4)
  assert_eq(seeded.value(), 0x0B2CB792UL)
  assert_eq(@spec.Hash::block(seeded), 16)
}
