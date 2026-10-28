// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One case: the width, the seed, the message in hex, and the two halves of the
/// digest.
struct Case {
  width : Int32
  seed : UInt64
  data : String
  low : UInt64
  high : UInt64
}

///|
/// From `scripts/gen_murmur3_vectors.py`, which writes both variants out from the
/// algorithm and then refuses to emit anything unless all of them agree with
/// `mmh3`.
///
/// The lengths bracket the 4-byte and 16-byte block boundaries, and the cases
/// with 9 to 15 trailing bytes are the ones that catch the rule that a tail of
/// exactly eight bytes must not be mixed into the second lane.
let cases : Array[Case] = [
  { width: 32, seed: 0x00000000UL, data: "", low: 0x00000000UL, high: 0UL, },
  { width: 32, seed: 0x00000000UL, data: "61", low: 0x3C2569B2UL, high: 0UL, },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "616263",
    low: 0xB3DD93FAUL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "666f6f",
    low: 0xF6A5C420UL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "666f6f626172",
    low: 0xA4C4D4BDUL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "313233343536373839",
    low: 0xB4FEF382UL,
    high: 0UL,
  },
  { width: 32, seed: 0x00000000UL, data: "00", low: 0x514E28B7UL, high: 0UL, },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "00010203",
    low: 0xF4C0EC39UL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "000102030405060708",
    low: 0xE7E27A50UL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f",
    low: 0x191573DDUL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f10",
    low: 0xCBE58DC6UL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f101112131415161718",
    low: 0xF462D717UL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "6d6f6f6e6372797074",
    low: 0x39840D4CUL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "6d65737361676520646967657374",
    low: 0x638F4169UL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    low: 0xE85EA13EUL,
    high: 0UL,
  },
  {
    width: 32,
    seed: 0x00000000UL,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    low: 0x2E4FF723UL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "",
    low: 0x0000000000000000UL,
    high: 0x0000000000000000UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "61",
    low: 0x85555565F6597889UL,
    high: 0xE6B53A48510E895AUL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "616263",
    low: 0xB4963F3F3FAD7867UL,
    high: 0x3BA2744126CA2D52UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "666f6f",
    low: 0xE271865701F54561UL,
    high: 0x7EAF87E42BBA7D87UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "666f6f626172",
    low: 0xBDD2AE7116C85A45UL,
    high: 0x74A255E0BAF8D6AFUL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "313233343536373839",
    low: 0x3C84645EDB66CCA4UL,
    high: 0x99F8FAC73A1EA105UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "00",
    low: 0x4610ABE56EFF5CB5UL,
    high: 0x51622DAA78F83583UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "00010203",
    low: 0xE1C594AE0DDFAF10UL,
    high: 0xD3D605BD13C2FDE2UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "000102030405060708",
    low: 0xFBB4CB0F6E812D32UL,
    high: 0x78DE751D0200FFB9UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f",
    low: 0x444924B591903F30UL,
    high: 0xAB906456762FE845UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f10",
    low: 0x5C76F40F9FE7C20EUL,
    high: 0xC15F026B9EDAA824UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "000102030405060708090a0b0c0d0e0f101112131415161718",
    low: 0x3BBE7CB52EE982CBUL,
    high: 0xA2D35433BEEF9FFCUL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "6d6f6f6e6372797074",
    low: 0x8AF5EDA4497CBB80UL,
    high: 0x8D886DBC9B55479BUL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "6d65737361676520646967657374",
    low: 0x875D2C2D76147DFCUL,
    high: 0xF622B02A12BC6F39UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    low: 0x2160D8CAD132AC93UL,
    high: 0x36D0284CF2F8A1E4UL,
  },
  {
    width: 128,
    seed: 0x00000000UL,
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    low: 0xE34BBC7BBC071B6CUL,
    high: 0x7A433CA9C49A9347UL,
  },
  { width: 32, seed: 0x00000001UL, data: "", low: 0x514E28B7UL, high: 0UL, },
  {
    width: 128,
    seed: 0x00000001UL,
    data: "",
    low: 0x4610ABE56EFF5CB5UL,
    high: 0x51622DAA78F83583UL,
  },
  { width: 32, seed: 0x00000001UL, data: "61", low: 0x588ADCE8UL, high: 0UL, },
  {
    width: 128,
    seed: 0x00000001UL,
    data: "61",
    low: 0x47EAE1073748CF70UL,
    high: 0x6BE0518AD2ED3728UL,
  },
  {
    width: 32,
    seed: 0x00000001UL,
    data: "616263",
    low: 0xAA75E9FFUL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0x00000001UL,
    data: "616263",
    low: 0x9C88BE4E9A8A61F0UL,
    high: 0xCA12C88BF31B256CUL,
  },
  {
    width: 32,
    seed: 0x00000001UL,
    data: "666f6f",
    low: 0x34BE5F72UL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0x00000001UL,
    data: "666f6f",
    low: 0x71A5CE8C69792053UL,
    high: 0x9D18184EFAC2336BUL,
  },
  {
    width: 32,
    seed: 0x00000001UL,
    data: "666f6f626172",
    low: 0x6C9B7A46UL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0x00000001UL,
    data: "666f6f626172",
    low: 0xC1130408A700AFE0UL,
    high: 0x7B23010FDB6981E5UL,
  },
  {
    width: 32,
    seed: 0x00000001UL,
    data: "313233343536373839",
    low: 0x54D0D6FFUL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0x00000001UL,
    data: "313233343536373839",
    low: 0xF16B761FE114E80BUL,
    high: 0xBE5F6AE246129F16UL,
  },
  { width: 32, seed: 0x9747B28CUL, data: "", low: 0xEBB6C228UL, high: 0UL, },
  {
    width: 128,
    seed: 0x9747B28CUL,
    data: "",
    low: 0x392B208A1DAABBB3UL,
    high: 0x93B0608FE302957AUL,
  },
  { width: 32, seed: 0x9747B28CUL, data: "61", low: 0x7FA09EA6UL, high: 0UL, },
  {
    width: 128,
    seed: 0x9747B28CUL,
    data: "61",
    low: 0x5CE8D8512DB25A1DUL,
    high: 0x9E6DAB0F9208F004UL,
  },
  {
    width: 32,
    seed: 0x9747B28CUL,
    data: "616263",
    low: 0xC84A62DDUL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0x9747B28CUL,
    data: "616263",
    low: 0x3743630DBFC3CEDCUL,
    high: 0xCDE0A23420B504BFUL,
  },
  {
    width: 32,
    seed: 0x9747B28CUL,
    data: "666f6f",
    low: 0x27556701UL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0x9747B28CUL,
    data: "666f6f",
    low: 0x48D9F8A111583971UL,
    high: 0x7CFCEC788BADC67CUL,
  },
  {
    width: 32,
    seed: 0x9747B28CUL,
    data: "666f6f626172",
    low: 0x64A9B34DUL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0x9747B28CUL,
    data: "666f6f626172",
    low: 0x48135F4DFBCFDEDBUL,
    high: 0xDDC120D15EEEB9CEUL,
  },
  {
    width: 32,
    seed: 0x9747B28CUL,
    data: "313233343536373839",
    low: 0x5C0F422CUL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0x9747B28CUL,
    data: "313233343536373839",
    low: 0xC3ACF0E8FA28FF9AUL,
    high: 0xA4B7A84EDFB62174UL,
  },
  { width: 32, seed: 0xFFFFFFFFUL, data: "", low: 0x81F16F39UL, high: 0UL, },
  {
    width: 128,
    seed: 0xFFFFFFFFUL,
    data: "",
    low: 0x6AF1DF4D9D3BC9ECUL,
    high: 0x857421121EE6446BUL,
  },
  { width: 32, seed: 0xFFFFFFFFUL, data: "61", low: 0x2A684527UL, high: 0UL, },
  {
    width: 128,
    seed: 0xFFFFFFFFUL,
    data: "61",
    low: 0xBEF385FAEAD16340UL,
    high: 0xA9363D237B2EE74CUL,
  },
  {
    width: 32,
    seed: 0xFFFFFFFFUL,
    data: "616263",
    low: 0xFC80C2AFUL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0xFFFFFFFFUL,
    data: "616263",
    low: 0x5A2D798580260F18UL,
    high: 0x5BF10E33D36C3789UL,
  },
  {
    width: 32,
    seed: 0xFFFFFFFFUL,
    data: "666f6f",
    low: 0x6DF0E71DUL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0xFFFFFFFFUL,
    data: "666f6f",
    low: 0x8C6E721E20CCAC84UL,
    high: 0x8E56F7E298DAB045UL,
  },
  {
    width: 32,
    seed: 0xFFFFFFFFUL,
    data: "666f6f626172",
    low: 0xFF91CF84UL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0xFFFFFFFFUL,
    data: "666f6f626172",
    low: 0x56D15D5281794394UL,
    high: 0xDE845AEF35ED600BUL,
  },
  {
    width: 32,
    seed: 0xFFFFFFFFUL,
    data: "313233343536373839",
    low: 0x359456E3UL,
    high: 0UL,
  },
  {
    width: 128,
    seed: 0xFFFFFFFFUL,
    data: "313233343536373839",
    low: 0x951EF9821A5EBF84UL,
    high: 0x79BCF0F19323C76DUL,
  },
]

///|
fn kind_of(width : Int32) -> @murmur3.Kind {
  if width == 32 {
    @murmur3.X86_32
  } else {
    @murmur3.X64_128
  }
}

///|
/// Every case, one-shot, and again through a state fed a byte at a time.
test "murmur3 matches the reference" {
  for case in cases {
    let data = raw(case.data)
    let kind = kind_of(case.width)
    assert_eq(
      @murmur3.murmur3(data[:], kind~, seed=case.seed),
      (case.low, case.high),
    )
    let state = @murmur3.Murmur3::new(kind~, seed=case.seed)
    for i in 0..<data.length() {
      state.update(data[i:i + 1])
    }
    let (lo, hi) = state.value()
    assert_eq(lo, case.low)
    assert_eq(hi, case.high)
  }
}

///|
/// No split point may change the digest, including one that lands in the middle
/// of the trailing partial block.
test "murmur3 does not depend on how the input is split" {
  let data = raw(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122",
  )
  let want32 = @murmur3.murmur3(data[:], kind=@murmur3.X86_32)
  let want128 = @murmur3.murmur3(data[:], kind=@murmur3.X64_128)
  for cut in 0..<=data.length() {
    let a = @murmur3.Murmur3::new(kind=@murmur3.X86_32)
    a.update(data[0:cut])
    a.update(data[cut:])
    assert_eq(a.value(), want32)
    let b = @murmur3.Murmur3::new(kind=@murmur3.X64_128)
    b.update(data[0:cut])
    b.update(data[cut:])
    assert_eq(b.value(), want128)
  }
}

///|
/// The seed reaches both halves of the 128-bit digest, and the two kinds are
/// different functions rather than one derived from the other.
test "the seed and the kind both matter" {
  let data = raw("666f6f")
  let plain = @murmur3.murmur3(data[:])
  let seeded = @murmur3.murmur3(data[:], seed=1)
  assert_true(plain.0 != seeded.0)
  assert_true(plain.1 != seeded.1)
  let (narrow, _) = @murmur3.murmur3(data[:], kind=@murmur3.X86_32)
  assert_true(narrow != plain.0)
}

///|
/// The [`@spec.Hash`] form writes each half big-endian, `h1` first, and reports
/// the size and block of the chosen kind.
test "murmur3 through the Hash trait" {
  let state = @murmur3.Murmur3::new(kind=@murmur3.X86_32)
  assert_eq(@spec.Hash::size(state), 4)
  assert_eq(@spec.Hash::block(state), 4)
  @spec.Hash::write(state, b"foo"[:])
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "f6a5c420")
  let wide = @murmur3.Murmur3::new()
  assert_eq(@spec.Hash::size(wide), 16)
  assert_eq(@spec.Hash::block(wide), 16)
  @spec.Hash::write(wide, b"foo"[:])
  assert_eq(
    @base16.encode(@spec.Hash::finish(wide)[:]),
    "e271865701f545617eaf87e42bba7d87",
  )
  // Reset leaves the state ready for another message with the same seed.
  @spec.Hash::reset(wide)
  assert_eq(
    @base16.encode(@spec.Hash::finish(wide)[:]),
    "00000000000000000000000000000000",
  )
  assert_eq(@spec.Hash::size(wide), 16)
}
