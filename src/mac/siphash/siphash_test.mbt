// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One case: the key in hex, the message in hex, and the tag.
struct Case {
  key : String
  data : String
  expected : UInt64
}

///|
/// From `scripts/gen_siphash_vectors.py`, which writes SipHash out from the paper
/// and then refuses to emit anything unless every case agrees with the `siphash`
/// module.
///
/// The first rows are the published reference sequence for the key
/// `000102...0f`, so they pin the constants without the module. The lengths
/// cover zero through eight bytes — the block boundary — and beyond.
let cases : Array[Case] = [
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "",
    expected: 0x726FDB47DD0E0E31UL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "000102030405060708090a0b0c0d0e",
    expected: 0xA129CA6149BE45E5UL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "000102030405060708090a0b0c0d0e0f",
    expected: 0x3F2ACC7F57C29BDBUL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "00",
    expected: 0x74F839C593DC67FDUL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "61",
    expected: 0x2BA3E8E9A71148CAUL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "616263",
    expected: 0x5DBCFA53AA2007A5UL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "666f6f",
    expected: 0xE0B8C1D41E478D1DUL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "666f6f626172",
    expected: 0xF15E87A1187632C0UL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "0001020304050607",
    expected: 0x93F5F5799A932462UL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "000102030405060708",
    expected: 0x9E0082DF0BA9E4B0UL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "000102030405060708090a0b0c0d0e0f1011121314151617",
    expected: 0xB8AD50C6F649AF94UL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "6d6f6f6e6372797074",
    expected: 0x02C641F174CBE97AUL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "ffffffffffffffffffffffffffffffffff",
    expected: 0x28A447DA70A115DAUL,
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    data: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    expected: 0x52276105DC1F6FE4UL,
  },
  {
    key: "0f0e0d0c0b0a09080706050403020100",
    data: "",
    expected: 0x0B6607096DA500FFUL,
  },
  {
    key: "0f0e0d0c0b0a09080706050403020100",
    data: "666f6f626172",
    expected: 0xC3EA35CD382A34C1UL,
  },
  {
    key: "0f0e0d0c0b0a09080706050403020100",
    data: "000102030405060708090a0b0c0d0e0f",
    expected: 0x700EF267F7ED1C5DUL,
  },
]

///|
/// Read eight big-endian bytes back as the number they are.
fn be_word(bytes : Bytes) -> UInt64 {
  let mut v = 0UL
  for i in 0..<bytes.length() {
    v = (v << 8) | bytes[i].to_uint().to_uint64()
  }
  v
}

///|
/// Every case, one-shot and through a state fed a byte at a time. The byte form
/// is checked too, so the tag really is the number read big-endian.
test "siphash matches the reference" {
  for case in cases {
    let key = raw(case.key)
    let data = raw(case.data)
    let tag = @siphash.siphash(key[:], data[:])
    assert_eq(tag.length(), 8)
    assert_eq(be_word(tag), case.expected)
    let state = @siphash.SipHash::new(key[:])
    for i in 0..<data.length() {
      state.update(data[i:i + 1])
    }
    assert_eq(state.value(), case.expected)
  }
}

///|
/// The published sequence from the SipHash paper, written out rather than taken
/// from the table above: a transcription error there would otherwise be invisible.
test "siphash reproduces the published sequence" {
  let key = raw("000102030405060708090a0b0c0d0e0f")
  let lengths = [
    (0, 0x726FDB47DD0E0E31UL),
    (1, 0x74F839C593DC67FDUL),
    (8, 0x93F5F5799A932462UL),
    (15, 0xA129CA6149BE45E5UL),
  ]
  for pair in lengths {
    let (n, want) = pair
    let msg : FixedArray[Byte] = FixedArray::make(n, b'\x00')
    for i in 0..<n {
      msg[i] = i.to_byte()
    }
    let state = @siphash.SipHash::new(key[:])
    state.update(Bytes::from_array(msg)[:])
    assert_eq(state.value(), want)
  }
}

///|
/// No split point may change the tag, which is what makes this usable on a stream.
test "siphash does not depend on how the input is split" {
  let key = raw("000102030405060708090a0b0c0d0e0f")
  let data = raw("000102030405060708090a0b0c0d0e0f101112131415161718")
  let want = @siphash.siphash(key[:], data[:])
  for cut in 0..<=data.length() {
    let state = @siphash.SipHash::new(key[:])
    state.update(data[0:cut])
    state.update(data[cut:])
    assert_eq(@spec.Mac::finish(state), want)
  }
}

///|
/// A key of the wrong length is refused, not padded.
test "siphash refuses a key of the wrong length" {
  let short = raw("000102030405060708090a0b0c0d0e")
  let long = raw("000102030405060708090a0b0c0d0e0f10")
  for bad in [short, long] {
    let mut refused = false
    try {
      let _ = @siphash.SipHash::new(bad[:])
    } catch {
      _ => refused = true
    }
    assert_true(refused)
  }
  assert_eq(@siphash.key_size, 16)
}

///|
/// The [`@spec.Mac`] form reports a 64-bit tag, and computing it twice gives the
/// same answer because the state is copied rather than consumed.
test "siphash through the Mac trait" {
  let key = raw("000102030405060708090a0b0c0d0e0f")
  let state = @siphash.SipHash::new(key[:])
  assert_eq(@spec.Mac::size(state), 8)
  @spec.Mac::write(state, b"foobar"[:])
  let tag = @spec.Mac::finish(state)
  assert_eq(@base16.encode(tag[:]), "f15e87a1187632c0")
  assert_eq(@base16.encode(@spec.Mac::finish(state)[:]), "f15e87a1187632c0")
  // Two different keys give two different tags for the same message, which is
  // the one property a MAC has to have.
  let other = @siphash.SipHash::new(raw("0f0e0d0c0b0a09080706050403020100")[:])
  @spec.Mac::write(other, b"foobar"[:])
  assert_true(@spec.Mac::finish(other) != tag)
}
