// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// The check value of `"123456789"` is the one every CRC catalogue publishes, so
/// it is the anchor; the rest come from `scripts/gen_crc_vectors.py`, which
/// reproduces that anchor and agrees with `zlib.crc32` on every IEEE case.
///
/// `data` is hex; the message is the empty string only for the two cases with a
/// checksum of zero.
fn check(kind : @crc32.Kind, data : String) -> UInt32 {
  @crc32.crc32(raw(data)[:], kind~)
}

///|
let every_byte : String = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
  "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
  "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
  "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
  "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
  "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

///|
/// The published check values, which every CRC catalogue lists.
test "crc32 matches the published check values" {
  assert_eq(check(@crc32.Ieee, "313233343536373839"), 0xCBF43926)
  assert_eq(check(@crc32.Castagnoli, "313233343536373839"), 0xE3069283)
  assert_eq(check(@crc32.Ieee, ""), 0x00000000)
  assert_eq(check(@crc32.Castagnoli, ""), 0x00000000)
}

///|
/// More cases, from the reference in `scripts/gen_crc_vectors.py`.
test "crc32 matches the reference" {
  assert_eq(check(@crc32.Ieee, "61"), 0xE8B7BE43)
  assert_eq(check(@crc32.Castagnoli, "61"), 0xC1D04330)
  assert_eq(check(@crc32.Ieee, "616263"), 0x352441C2)
  assert_eq(check(@crc32.Castagnoli, "616263"), 0x364B3FB7)
  assert_eq(
    check(
      @crc32.Ieee,
      "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    ),
    0x414FA339,
  )
  assert_eq(
    check(
      @crc32.Castagnoli,
      "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    ),
    0x22620404,
  )
  // Every byte value once, so the whole table is walked.
  assert_eq(check(@crc32.Ieee, every_byte), 0x29058C73)
  assert_eq(check(@crc32.Castagnoli, every_byte), 0x9C44184B)
  assert_eq(check(@crc32.Ieee, "6d6f6f6e6372797074"), 0x313D68EA)
  assert_eq(check(@crc32.Castagnoli, "6d6f6f6e6372797074"), 0xA7F93F6D)
}

///|
/// A run of zeroes, which a table lookup could get wrong by treating the zero
/// byte as "nothing to do". Fed whole and in slices, and the two must agree.
test "crc32 over a long run of zeroes" {
  let zeros : FixedArray[Byte] = FixedArray::make(300, b'\x00')
  let data = Bytes::from_array(zeros)
  assert_eq(@crc32.crc32(data[:]), 0xB5348FD2)
  assert_eq(@crc32.crc32(data[:], kind=@crc32.Castagnoli), 0x64557710)
  let state = @crc32.Crc32::new()
  for i in 0..<30 {
    state.update(data[i * 10:i * 10 + 10])
  }
  assert_eq(state.value(), 0xB5348FD2)
  // One byte at a time is the slowest way to get it wrong.
  let slow = @crc32.Crc32::new()
  for i in 0..<data.length() {
    slow.update(data[i:i + 1])
  }
  assert_eq(slow.value(), 0xB5348FD2)
}

///|
/// The [`@spec.Hash`] form gives the same bytes, big-endian, and the state can be
/// reset and reused.
test "crc32 through the Hash trait" {
  let data = raw("313233343536373839")
  let state = @crc32.Crc32::new()
  @spec.Hash::write(state, data[:])
  let first = @spec.Hash::finish(state)
  assert_eq(@base16.encode(first[:]), "cbf43926")
  assert_eq(@spec.Hash::size(state), 4)
  assert_eq(@spec.Hash::block(state), 1)
  // `finish` does not consume the state, so reading it twice gives the same
  // answer.
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "cbf43926")
  @spec.Hash::reset(state)
  assert_eq(@spec.Hash::finish(state)[:], raw("00000000")[:])
  @spec.Hash::write(state, data[:])
  assert_eq(@base16.encode(@spec.Hash::finish(state)[:]), "cbf43926")
  // And the one-shot helper in `spec` goes through the same path.
  assert_eq(@base16.encode(@spec.digest(state, data[:])[:]), "cbf43926")
}

///|
/// The two polynomials really do differ, so a caller that picks the wrong one
/// gets a wrong answer rather than a right one by accident.
test "the two polynomials disagree" {
  let data = raw("313233343536373839")
  assert_true(
    @crc32.crc32(data[:], kind=@crc32.Ieee) !=
    @crc32.crc32(data[:], kind=@crc32.Castagnoli),
  )
  assert_eq(@crc32.Kind::size(@crc32.Ieee), 4)
  assert_eq(@crc32.Kind::block(@crc32.Castagnoli), 1)
}
