// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn ascii(s : String) -> Bytes {
  @utf8.encode(s)
}

///|
/// RFC 6986 §A.1's M1: the ASCII digits, repeated.
let m1 = "012345678901234567890123456789012345678901234567890123456789012"

///|
test "Streebog-512 matches the RFC 6986 vectors" {
  assert_eq(
    @base16.encode(@streebog.hash(ascii(m1)[:])),
    "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa" +
    "00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48",
  )
  assert_eq(
    @base16.encode(@streebog.hash(b""[:])),
    "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7" +
    "362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",
  )
}

///|
test "Streebog-256 matches the RFC 6986 and reference vectors" {
  assert_eq(
    @base16.encode(@streebog.hash(ascii(m1)[:], size=32)),
    "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
  )
  assert_eq(
    @base16.encode(@streebog.hash(b""[:], size=32)),
    "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
  )
  assert_eq(
    @base16.encode(@streebog.hash(ascii("foobar")[:], size=32)),
    "e3c9fd89226d93b489a9fe27d686806e24a514e3787bca053c698ec4616ceb78",
  )
}

///|
test "Streebog streams identically in chunks" {
  let msg = ascii(
    "The quick brown fox jumps over the lazy dog, twice. The quick brown fox jumps over the lazy dog.",
  )
  let whole = @streebog.hash(msg[:], size=32)
  let h = @streebog.Hasher::new(size=32)
  let mut at = 0
  while at < msg.length() {
    let take = if msg.length() - at > 5 { 5 } else { msg.length() - at }
    h.write(msg[at:at + take])
    at = at + take
  }
  assert_eq(@base16.encode(h.finish()[:]), @base16.encode(whole[:]))
}
