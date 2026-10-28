// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// The 32-byte key the examples in SP 800-185 use, `40 41 ... 5f`.
fn key() -> Bytes {
  Bytes::from_array(Array::make(32, 0).mapi(fn(i, _) { (0x40 + i).to_byte() }))
}

///|
/// The four-byte message those examples mac.
fn msg() -> Bytes {
  [0x00, 0x01, 0x02, 0x03]
}

///|
/// The two hundred-byte message, `00 01 ... c7`.
fn long() -> Bytes {
  Bytes::from_array(Array::make(200, 0).mapi(fn(i, _) { i.to_byte() }))
}

///|
/// SP 800-185 A.2: KMAC128 with and without a customisation string.
test "KMAC128 matches the SP 800-185 examples" {
  assert_eq(
    hex(@kmac.mac(key()[:], msg()[:], len=32)),
    "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
  )
  let tag : Bytes = @moonbase.ascii("My Tagged Application")
  assert_eq(
    hex(@kmac.mac(key()[:], msg()[:], len=32, custom=tag[:])),
    "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
  )
}

///|
/// SP 800-185 A.3 and A.4: a message longer than the rate, and the 256-bit
/// variant.
test "KMAC carries a message past the block boundary" {
  let tag : Bytes = @moonbase.ascii("My Tagged Application")
  assert_eq(
    hex(@kmac.mac(key()[:], long()[:], len=64, custom=tag[:])),
    "bc834ff753cb4fce2b44658f71c62c1e5b5cf3ade4f4383c5f09316532f0730b833af6d4f2b018d5d216a41c331c81ba1012ede8c62777caa665ee74e18b4d3c",
  )
  assert_eq(
    hex(@kmac.mac(key()[:], msg()[:], kind=Kmac256, len=64, custom=tag[:])),
    "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
  )
}

///|
/// A streaming KMAC sees the same message however it arrives, and reading
/// twice answers the same tag.
test "KMAC streams, and reads twice" {
  let m = @kmac.Kmac::new(key()[:])
  m.write(b"\x00\x01"[:])
  m.write(b"\x02\x03"[:])
  let first = m.finish()
  assert_eq(hex(first), hex(@kmac.mac(key()[:], msg()[:], len=32)))
  assert_eq(hex(m.finish()), hex(first))
  assert_eq(m.size(), 32)
  let as_mac : &@spec.Mac = m
  assert_eq(as_mac.size(), 32)
  assert_eq(hex(as_mac.finish()), hex(first))
}

///|
/// The tag length is part of the sponge, so the same message at two lengths is
/// two unrelated tags rather than one a prefix of the other.
test "KMAC mixes in the length it is asked for" {
  let short = @kmac.mac(key()[:], msg()[:], len=16)
  let long = @kmac.mac(key()[:], msg()[:], len=32)
  assert_eq(short.length(), 16)
  assert_true(hex(short) != hex(long[0:16]))
}

///|
/// KMACXOF has no length in the sponge at all, so a prefix of a longer read is
/// the shorter read.
test "KMACXOF is an extendable output" {
  let short = @kmac.xof(key()[:], msg()[:], len=16)
  let long = @kmac.xof(key()[:], msg()[:], len=64)
  assert_eq(hex(short), hex(long[0:16]))
  // Reading in pieces continues rather than repeating.
  let m = @kmac.KmacXof::new(key()[:])
  m.write(msg()[:])
  let head = m.squeeze(8)
  let tail = m.squeeze(8)
  assert_eq(hex(head) + hex(tail), hex(short))
}
