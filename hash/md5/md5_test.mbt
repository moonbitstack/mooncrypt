// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : Bytes) -> String {
  @base16.encode(b[:])
}

///|
fn ascii(s : String) -> Bytes {
  @moonbase.ascii(s)
}

///|
/// The seven-string test suite of RFC 1321 §A.5, which every MD5 is expected to
/// reproduce verbatim.
test "MD5 matches the RFC 1321 test suite" {
  let cases = [
    ("", "d41d8cd98f00b204e9800998ecf8427e"),
    ("a", "0cc175b9c0f1b6a831c399e269772661"),
    ("abc", "900150983cd24fb0d6963f7d28e17f72"),
    ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
    ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
    (
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f",
    ),
    (
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "57edf4a22be3c955ac49da2e2107b67a",
    ),
  ]
  for case in cases {
    let (msg, want) = case
    assert_eq(hex(@md5.hash(ascii(msg)[:])), want)
  }
}

///|
test "streaming in chunks agrees with the one-shot" {
  let msg : Array[Byte] = []
  for i in 0..<200 {
    msg.push((i * 13 % 251).to_byte())
  }
  let whole = Bytes::from_array(msg)
  let want = @md5.hash(whole[:])
  for cut in [1, 17, 63, 64, 65, 128] {
    let h = @md5.Hasher::new()
    let mut at = 0
    while at < whole.length() {
      let end = if at + cut < whole.length() {
        at + cut
      } else {
        whole.length()
      }
      h.write(whole[at:end])
      at = end
    }
    assert_eq(h.finish(), want)
  }
}

///|
test "a digest is sixteen bytes over a sixty-four byte block" {
  let h = @md5.Hasher::new()
  assert_eq(h.size(), 16)
  assert_eq(h.block(), 64)
  h.write(ascii("abc")[:])
  h.reset()
  assert_eq(hex(h.finish()), "d41d8cd98f00b204e9800998ecf8427e")
}
