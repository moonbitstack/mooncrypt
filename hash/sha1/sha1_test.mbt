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
/// FIPS 180-4 §A.1 and §A.2, plus the three lengths around the padding boundary.
test "SHA-1 matches the published vectors" {
  let cases = [
    ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    ),
    (
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "c1c8bbdc22796e28c0e15163d20899b65621d65a",
    ),
    (
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "c2db330f6083854c99d4b5bfb6e8f29f201be699",
    ),
    (
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0098ba824b5c16427bd7a1122a5a442a25ec644d",
    ),
  ]
  for case in cases {
    let (msg, want) = case
    assert_eq(hex(@sha1.hash(ascii(msg)[:])), want)
  }
}

///|
test "streaming in chunks agrees with the one-shot" {
  let msg : Array[Byte] = []
  for i in 0..<200 {
    msg.push((i * 11 % 251).to_byte())
  }
  let whole = Bytes::from_array(msg)
  let want = @sha1.hash(whole[:])
  for cut in [1, 17, 63, 64, 65, 128] {
    let h = @sha1.Hasher::new()
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
test "a digest is twenty bytes over a sixty-four byte block" {
  let h = @sha1.Hasher::new()
  assert_eq(h.size(), 20)
  assert_eq(h.block(), 64)
  h.write(ascii("abc")[:])
  h.reset()
  assert_eq(hex(h.finish()), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
}
