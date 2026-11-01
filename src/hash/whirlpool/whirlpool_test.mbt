// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn ascii(s : String) -> Bytes {
  @utf8.encode(s)
}

///|
/// The ISO/IEC 10118-3 worked examples: a 512-bit output leaves no room for a
/// coincidence, so a match on these is a match on the algorithm.
test "Whirlpool matches the ISO/IEC 10118-3 examples" {
  assert_eq(
    @base16.encode(@whirlpool.hash(ascii("")[:])),
    "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7" +
    "3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
  )
  assert_eq(
    @base16.encode(@whirlpool.hash(ascii("a")[:])),
    "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42" +
    "d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a",
  )
  assert_eq(
    @base16.encode(@whirlpool.hash(ascii("abc")[:])),
    "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c" +
    "7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
  )
}

///|
/// Writing a message in awkward pieces must reach the same digest as writing it
/// whole, which is what exercises the block buffer and its bounds.
test "Whirlpool streams identically in chunks" {
  let msg = Bytes::make(200, b'x')
  let whole = @whirlpool.hash(msg[:])
  let h = @whirlpool.Hasher::new()
  let mut at = 0
  while at < msg.length() {
    let take = if msg.length() - at > 7 { 7 } else { msg.length() - at }
    h.write(msg[at:at + take])
    at = at + take
  }
  assert_eq(@base16.encode(h.finish()[:]), @base16.encode(whole[:]))
}
