// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The largest prime below 65536, which is what keeps the two sums inside
/// sixteen bits once they are reduced.
let modulus : UInt32 = 65521

///|
/// The digest length in bytes.
pub let size : Int32 = 4

///|
/// The most bytes that can be accumulated between reductions: 255n(n+1)/2 +
/// (n+1)(65520) has to stay inside 32 bits, which zlib's own comment states as
/// 5552. Reducing more often would be correct but slower; reducing less often
/// would overflow, and an overflow here is a wrong checksum only on long inputs,
/// which is the worst kind of bug to find.
let batch : Int32 = 5552

///|
/// An Adler-32 in progress.
pub struct Adler32 {
  ///
  /// The sum of every byte so far, reduced only at batch boundaries.
  mut low : UInt32
  ///
  /// The sum of `low` after every byte, likewise.
  mut high : UInt32
}

///|
/// Start an Adler-32.
///
/// The initial sums are `a = 1` and `b = 0`, which is why the empty message has
/// a checksum of 1 and not 0.
pub fn Adler32::new() -> Adler32 {
  { low: 1, high: 0, }
}

///|
/// Feed more bytes.
pub fn Adler32::update(self : Adler32, data : BytesView) -> Unit {
  let mut a = self.low
  let mut b = self.high
  let mut at = 0
  while at < data.length() {
    let take = if data.length() - at < batch {
      data.length() - at
    } else {
      batch
    }
    for i in 0..<take {
      a = a + data[at + i].to_uint()
      b = b + a
    }
    a = a % modulus
    b = b % modulus
    at = at + take
  }
  self.low = a
  self.high = b
}

///|
/// The checksum of everything fed so far: `b` in the high half, `a` in the low,
/// which is the order every format that carries it writes.
pub fn Adler32::value(self : Adler32) -> UInt32 {
  let a = self.low % modulus
  let b = self.high % modulus
  (b << 16) | a
}

///|
/// The checksum as four bytes, most significant first — the order zlib's own
/// API and the gzip trailer write it in.
fn Adler32::bytes(self : Adler32) -> Bytes {
  let v = self.value()
  Bytes::from_array([
    (v >> 24).to_byte(),
    ((v >> 16) & 0xFF).to_byte(),
    ((v >> 8) & 0xFF).to_byte(),
    (v & 0xFF).to_byte(),
  ])
}

///|
/// The Adler-32 of a whole message.
pub fn adler32(data : BytesView) -> UInt32 {
  let state = Adler32::new()
  state.update(data)
  state.value()
}

///|
pub extend Adler32 with @spec.Hash::{write, finish, reset, size, block}

///|
pub impl @spec.Hash for Adler32 with fn write(self, data) {
  self.update(data)
}

///|
pub impl @spec.Hash for Adler32 with fn finish(self) {
  self.bytes()
}

///|
pub impl @spec.Hash for Adler32 with fn reset(self) {
  self.low = 1
  self.high = 0
}

///|
pub impl @spec.Hash for Adler32 with fn size(self) {
  let _ = self
  4
}

///|
pub impl @spec.Hash for Adler32 with fn block(self) {
  let _ = self
  1
}
