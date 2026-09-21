// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An MD5 computation in progress.
///
/// MD5 is broken: collisions are minutes of work on a laptop and have been since
/// 2005. It is here because PostgreSQL's `md5` authentication and a long tail of
/// checksums and legacy file formats still speak it. Never use it to
/// authenticate anything new — `mooncrypt/hash/sha2` is the replacement.
struct Hasher {
  h : FixedArray[UInt]
  buf : FixedArray[Byte]
  mut used : Int
  mut n : UInt64
}

///|
pub fn Hasher::new() -> Hasher {
  let h = {
    h: FixedArray::make(4, 0U),
    buf: FixedArray::make(64, b'\x00'),
    used: 0,
    n: 0,
  }
  h.reset()
  h
}

///|
/// Hash one whole message to a 16-byte digest.
pub fn hash(msg : BytesView) -> Bytes {
  let h = Hasher::new()
  h.write(msg)
  h.finish()
}

///|
pub extend Hasher with @spec.Hash::{block, finish, reset, size, write}

///|
pub impl @spec.Hash for Hasher with fn size(_ : Hasher) -> Int {
  16
}

///|
pub impl @spec.Hash for Hasher with fn block(_ : Hasher) -> Int {
  64
}

///|
pub impl @spec.Hash for Hasher with fn reset(self : Hasher) -> Unit {
  self.h[0] = 0x67452301
  self.h[1] = 0xEFCDAB89
  self.h[2] = 0x98BADCFE
  self.h[3] = 0x10325476
  self.used = 0
  self.n = 0
}

///|
pub impl @spec.Hash for Hasher with fn write(self : Hasher, msg : BytesView) -> Unit {
  self.n += msg.length().to_uint64()
  let mut at = 0
  while at < msg.length() {
    let room = 64 - self.used
    let left = msg.length() - at
    let take = if room < left { room } else { left }
    for i in 0..<take {
      self.buf[self.used + i] = msg[at + i]
    }
    self.used += take
    at += take
    if self.used == 64 {
      block(self.h, self.buf, 0)
      self.used = 0
    }
  }
}

///|
/// MD5 counts and emits little-endian, where SHA-1 and SHA-2 are big-endian —
/// the one place the two designs part company in the padding.
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  let h : FixedArray[UInt] = FixedArray::make(4, 0U)
  for i in 0..<4 {
    h[i] = self.h[i]
  }
  let pad : FixedArray[Byte] = FixedArray::make(128, b'\x00')
  for i in 0..<self.used {
    pad[i] = self.buf[i]
  }
  pad[self.used] = b'\x80'
  let total = if self.used < 56 { 64 } else { 128 }
  let bits = self.n * 8UL
  for i in 0..<8 {
    pad[total - 8 + i] = ((bits >> (i * 8)) & 0xFFUL).to_byte()
  }
  for off = 0; off < total; off = off + 64 {
    block(h, pad, off)
  }
  let out : Array[Byte] = []
  for i in 0..<4 {
    for shift in 0..<4 {
      out.push(((h[i] >> (shift * 8)) & 0xFFU).to_byte())
    }
  }
  Bytes::from_array(out)
}

///|
/// The per-round constants: the integer part of `2^32 · |sin(i + 1)|` with `i`
/// in radians (RFC 1321 §3.4).
let k : FixedArray[UInt] = [
  0xD76AA478U, 0xE8C7B756U, 0x242070DBU, 0xC1BDCEEEU, 0xF57C0FAFU, 0x4787C62AU, 0xA8304613U,
  0xFD469501U, 0x698098D8U, 0x8B44F7AFU, 0xFFFF5BB1U, 0x895CD7BEU, 0x6B901122U, 0xFD987193U,
  0xA679438EU, 0x49B40821U, 0xF61E2562U, 0xC040B340U, 0x265E5A51U, 0xE9B6C7AAU, 0xD62F105DU,
  0x02441453U, 0xD8A1E681U, 0xE7D3FBC8U, 0x21E1CDE6U, 0xC33707D6U, 0xF4D50D87U, 0x455A14EDU,
  0xA9E3E905U, 0xFCEFA3F8U, 0x676F02D9U, 0x8D2A4C8AU, 0xFFFA3942U, 0x8771F681U, 0x6D9D6122U,
  0xFDE5380CU, 0xA4BEEA44U, 0x4BDECFA9U, 0xF6BB4B60U, 0xBEBFBC70U, 0x289B7EC6U, 0xEAA127FAU,
  0xD4EF3085U, 0x04881D05U, 0xD9D4D039U, 0xE6DB99E5U, 0x1FA27CF8U, 0xC4AC5665U, 0xF4292244U,
  0x432AFF97U, 0xAB9423A7U, 0xFC93A039U, 0x655B59C3U, 0x8F0CCC92U, 0xFFEFF47DU, 0x85845DD1U,
  0x6FA87E4FU, 0xFE2CE6E0U, 0xA3014314U, 0x4E0811A1U, 0xF7537E82U, 0xBD3AF235U, 0x2AD7D2BBU,
  0xEB86D391U,
]

///|
/// How far each round rotates left, four values repeated across each group of
/// sixteen (RFC 1321 §3.4).
let shifts : FixedArray[Int] = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9,
  14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]

///|
fn rotl(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
fn block(h : FixedArray[UInt], data : FixedArray[Byte], off : Int) -> Unit {
  let m : FixedArray[UInt] = FixedArray::make(16, 0U)
  for i in 0..<16 {
    let j = off + i * 4
    m[i] = data[j].to_int().reinterpret_as_uint() |
      (data[j + 1].to_int().reinterpret_as_uint() << 8) |
      (data[j + 2].to_int().reinterpret_as_uint() << 16) |
      (data[j + 3].to_int().reinterpret_as_uint() << 24)
  }
  let mut a = h[0]
  let mut b = h[1]
  let mut c = h[2]
  let mut d = h[3]
  for i in 0..<64 {
    let (f, g) = if i < 16 {
      ((b & c) | (b.lnot() & d), i)
    } else if i < 32 {
      ((d & b) | (d.lnot() & c), (5 * i + 1) % 16)
    } else if i < 48 {
      (b ^ c ^ d, (3 * i + 5) % 16)
    } else {
      (c ^ (b | d.lnot()), 7 * i % 16)
    }
    let t = f + a + k[i] + m[g]
    a = d
    d = c
    c = b
    b = b + rotl(t, shifts[i])
  }
  h[0] += a
  h[1] += b
  h[2] += c
  h[3] += d
}
