// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A SHA-1 computation in progress.
///
/// SHA-1 is broken for anything that needs collision resistance — a chosen-prefix
/// collision has been public since 2019 — and is here because three protocols
/// still specify it and will not stop: the WebSocket handshake (RFC 6455 §4.2.2),
/// MySQL's `mysql_native_password`, and Git's object names. Reach for
/// `mooncrypt/hash/sha2` for anything new.
struct Hasher {
  h : FixedArray[UInt]
  buf : FixedArray[Byte]
  mut used : Int
  mut n : UInt64
}

///|
pub fn Hasher::new() -> Hasher {
  let h = {
    h: FixedArray::make(5, 0U),
    buf: FixedArray::make(64, b'\x00'),
    used: 0,
    n: 0,
  }
  h.reset()
  h
}

///|
/// Hash one whole message to a 20-byte digest.
pub fn hash(msg : BytesView) -> Bytes {
  let h = Hasher::new()
  h.write(msg)
  h.finish()
}

///|
pub extend Hasher with @spec.Hash::{block, finish, reset, size, write}

///|
pub impl @spec.Hash for Hasher with fn size(_ : Hasher) -> Int {
  20
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
  self.h[4] = 0xC3D2E1F0
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
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  let h : FixedArray[UInt] = FixedArray::make(5, 0U)
  for i in 0..<5 {
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
    pad[total - 1 - i] = ((bits >> (i * 8)) & 0xFFUL).to_byte()
  }
  for off = 0; off < total; off = off + 64 {
    block(h, pad, off)
  }
  let out : Array[Byte] = []
  for i in 0..<5 {
    for k = 3; k >= 0; k = k - 1 {
      out.push(((h[i] >> (k * 8)) & 0xFFU).to_byte())
    }
  }
  Bytes::from_array(out)
}

///|
fn rotl(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
/// The 80-round compression of FIPS 180-4 §6.1.2, with the four round functions
/// and their constants inline.
fn block(h : FixedArray[UInt], data : FixedArray[Byte], off : Int) -> Unit {
  let w : FixedArray[UInt] = FixedArray::make(80, 0U)
  for i in 0..<16 {
    let j = off + i * 4
    w[i] = (data[j].to_int().reinterpret_as_uint() << 24) |
      (data[j + 1].to_int().reinterpret_as_uint() << 16) |
      (data[j + 2].to_int().reinterpret_as_uint() << 8) |
      data[j + 3].to_int().reinterpret_as_uint()
  }
  for i in 16..<80 {
    w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
  }
  let mut a = h[0]
  let mut b = h[1]
  let mut c = h[2]
  let mut d = h[3]
  let mut e = h[4]
  for i in 0..<80 {
    let (f, k) = if i < 20 {
      ((b & c) | (b.lnot() & d), 0x5A827999U)
    } else if i < 40 {
      (b ^ c ^ d, 0x6ED9EBA1U)
    } else if i < 60 {
      ((b & c) | (b & d) | (c & d), 0x8F1BBCDCU)
    } else {
      (b ^ c ^ d, 0xCA62C1D6U)
    }
    let t = rotl(a, 5) + f + e + k + w[i]
    e = d
    d = c
    c = rotl(b, 30)
    b = a
    a = t
  }
  h[0] += a
  h[1] += b
  h[2] += c
  h[3] += d
  h[4] += e
}
