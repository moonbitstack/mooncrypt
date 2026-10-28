// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The digest length in bytes.
pub let size : Int32 = 32

///|
/// The block length in bytes.
pub let block : Int32 = 64

///|
/// The initial vector (GB/T 32905 §4.1).
let iv : FixedArray[UInt32] = [
  0x7380166FU, 0x4914B2B9U, 0x172442D7U, 0xDA8A0600U, 0xA96F30BCU, 0x163138AAU, 0xE38DEE4DU,
  0xB0FB0E4EU,
]

///|
fn rotl(x : UInt32, n : Int32) -> UInt32 {
  if n == 0 {
    x
  } else {
    (x << n) | (x >> (32 - n))
  }
}

///|
/// `P0`, the permutation applied to the round's second half.
fn p0(x : UInt32) -> UInt32 {
  x ^ rotl(x, 9) ^ rotl(x, 17)
}

///|
/// `P1`, the permutation inside the message expansion.
fn p1(x : UInt32) -> UInt32 {
  x ^ rotl(x, 15) ^ rotl(x, 23)
}

///|
/// The round constant: `0x79cc4519` for the first sixteen rounds and
/// `0x7a879d8a` for the rest, rotated by the round number.
fn t(j : Int32) -> UInt32 {
  let c = if j < 16 { 0x79CC4519U } else { 0x7A879D8AU }
  rotl(c, j % 32)
}

///|
fn ff(j : Int32, x : UInt32, y : UInt32, z : UInt32) -> UInt32 {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | (x & z) | (y & z)
  }
}

///|
fn gg(j : Int32, x : UInt32, y : UInt32, z : UInt32) -> UInt32 {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | (x.lnot() & z)
  }
}

///|
fn word(buf : FixedArray[Byte], off : Int32) -> UInt32 {
  let mut v = 0U
  for b in 0..<4 {
    v = (v << 8) | buf[off + b].to_int().reinterpret_as_uint()
  }
  v
}

///|
/// The compression function (GB/T 32905 §5.3).
fn compress(
  h : FixedArray[UInt32],
  buf : FixedArray[Byte],
  off : Int32,
) -> Unit {
  let w : FixedArray[UInt32] = FixedArray::make(68, 0U)
  for i in 0..<16 {
    w[i] = word(buf, off + i * 4)
  }
  for j in 16..<68 {
    w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^
      rotl(w[j - 13], 7) ^
      w[j - 6]
  }
  let mut a = h[0]
  let mut b = h[1]
  let mut c = h[2]
  let mut d = h[3]
  let mut e = h[4]
  let mut f = h[5]
  let mut g = h[6]
  let mut k = h[7]
  for j in 0..<64 {
    let ss1 = rotl(rotl(a, 12) + e + t(j), 7)
    let ss2 = ss1 ^ rotl(a, 12)
    let tt1 = ff(j, a, b, c) + d + ss2 + (w[j] ^ w[j + 4])
    let tt2 = gg(j, e, f, g) + k + ss1 + w[j]
    d = c
    c = rotl(b, 9)
    b = a
    a = tt1
    k = g
    g = rotl(f, 19)
    f = e
    e = p0(tt2)
  }
  h[0] = h[0] ^ a
  h[1] = h[1] ^ b
  h[2] = h[2] ^ c
  h[3] = h[3] ^ d
  h[4] = h[4] ^ e
  h[5] = h[5] ^ f
  h[6] = h[6] ^ g
  h[7] = h[7] ^ k
}

///|
/// An SM3 computation in progress.
struct Hasher {
  h : FixedArray[UInt32]
  buf : FixedArray[Byte]
  mut used : Int32
  mut n : UInt64
}

///|
pub fn Hasher::new() -> Hasher {
  let h : FixedArray[UInt32] = FixedArray::make(8, 0U)
  for i in 0..<8 {
    h[i] = iv[i]
  }
  { h, buf: FixedArray::make(64, b'\x00'), used: 0, n: 0, }
}

///|
/// Hash one whole message.
pub fn hash(msg : BytesView) -> Bytes {
  let h = Hasher::new()
  h.write(msg)
  h.finish()
}

///|
pub extend Hasher with @spec.Hash::{block, finish, reset, size, write}

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
      compress(self.h, self.buf, 0)
      self.used = 0
    }
  }
}

///|
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  let h : FixedArray[UInt32] = FixedArray::make(8, 0U)
  for i in 0..<8 {
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
    compress(h, pad, off)
  }
  let out : Array[Byte] = []
  for i in 0..<8 {
    for b = 3; b >= 0; b = b - 1 {
      out.push(((h[i] >> (b * 8)) & 0xFFU).to_byte())
    }
  }
  Bytes::from_array(out)
}

///|
pub impl @spec.Hash for Hasher with fn reset(self : Hasher) -> Unit {
  for i in 0..<8 {
    self.h[i] = iv[i]
  }
  self.used = 0
  self.n = 0
}

///|
pub impl @spec.Hash for Hasher with fn size(_self : Hasher) -> Int32 {
  32
}

///|
pub impl @spec.Hash for Hasher with fn block(_self : Hasher) -> Int32 {
  64
}
