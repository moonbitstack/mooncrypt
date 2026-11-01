// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn dup(a : FixedArray[Byte]) -> FixedArray[Byte] {
  let o = FixedArray::make(a.length(), b'\x00')
  for i in 0..<a.length() {
    o[i] = a[i]
  }
  o
}

///|
fn bxor(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
  let o = FixedArray::make(a.length(), b'\x00')
  for i in 0..<a.length() {
    o[i] = (a[i].to_int() ^ b[i].to_int()).to_byte()
  }
  o
}

///|
/// The PS transform: substitute each byte through Pi, then move byte i to
/// position Tau[i].
fn ps(d : FixedArray[Byte]) -> FixedArray[Byte] {
  let o = FixedArray::make(64, b'\x00')
  for i in 0..<64 {
    o[tau[i]] = pi[d[i].to_int()]
  }
  o
}

///|
/// The linear transform L: each of the eight 64-bit words (little-endian) is
/// multiplied by the A matrix over GF(2), most significant bit first.
fn l(d : FixedArray[Byte]) -> FixedArray[Byte] {
  let o = FixedArray::make(64, b'\x00')
  for w in 0..<8 {
    let mut val = 0UL
    for k in 0..<8 {
      val = val | (d[w * 8 + k].to_int().to_uint64() << (k * 8))
    }
    let mut r64 = 0UL
    let mut v = val
    for j in 0..<64 {
      if (v & 0x8000000000000000UL) != 0UL {
        r64 = r64 ^ a_tab[j]
      }
      v = v << 1
    }
    for k in 0..<8 {
      o[w * 8 + k] = ((r64 >> (k * 8)) & 0xFFUL).to_byte()
    }
  }
  o
}

///|
fn lps(d : FixedArray[Byte]) -> FixedArray[Byte] {
  l(ps(d))
}

///|
/// The cipher E: twelve rounds of LPS, the key updated by LPS(K ⊕ C[i]) between
/// them.
fn e(k : FixedArray[Byte], msg : FixedArray[Byte]) -> FixedArray[Byte] {
  let mut m = dup(msg)
  let mut kk = dup(k)
  for i in 0..<12 {
    m = lps(bxor(kk, m))
    kk = lps(bxor(kk, c_tab[i]))
  }
  bxor(kk, m)
}

///|
/// The compression g_N(h, m) = E(LPS(h ⊕ N), m) ⊕ h ⊕ m, with the bit counter N
/// mixed into the first eight bytes little-endian.
fn g(
  n : UInt64,
  hsh : FixedArray[Byte],
  msg : FixedArray[Byte],
) -> FixedArray[Byte] {
  let combined = FixedArray::make(64, b'\x00')
  for k in 0..<8 {
    combined[k] = (hsh[k].to_int() ^ ((n >> (k * 8)) & 0xFFUL).to_int()).to_byte()
  }
  for k in 8..<64 {
    combined[k] = hsh[k]
  }
  bxor(bxor(e(lps(combined), msg), hsh), msg)
}

///|
/// Add two 512-bit vectors little-endian, mod 2^512.
fn add512(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
  let o = FixedArray::make(64, b'\x00')
  let mut carry = 0
  for i in 0..<64 {
    let s = a[i].to_int() + b[i].to_int() + carry
    o[i] = (s & 0xFF).to_byte()
    carry = s >> 8
  }
  o
}

///|
/// A Streebog computation in progress.
struct Hasher {
  mut hsh : FixedArray[Byte]
  mut chk : FixedArray[Byte]
  buf : FixedArray[Byte]
  mut used : Int32
  mut n : UInt64
  out_size : Int32
}

///|
fn initial(size : Int32) -> FixedArray[Byte] {
  let h = FixedArray::make(64, b'\x00')
  if size == 32 {
    for i in 0..<64 {
      h[i] = b'\x01'
    }
  }
  h
}

///|
/// A fresh state. `size` is the digest length in bytes: 32 for Streebog-256,
/// 64 for Streebog-512 (the default), which differ only in the initial vector.
pub fn Hasher::new(size~ : Int32 = 64) -> Hasher {
  {
    hsh: initial(size),
    chk: FixedArray::make(64, b'\x00'),
    buf: FixedArray::make(64, b'\x00'),
    used: 0,
    n: 0UL,
    out_size: size,
  }
}

///|
pub extend Hasher with @spec.Hash::{block, finish, reset, size, write}

///|
pub impl @spec.Hash for Hasher with fn write(self : Hasher, msg : BytesView) -> Unit {
  let mut at = 0
  while at < msg.length() {
    let room = 64 - self.used
    let left = msg.length() - at
    let take = if room < left { room } else { left }
    for i in 0..<take {
      self.buf[self.used + i] = msg[at + i]
    }
    self.used = self.used + take
    at = at + take
    if self.used == 64 {
      self.hsh = g(self.n, self.hsh, self.buf)
      self.chk = add512(self.chk, self.buf)
      self.n = self.n + 512UL
      self.used = 0
    }
  }
}

///|
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  let last = FixedArray::make(64, b'\x00')
  for k in 0..<self.used {
    last[k] = self.buf[k]
  }
  last[self.used] = b'\x01'
  let h1 = g(self.n, self.hsh, last)
  let n1 = self.n + (self.used * 8).to_uint64()
  let ch1 = add512(self.chk, last)
  let nb = FixedArray::make(64, b'\x00')
  for k in 0..<8 {
    nb[k] = ((n1 >> (k * 8)) & 0xFFUL).to_byte()
  }
  let h2 = g(0UL, h1, nb)
  let h3 = g(0UL, h2, ch1)
  let out : Array[Byte] = []
  for k in (64 - self.out_size)..<64 {
    out.push(h3[k])
  }
  Bytes::from_array(out)
}

///|
pub impl @spec.Hash for Hasher with fn reset(self : Hasher) -> Unit {
  self.hsh = initial(self.out_size)
  self.chk = FixedArray::make(64, b'\x00')
  self.used = 0
  self.n = 0UL
}

///|
pub impl @spec.Hash for Hasher with fn size(self : Hasher) -> Int32 {
  self.out_size
}

///|
pub impl @spec.Hash for Hasher with fn block(self : Hasher) -> Int32 {
  ignore(self)
  64
}

///|
/// One whole message through Streebog, in one call. `size` selects 256 (32) or
/// 512 (64, the default).
pub fn hash(msg : BytesView, size~ : Int32 = 64) -> Bytes {
  let h = Hasher::new(size~)
  h.write(msg)
  h.finish()
}
