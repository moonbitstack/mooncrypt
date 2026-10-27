// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The tag length in bytes.
pub let tag : Int32 = 16

///|
/// A Poly1305 computation under one key, fed in pieces. The accumulator is held
/// in five 26-bit limbs so every product fits in 64 bits.
pub struct Poly1305 {
  priv r : FixedArray[UInt64]
  priv s : FixedArray[UInt64]
  priv pad : FixedArray[UInt64]
  priv h : FixedArray[UInt64]
  priv buf : FixedArray[Byte]
  priv mut used : Int32
}

///|
let mask : UInt64 = 0x3ffffff

///|
fn le32(b : BytesView, at : Int32) -> UInt64 {
  b[at].to_uint64() |
  (b[at + 1].to_uint64() << 8) |
  (b[at + 2].to_uint64() << 16) |
  (b[at + 3].to_uint64() << 24)
}

///|
/// A computation under the 32-byte one-time `key`: `r` (clamped) then `s`.
pub fn Poly1305::new(key : BytesView) -> Poly1305 raise @spec.Broken {
  guard key.length() == 32 else { raise Size(want=32, got=key.length()) }
  let r : FixedArray[UInt64] = [
    le32(key, 0) & 0x3ffffff,
    (le32(key, 3) >> 2) & 0x3ffff03,
    (le32(key, 6) >> 4) & 0x3ffc0ff,
    (le32(key, 9) >> 6) & 0x3f03fff,
    (le32(key, 12) >> 8) & 0x00fffff,
  ]
  {
    r,
    s: FixedArray::makei(5, i => r[i] * 5),
    pad: FixedArray::makei(4, i => le32(key, 16 + 4 * i)),
    h: FixedArray::make(5, 0),
    buf: FixedArray::make(16, b'\x00'),
    used: 0,
  }
}

///|
/// Fold one 16-byte block into the accumulator; `hibit` is 2^128 for a full
/// block and 0 for the padded last one, which carries its own 1 byte.
fn Poly1305::block(self : Poly1305, m : BytesView, hibit : UInt64) -> Unit {
  let h = self.h
  let r = self.r
  let s = self.s
  h[0] += le32(m, 0) & mask
  h[1] += (le32(m, 3) >> 2) & mask
  h[2] += (le32(m, 6) >> 4) & mask
  h[3] += (le32(m, 9) >> 6) & mask
  h[4] += (le32(m, 12) >> 8) | hibit
  let d0 = h[0] * r[0] + h[1] * s[4] + h[2] * s[3] + h[3] * s[2] + h[4] * s[1]
  let d1 = h[0] * r[1] + h[1] * r[0] + h[2] * s[4] + h[3] * s[3] + h[4] * s[2]
  let d2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s[4] + h[4] * s[3]
  let d3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s[4]
  let d4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0]
  let mut c = d0 >> 26
  h[0] = d0 & mask
  let d1 = d1 + c
  c = d1 >> 26
  h[1] = d1 & mask
  let d2 = d2 + c
  c = d2 >> 26
  h[2] = d2 & mask
  let d3 = d3 + c
  c = d3 >> 26
  h[3] = d3 & mask
  let d4 = d4 + c
  c = d4 >> 26
  h[4] = d4 & mask
  h[0] += c * 5
  c = h[0] >> 26
  h[0] = h[0] & mask
  h[1] += c
}

///|
pub fn Poly1305::write(self : Poly1305, data : BytesView) -> Unit {
  let mut at = 0
  if self.used > 0 {
    while self.used < 16 && at < data.length() {
      self.buf[self.used] = data[at]
      self.used += 1
      at += 1
    }
    if self.used < 16 {
      return
    }
    self.block(Bytes::from_array(self.buf)[:], 1UL << 24)
    self.used = 0
  }
  while data.length() - at >= 16 {
    self.block(data[at:at + 16], 1UL << 24)
    at += 16
  }
  while at < data.length() {
    self.buf[self.used] = data[at]
    self.used += 1
    at += 1
  }
}

///|
/// The tag. The computation is spent: a one-time key signs one message.
pub fn Poly1305::finish(self : Poly1305) -> Bytes {
  if self.used > 0 {
    let last = Array::make(16, b'\x00')
    for i in 0..<self.used {
      last[i] = self.buf[i]
    }
    last[self.used] = b'\x01'
    self.block(Bytes::from_array(last)[:], 0)
    self.used = 0
  }
  let h = self.h
  let mut c = h[1] >> 26
  h[1] = h[1] & mask
  h[2] += c
  c = h[2] >> 26
  h[2] = h[2] & mask
  h[3] += c
  c = h[3] >> 26
  h[3] = h[3] & mask
  h[4] += c
  c = h[4] >> 26
  h[4] = h[4] & mask
  h[0] += c * 5
  c = h[0] >> 26
  h[0] = h[0] & mask
  h[1] += c
  // h + 5 - 2^130: when it does not borrow, h was at least p and g is h mod p.
  let g = FixedArray::make(5, 0UL)
  g[0] = h[0] + 5
  c = g[0] >> 26
  g[0] = g[0] & mask
  for i in 1..<4 {
    g[i] = h[i] + c
    c = g[i] >> 26
    g[i] = g[i] & mask
  }
  g[4] = h[4] + c - (1UL << 26)
  // All ones when g[4] did not borrow, so g is taken; zero keeps h. No branch.
  let take = (g[4] >> 63) - 1
  for i in 0..<5 {
    h[i] = (h[i] & take.lnot()) | (g[i] & take)
  }
  let w0 = (h[0] | (h[1] << 26)) & 0xffffffff
  let w1 = ((h[1] >> 6) | (h[2] << 20)) & 0xffffffff
  let w2 = ((h[2] >> 12) | (h[3] << 14)) & 0xffffffff
  let w3 = ((h[3] >> 18) | (h[4] << 8)) & 0xffffffff
  let mut f = w0 + self.pad[0]
  let out = Array::make(16, b'\x00')
  let words = [0UL, 0, 0, 0]
  words[0] = f & 0xffffffff
  f = w1 + self.pad[1] + (f >> 32)
  words[1] = f & 0xffffffff
  f = w2 + self.pad[2] + (f >> 32)
  words[2] = f & 0xffffffff
  f = w3 + self.pad[3] + (f >> 32)
  words[3] = f & 0xffffffff
  for i in 0..<16 {
    out[i] = (words[i / 4] >> (8 * (i % 4))).to_byte()
  }
  Bytes::from_array(out)
}

///|
pub fn Poly1305::size(_ : Poly1305) -> Int32 {
  tag
}

///|
pub impl @spec.Mac for Poly1305 with fn write(self, data) {
  Poly1305::write(self, data)
}

///|
pub impl @spec.Mac for Poly1305 with fn finish(self) {
  Poly1305::finish(self)
}

///|
pub impl @spec.Mac for Poly1305 with fn size(self) {
  Poly1305::size(self)
}

///|
/// The tag of `msg` under the one-time `key`.
pub fn mac(key : BytesView, msg : BytesView) -> Bytes raise @spec.Broken {
  let p = Poly1305::new(key)
  p.write(msg)
  p.finish()
}
