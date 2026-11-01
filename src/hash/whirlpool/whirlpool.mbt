// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The Whirlpool S-box: the substitution of the W cipher, sixteen rows aligned
/// to the top nibble of the index.
let sbox : FixedArray[Byte] = [
  0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f,
  0x91, 0x52, 0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2,
  0x2e, 0x4b, 0xfe, 0x57, 0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9,
  0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85, 0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67,
  0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8, 0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17,
  0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33, 0x63, 0x02, 0xaa, 0x71,
  0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0, 0xe9, 0x0f,
  0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
  0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1,
  0x8d, 0x3d, 0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50,
  0x45, 0xf3, 0x30, 0xef, 0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c,
  0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a, 0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96,
  0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c, 0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5,
  0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04, 0x51, 0x99, 0x6d, 0x0d,
  0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb, 0x3c, 0x81,
  0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
  0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89,
  0x14, 0xe1, 0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4,
  0x28, 0x5c, 0xf8, 0x86,
]

///|
/// The ten round constants, `rc[1..=10]`; `rc[0]` is the zero that never fires
/// so the loop can index by round number directly.
let rc : FixedArray[UInt64] = [
  0x0000000000000000UL, 0x1823c6e887b8014fUL, 0x36a6d2f5796f9152UL, 0x60bc9b8ea30c7b35UL,
  0x1de0d7c22e4bfe57UL, 0x157737e59ff04adaUL, 0x58c9290ab1a06b85UL, 0xbd5d10f4cb3e0567UL,
  0xe427418ba77d95d8UL, 0xfbee7c66dd17479eUL, 0xca2dbf07ad5a8333UL,
]

///|
/// Multiply in GF(2^8) with Whirlpool's reduction polynomial x^8 + x^4 + x^3 +
/// x^2 + 1 (0x11D).
fn gmul(a : Int32, b : Int32) -> Int32 {
  let mut x = a
  let mut y = b
  let mut p = 0
  while y != 0 {
    if (y & 1) != 0 {
      p = p ^ x
    }
    x = ((x << 1) ^ (if (x & 0x80) != 0 { 0x1D } else { 0 })) & 0xFF
    y = y >> 1
  }
  p
}

///|
fn ror64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
/// `C0`, the S-box composed with the first column of the circulant MDS matrix
/// (coeffs 1, 1, 4, 1, 8, 5, 2, 9). `C1`..`C7` are its byte rotations.
fn build_c0() -> FixedArray[UInt64] {
  let t = FixedArray::make(256, 0UL)
  for x in 0..<256 {
    let v = sbox[x].to_int()
    let v2 = gmul(v, 2)
    let v4 = gmul(v, 4)
    let v5 = gmul(v, 5)
    let v8 = gmul(v, 8)
    let v9 = gmul(v, 9)
    t[x] = (v.to_uint64() << 56) |
      (v.to_uint64() << 48) |
      (v4.to_uint64() << 40) |
      (v.to_uint64() << 32) |
      (v8.to_uint64() << 24) |
      (v5.to_uint64() << 16) |
      (v2.to_uint64() << 8) |
      v9.to_uint64()
  }
  t
}

///|
/// The eight round tables `C0`..`C7`, each a one-byte-rotated copy of the last.
let tables : FixedArray[FixedArray[UInt64]] = {
  let c0 = build_c0()
  let all : FixedArray[FixedArray[UInt64]] = FixedArray::make(8, c0)
  all[0] = c0
  for k in 1..<8 {
    let prev = all[k - 1]
    let cur = FixedArray::make(256, 0UL)
    for x in 0..<256 {
      cur[x] = ror64(prev[x], 8)
    }
    all[k] = cur
  }
  all
}

///|
/// One output row of ρ = θ∘π∘γ: a byte from each of the eight (rotated) rows
/// of `b`, looked up and folded together. `a0`..`a7` are the row indices in the
/// rotation order the round fixes.
fn cdo(
  b : FixedArray[UInt64],
  a0 : Int32,
  a1 : Int32,
  a2 : Int32,
  a3 : Int32,
  a4 : Int32,
  a5 : Int32,
  a6 : Int32,
  a7 : Int32,
) -> UInt64 {
  tables[0][(b[a0] >> 56).to_int() & 0xFF] ^
  tables[1][(b[a1] >> 48).to_int() & 0xFF] ^
  tables[2][(b[a2] >> 40).to_int() & 0xFF] ^
  tables[3][(b[a3] >> 32).to_int() & 0xFF] ^
  tables[4][(b[a4] >> 24).to_int() & 0xFF] ^
  tables[5][(b[a5] >> 16).to_int() & 0xFF] ^
  tables[6][(b[a6] >> 8).to_int() & 0xFF] ^
  tables[7][b[a7].to_int() & 0xFF]
}

///|
/// The compression function: the W cipher keyed by the chaining value, run on
/// the message block, then folded back with Miyaguchi-Preneel
/// `H = H ⊕ state ⊕ block`.
fn transform(
  h : FixedArray[UInt64],
  block : FixedArray[Byte],
  off : Int32,
) -> Unit {
  let k = FixedArray::make(8, 0UL)
  let state = FixedArray::make(8, 0UL)
  let m = FixedArray::make(8, 0UL)
  for i in 0..<8 {
    let mut v = 0UL
    for b in 0..<8 {
      v = (v << 8) | (block[off + i * 8 + b].to_int() & 0xFF).to_uint64()
    }
    m[i] = v
  }
  for i in 0..<8 {
    k[i] = h[i]
    state[i] = m[i] ^ k[i]
  }
  let l = FixedArray::make(8, 0UL)
  for r in 1..<=10 {
    l[0] = cdo(k, 0, 7, 6, 5, 4, 3, 2, 1) ^ rc[r]
    l[1] = cdo(k, 1, 0, 7, 6, 5, 4, 3, 2)
    l[2] = cdo(k, 2, 1, 0, 7, 6, 5, 4, 3)
    l[3] = cdo(k, 3, 2, 1, 0, 7, 6, 5, 4)
    l[4] = cdo(k, 4, 3, 2, 1, 0, 7, 6, 5)
    l[5] = cdo(k, 5, 4, 3, 2, 1, 0, 7, 6)
    l[6] = cdo(k, 6, 5, 4, 3, 2, 1, 0, 7)
    l[7] = cdo(k, 7, 6, 5, 4, 3, 2, 1, 0)
    for i in 0..<8 {
      k[i] = l[i]
    }
    l[0] = cdo(state, 0, 7, 6, 5, 4, 3, 2, 1) ^ k[0]
    l[1] = cdo(state, 1, 0, 7, 6, 5, 4, 3, 2) ^ k[1]
    l[2] = cdo(state, 2, 1, 0, 7, 6, 5, 4, 3) ^ k[2]
    l[3] = cdo(state, 3, 2, 1, 0, 7, 6, 5, 4) ^ k[3]
    l[4] = cdo(state, 4, 3, 2, 1, 0, 7, 6, 5) ^ k[4]
    l[5] = cdo(state, 5, 4, 3, 2, 1, 0, 7, 6) ^ k[5]
    l[6] = cdo(state, 6, 5, 4, 3, 2, 1, 0, 7) ^ k[6]
    l[7] = cdo(state, 7, 6, 5, 4, 3, 2, 1, 0) ^ k[7]
    for i in 0..<8 {
      state[i] = l[i]
    }
  }
  for i in 0..<8 {
    h[i] = h[i] ^ state[i] ^ m[i]
  }
}

///|
/// A Whirlpool computation in progress.
struct Hasher {
  hash : FixedArray[UInt64]
  buffer : FixedArray[Byte]
  mut used : Int32
  mut n : UInt64
}

///|
/// A fresh state: sixty-four bytes of output, a sixty-four-byte block, and an
/// all-zero chaining value.
pub fn Hasher::new() -> Hasher {
  {
    hash: FixedArray::make(8, 0UL),
    buffer: FixedArray::make(64, b'\x00'),
    used: 0,
    n: 0UL,
  }
}

///|
pub extend Hasher with @spec.Hash::{block, finish, reset, size, write}

///|
pub impl @spec.Hash for Hasher with fn write(self : Hasher, msg : BytesView) -> Unit {
  self.n = self.n + msg.length().to_uint64()
  let mut at = 0
  while at < msg.length() {
    let room = 64 - self.used
    let left = msg.length() - at
    let take = if room < left { room } else { left }
    for i in 0..<take {
      self.buffer[self.used + i] = msg[at + i]
    }
    self.used = self.used + take
    at = at + take
    if self.used == 64 {
      transform(self.hash, self.buffer, 0)
      self.used = 0
    }
  }
}

///|
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  let h = FixedArray::make(8, 0UL)
  for i in 0..<8 {
    h[i] = self.hash[i]
  }
  let pad = FixedArray::make(128, b'\x00')
  for i in 0..<self.used {
    pad[i] = self.buffer[i]
  }
  pad[self.used] = b'\x80'
  // The last thirty-two bytes of a block hold the message bit length, so a
  // state that reached past byte thirty-two needs a second block.
  let total = if self.used < 32 { 64 } else { 128 }
  let bits = self.n * 8UL
  for i in 0..<8 {
    pad[total - 1 - i] = ((bits >> (i * 8)) & 0xFFUL).to_byte()
  }
  for off = 0; off < total; off = off + 64 {
    transform(h, pad, off)
  }
  let out : Array[Byte] = []
  for i in 0..<8 {
    for b = 7; b >= 0; b = b - 1 {
      out.push(((h[i] >> (b * 8)) & 0xFFUL).to_byte())
    }
  }
  Bytes::from_array(out)
}

///|
pub impl @spec.Hash for Hasher with fn reset(self : Hasher) -> Unit {
  for i in 0..<8 {
    self.hash[i] = 0UL
  }
  self.used = 0
  self.n = 0UL
}

///|
pub impl @spec.Hash for Hasher with fn size(self : Hasher) -> Int32 {
  ignore(self)
  64
}

///|
pub impl @spec.Hash for Hasher with fn block(self : Hasher) -> Int32 {
  ignore(self)
  64
}

///|
/// One whole message through Whirlpool, in one call.
pub fn hash(msg : BytesView) -> Bytes {
  let h = Hasher::new()
  h.write(msg)
  h.finish()
}
