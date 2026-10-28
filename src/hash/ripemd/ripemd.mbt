// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A RIPEMD-160 computation in progress.
///
/// RIPEMD-160 is not broken, but it is old: it was designed in 1996 for an
/// open European alternative to MD4 and SHA-1, and it has held up better than
/// either. It is still the slower choice, and new work should use SHA-2.
struct Hasher {
  h : FixedArray[UInt32]
  buf : FixedArray[Byte]
  mut used : Int32
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
pub impl @spec.Hash for Hasher with fn size(_ : Hasher) -> Int32 {
  20
}

///|
pub impl @spec.Hash for Hasher with fn block(_ : Hasher) -> Int32 {
  64
}

///|
/// The five chaining words start at the same values MD4 and MD5 use, which is not
/// a coincidence: the compression function was inherited and only the round
/// structure changed.
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
      compress(self.h, self.buf, 0)
      self.used = 0
    }
  }
}

///|
/// The padding is MD4's — a one bit, zeroes, and the length in bits as a
/// little-endian sixty-four bit number — and the digest is emitted the same way,
/// five words least significant byte first.
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  let h : FixedArray[UInt32] = FixedArray::make(5, 0U)
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
    pad[total - 8 + i] = ((bits >> (i * 8)) & 0xFFUL).to_byte()
  }
  for off = 0; off < total; off = off + 64 {
    compress(h, pad, off)
  }
  let out : Array[Byte] = []
  for i in 0..<5 {
    for shift in 0..<4 {
      out.push(((h[i] >> (shift * 8)) & 0xFFU).to_byte())
    }
  }
  Bytes::from_array(out)
}

///|
fn rotl(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
fn le32(b : FixedArray[Byte], at : Int32) -> UInt32 {
  b[at].to_uint() |
  (b[at + 1].to_uint() << 8) |
  (b[at + 2].to_uint() << 16) |
  (b[at + 3].to_uint() << 24)
}

///|
/// Bitwise complement, spelled out because the language has no `~` and because
/// `x ^ 0xFFFFFFFF` is what it means on an unsigned word anyway.
fn not(x : UInt32) -> UInt32 {
  x ^ 0xFFFFFFFFU
}

///|
/// The nonlinear function of a round group: five of them, one per sixteen-round
/// stretch, and the two lines use them in opposite orders.
fn nonlinear(j : Int32, x : UInt32, y : UInt32, z : UInt32) -> UInt32 {
  if j < 16 {
    x ^ y ^ z
  } else if j < 32 {
    (x & y) | (not(x) & z)
  } else if j < 48 {
    (x | not(y)) ^ z
  } else if j < 64 {
    (x & z) | (y & not(z))
  } else {
    x ^ (y | not(z))
  }
}

///|
/// The compression function: eighty rounds, two lines, and a final mix that takes
/// two words from each line and one from the previous state.
///
/// The rotation by ten of `c` in every round is what stops a single-bit change
/// from staying in the same word; the swap of `d` and `e` at the end of each
/// round is what makes the five words cycle through the function.
fn compress(
  h : FixedArray[UInt32],
  block : FixedArray[Byte],
  at : Int32,
) -> Unit {
  let x : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i in 0..<16 {
    x[i] = le32(block, at + 4 * i)
  }
  let mut al = h[0]
  let mut bl = h[1]
  let mut cl = h[2]
  let mut dl = h[3]
  let mut el = h[4]
  let mut ar = h[0]
  let mut br = h[1]
  let mut cr = h[2]
  let mut dr = h[3]
  let mut er = h[4]
  for j in 0..<80 {
    let group = j / 16
    let mut t = rotl(
        al + nonlinear(j, bl, cl, dl) + x[order[j]] + left_constant[group],
        shifts[j],
      ) +
      el
    al = el
    el = dl
    dl = rotl(cl, 10)
    cl = bl
    bl = t
    // The right line runs the same rounds with the constants and the nonlinear
    // functions in reverse order, which is what keeps the two lines from ever
    // agreeing on an intermediate value.
    t = rotl(
        ar +
        nonlinear(79 - j, br, cr, dr) +
        x[right_order[j]] +
        right_constant[group],
        right_shifts[j],
      ) +
      er
    ar = er
    er = dr
    dr = rotl(cr, 10)
    cr = br
    br = t
  }
  // Each output word takes one from each line, and the previous state word is
  // shifted along — so a change in either line reaches every output word.
  let next = [
    h[1] + cl + dr,
    h[2] + dl + er,
    h[3] + el + ar,
    h[4] + al + br,
    h[0] + bl + cr,
  ]
  for i in 0..<5 {
    h[i] = next[i]
  }
}

///|
/// Which of the sixteen message words each round of the left line uses.
let order : FixedArray[Int32] = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
   7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, //
   3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, //
   1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, //
   4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]

///|
/// And the right line's, which shares no stretch with it.
let right_order : FixedArray[Int32] = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, //
   6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, //
   15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, //
   8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, //
   12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]

///|
/// How far each round rotates, left line.
let shifts : FixedArray[Int32] = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, //
   7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, //
   11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, //
   11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, //
   9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]

///|
/// And right line.
let right_shifts : FixedArray[Int32] = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, //
   9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, //
   9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, //
   15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, //
   8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]

///|
/// The additive constants of the left line, one per round group.
let left_constant : FixedArray[UInt32] = [
  0x00000000U, 0x5A827999U, 0x6ED9EBA1U, 0x8F1BBCDCU, 0xA953FD4EU,
]

///|
/// And of the right line, which are the left ones' mirror images: the right line
/// starts where the left one ends.
let right_constant : FixedArray[UInt32] = [
  0x50A28BE6U, 0x5C4DD124U, 0x6D703EF3U, 0x7A6D76E9U, 0x00000000U,
]
