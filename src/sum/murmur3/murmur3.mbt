// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which MurmurHash3.
///
/// The names are the ones the reference implementation uses: `x86_32` is the
/// 32-bit-output variant tuned for 32-bit machines, `x64_128` the 128-bit-output
/// variant for 64-bit machines. There is also an `x86_128` upstream, left out
/// because `x64_128` dominates it on the machines anyone runs today.
pub(all) enum Kind {
  ///
  /// `MurmurHash3_x86_32`: 4-byte blocks, one 32-bit lane, 4-byte digest.
  X86_32
  ///
  /// `MurmurHash3_x64_128`: 16-byte blocks, two coupled 64-bit lanes, 16-byte
  /// digest.
  X64_128
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The digest length in bytes.
pub fn Kind::size(self : Kind) -> Int32 {
  match self {
    X86_32 => 4
    X64_128 => 16
  }
}

///|
/// The block length: how many bytes one pass of the mixing loop consumes, and
/// what [`@spec.Hash::block`] reports.
pub fn Kind::block(self : Kind) -> Int32 {
  match self {
    X86_32 => 4
    X64_128 => 16
  }
}

///|
let low32 : UInt64 = 0xFFFF_FFFFUL

///|
let c32_1 : UInt64 = 0xCC9E_2D51UL

///|
let c32_2 : UInt64 = 0x1B87_3593UL

///|
let c64_1 : UInt64 = 0x87C3_7B91_1142_53D5UL

///|
let c64_2 : UInt64 = 0x4CF5_AD43_2745_937FUL

///|
fn turn32(x : UInt64, by : Int32) -> UInt64 {
  ((x << by) | (x >> (32 - by))) & low32
}

///|
fn turn64(x : UInt64, by : Int32) -> UInt64 {
  (x << by) | (x >> (64 - by))
}

///|
/// The little-endian word at `at`.
fn word32(buf : FixedArray[Byte], at : Int32) -> UInt64 {
  buf[at].to_uint().to_uint64() |
  (buf[at + 1].to_uint().to_uint64() << 8) |
  (buf[at + 2].to_uint().to_uint64() << 16) |
  (buf[at + 3].to_uint().to_uint64() << 24)
}

///|
fn word64(buf : FixedArray[Byte], at : Int32) -> UInt64 {
  word32(buf, at) | (word32(buf, at + 4) << 32)
}

///|
/// The 32-bit finaliser: xor-shift, multiply, xor-shift, multiply, xor-shift.
///
/// Without it the low bits of the digest barely move when the input changes in
/// one byte, and a hash table bucketing on `h & 0xFF` would degenerate.
fn mix32(h : UInt64) -> UInt64 {
  let mut h = h & low32
  h = h ^ (h >> 16)
  h = (h * 0x85EB_CA6BUL) & low32
  h = h ^ (h >> 13)
  h = (h * 0xC2B2_AE35UL) & low32
  h ^ (h >> 16)
}

///|
/// The 64-bit finaliser, the murmur/churn pair of constants.
fn mix64(k : UInt64) -> UInt64 {
  let mut k = k
  k = k ^ (k >> 33)
  k = k * 0xFF51_AFD7_ED55_8CCDUL
  k = k ^ (k >> 33)
  k = k * 0xC4CE_B9FE_1A85_EC53UL
  k ^ (k >> 33)
}

///|
/// A MurmurHash3 in progress.
///
/// Bytes are buffered until a whole block is present. That is not an optimisation
/// but a requirement: the trailing partial block is mixed differently from a
/// whole one, and its length is only known at the end.
pub struct Murmur3 {
  kind : Kind
  seed : UInt64
  mut h1 : UInt64
  mut h2 : UInt64
  buf : FixedArray[Byte]
  mut held : Int32
  mut total : UInt64
}

///|
/// Start a MurmurHash3. The seed is mixed in from the first byte, so two seeds
/// give unrelated digests of the same message.
pub fn Murmur3::new(kind~ : Kind = X64_128, seed~ : UInt64 = 0) -> Murmur3 {
  {
    kind,
    seed,
    h1: match kind {
      X86_32 => seed & low32
      X64_128 => seed
    },
    h2: match kind {
      X86_32 => 0UL
      X64_128 => seed
    },
    buf: FixedArray::make(16, b'\x00'),
    held: 0,
    total: 0UL,
  }
}

///|
/// One block — four words for the 32-bit kind, one 16-byte block for the 128-bit
/// one — mixed into the accumulators.
fn Murmur3::block_of(self : Murmur3) -> Unit {
  match self.kind {
    X86_32 =>
      for at in [0, 4, 8, 12] {
        let mut k = (word32(self.buf, at) * c32_1) & low32
        k = turn32(k, 15)
        k = (k * c32_2) & low32
        self.h1 = self.h1 ^ k
        self.h1 = turn32(self.h1, 13)
        self.h1 = (self.h1 * 5UL + 0xE654_6B64UL) & low32
      }
    X64_128 => {
      let mut k1 = word64(self.buf, 0) * c64_1
      k1 = turn64(k1, 31)
      k1 = k1 * c64_2
      self.h1 = self.h1 ^ k1
      self.h1 = turn64(self.h1, 27)
      self.h1 = self.h1 + self.h2
      self.h1 = self.h1 * 5UL + 0x52DC_E729UL
      let mut k2 = word64(self.buf, 8) * c64_2
      k2 = turn64(k2, 33)
      k2 = k2 * c64_1
      self.h2 = self.h2 ^ k2
      self.h2 = turn64(self.h2, 31)
      self.h2 = self.h2 + self.h1
      self.h2 = self.h2 * 5UL + 0x3849_5AB5UL
    }
  }
}

///|
/// Feed more bytes, a block at a time, holding back whatever does not fill one.
pub fn Murmur3::update(self : Murmur3, data : BytesView) -> Unit {
  self.total = self.total + data.length().to_uint64()
  let mut at = 0
  while at < data.length() {
    let room = 16 - self.held
    let left = data.length() - at
    let take = if left < room { left } else { room }
    for i in 0..<take {
      self.buf[self.held + i] = data[at + i]
    }
    self.held = self.held + take
    at = at + take
    if self.held == 16 {
      self.block_of()
      self.held = 0
    }
  }
}

///|
/// The digest as a pair of 64-bit halves, high half first. The 32-bit kind gives
/// `(digest, 0)`.
pub fn Murmur3::value(self : Murmur3) -> (UInt64, UInt64) {
  match self.kind {
    X86_32 => (self.tail32(), 0UL)
    X64_128 => self.tail64()
  }
}

///|
/// Whole words first, then the remaining bytes, then the finaliser and the
/// length.
fn Murmur3::tail32(self : Murmur3) -> UInt64 {
  let mut h = self.h1
  let mut at = 0
  while at + 4 <= self.held {
    let mut k = (word32(self.buf, at) * c32_1) & low32
    k = turn32(k, 15)
    k = (k * c32_2) & low32
    h = h ^ k
    h = turn32(h, 13)
    h = (h * 5UL + 0xE654_6B64UL) & low32
    at = at + 4
  }
  if at < self.held {
    let mut k = 0UL
    // Little-endian, so the last byte that is present is the most significant.
    for i in 0..<(self.held - at) {
      k = k | (self.buf[at + i].to_uint().to_uint64() << (8 * i))
    }
    k = (k * c32_1) & low32
    k = turn32(k, 15)
    k = (k * c32_2) & low32
    h = h ^ k
  }
  h = h ^ (self.total & low32)
  mix32(h)
}

///|
fn Murmur3::tail64(self : Murmur3) -> (UInt64, UInt64) {
  let mut h1 = self.h1
  let mut h2 = self.h2
  if self.held > 0 {
    let mut k1 = 0UL
    let mut k2 = 0UL
    for i in 0..<self.held {
      if i < 8 {
        k1 = k1 | (self.buf[i].to_uint().to_uint64() << (8 * i))
      } else {
        k2 = k2 | (self.buf[i].to_uint().to_uint64() << (8 * (i - 8)))
      }
    }
    // Only a tail longer than eight bytes has anything to mix into the second
    // lane, and a tail of exactly eight must not.
    if self.held > 8 {
      k2 = k2 * c64_2
      k2 = turn64(k2, 33)
      k2 = k2 * c64_1
      h2 = h2 ^ k2
    }
    k1 = k1 * c64_1
    k1 = turn64(k1, 31)
    k1 = k1 * c64_2
    h1 = h1 ^ k1
  }
  h1 = h1 ^ self.total
  h2 = h2 ^ self.total
  h1 = h1 + h2
  h2 = h2 + h1
  h1 = mix64(h1)
  h2 = mix64(h2)
  h1 = h1 + h2
  h2 = h2 + h1
  (h1, h2)
}

///|
/// The digest as four or sixteen bytes, each half most significant byte first,
/// in the order the algorithm produces them: `h1` then `h2`.
///
/// A MurmurHash3 has no canonical byte order — the reference writes the number,
/// not bytes — so this follows the rule the rest of mooncrypt follows and writes
/// the number big-endian. A format that stores the reference's little-endian
/// words should take [`Murmur3::value`] and write them itself.
fn Murmur3::bytes(self : Murmur3) -> Bytes {
  let (first, second) = self.value()
  let width = self.kind.size()
  let out : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  if width == 4 {
    for i in 0..<4 {
      out[i] = ((first >> ((3 - i) * 8)) & 0xFFUL).to_uint().to_byte()
    }
  } else {
    for i in 0..<8 {
      out[i] = ((first >> ((7 - i) * 8)) & 0xFFUL).to_uint().to_byte()
      out[8 + i] = ((second >> ((7 - i) * 8)) & 0xFFUL).to_uint().to_byte()
    }
  }
  Bytes::from_array(out)
}

///|
/// The MurmurHash3 of a whole message, as the 128-bit pair.
pub fn murmur3(
  data : BytesView,
  kind~ : Kind = X64_128,
  seed~ : UInt64 = 0,
) -> (UInt64, UInt64) {
  let state = Murmur3::new(kind~, seed~)
  state.update(data)
  state.value()
}

///|
pub extend Murmur3 with @spec.Hash::{write, finish, reset, size, block}

///|
pub impl @spec.Hash for Murmur3 with fn write(self, data) {
  self.update(data)
}

///|
pub impl @spec.Hash for Murmur3 with fn finish(self) {
  self.bytes()
}

///|
pub impl @spec.Hash for Murmur3 with fn reset(self) {
  self.h1 = match self.kind {
    X86_32 => self.seed & low32
    X64_128 => self.seed
  }
  self.h2 = match self.kind {
    X86_32 => 0UL
    X64_128 => self.seed
  }
  self.held = 0
  self.total = 0UL
}

///|
pub impl @spec.Hash for Murmur3 with fn size(self) {
  self.kind.size()
}

///|
pub impl @spec.Hash for Murmur3 with fn block(self) {
  self.kind.block()
}
