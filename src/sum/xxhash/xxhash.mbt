// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which xxHash.
///
/// The two are not a truncation of each other: the 64-bit one multiplies 64-bit
/// words and rotates by different amounts, so XXH64 of a message says nothing
/// about its XXH32.
pub(all) enum Kind {
  ///
  /// XXH32: four 32-bit lanes over 16-byte stripes.
  Xxh32
  ///
  /// XXH64: four 64-bit lanes over 32-byte stripes.
  Xxh64
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The digest length in bytes.
pub fn Kind::size(self : Kind) -> Int32 {
  match self {
    Xxh32 => 4
    Xxh64 => 8
  }
}

///|
/// The stripe length: how many bytes the four lanes consume before the state
/// moves to the next stripe, and what [`@spec.Hash::block`] reports.
pub fn Kind::block(self : Kind) -> Int32 {
  match self {
    Xxh32 => 16
    Xxh64 => 32
  }
}

///|
let prime32_1 : UInt64 = 0x9E37_79B1UL

///|
let prime32_2 : UInt64 = 0x85EB_CA77UL

///|
let prime32_3 : UInt64 = 0xC2B2_AE3DUL

///|
let prime32_4 : UInt64 = 0x27D4_EB2FUL

///|
let prime32_5 : UInt64 = 0x1656_67B1UL

///|
let prime64_1 : UInt64 = 0x9E37_79B1_85EB_CA87UL

///|
let prime64_2 : UInt64 = 0xC2B2_AE3D_27D4_EB4FUL

///|
let prime64_3 : UInt64 = 0x1656_67B1_9E37_79F9UL

///|
let prime64_4 : UInt64 = 0x85EB_CA77_C2B2_AE63UL

///|
let prime64_5 : UInt64 = 0x27D4_EB2F_1656_67C5UL

///|
/// Everything in the 32-bit path is masked back to 32 bits, including after the
/// rotates, so storing the lanes in 64-bit fields costs nothing but keeps one
/// struct for both kinds.
let low32 : UInt64 = 0xFFFF_FFFFUL

///|
fn turn32(x : UInt64, by : Int32) -> UInt64 {
  ((x << by) | (x >> (32 - by))) & low32
}

///|
fn turn64(x : UInt64, by : Int32) -> UInt64 {
  (x << by) | (x >> (64 - by))
}

///|
/// The little-endian word at `at`. Every multiply in xxHash reads its input this
/// way, so the digest of a message is the same on either endianness.
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
/// An xxHash in progress.
///
/// Bytes are buffered until a whole stripe is present, because a stripe is the
/// smallest unit the lanes can consume: a partial stripe has to be re-read from
/// the start at [`finish`](#finish), so it cannot be folded in early.
pub struct Xxh {
  kind : Kind
  seed : UInt64
  mut v1 : UInt64
  mut v2 : UInt64
  mut v3 : UInt64
  mut v4 : UInt64
  ///
  /// Whether any stripe has been consumed. Until one has, the accumulators hold
  /// nothing and the final value starts from the seed instead.
  mut started : Bool
  buf : FixedArray[Byte]
  mut held : Int32
  mut total : UInt64
}

///|
/// Start an xxHash. The seed is zero by default, which is what a plain checksum
/// wants; a hash table passes its own so that the same keys land in a different
/// order.
pub fn Xxh::new(kind~ : Kind = Xxh64, seed~ : UInt64 = 0) -> Xxh {
  let state = {
    kind,
    seed,
    v1: 0UL,
    v2: 0UL,
    v3: 0UL,
    v4: 0UL,
    started: false,
    buf: FixedArray::make(32, b'\x00'),
    held: 0,
    total: 0UL,
  }
  state.restart()
  state
}

///|
/// Put the four lanes at their seeded starting values.
///
/// This is deliberately separate from [`restart`](#restart): the first stripe of
/// a message seeds the lanes too, and at that point the byte count and the buffer
/// are already meaningful and must not be cleared.
fn Xxh::seed_lanes(self : Xxh) -> Unit {
  match self.kind {
    Xxh32 => {
      self.v1 = (self.seed + prime32_1 + prime32_2) & low32
      self.v2 = (self.seed + prime32_2) & low32
      self.v3 = self.seed & low32
      self.v4 = (self.seed - prime32_1) & low32
    }
    Xxh64 => {
      self.v1 = self.seed + prime64_1 + prime64_2
      self.v2 = self.seed + prime64_2
      self.v3 = self.seed
      self.v4 = self.seed - prime64_1
    }
  }
}

///|
/// Start a new message: seeded lanes, nothing buffered, nothing counted.
fn Xxh::restart(self : Xxh) -> Unit {
  self.seed_lanes()
  self.started = false
  self.held = 0
  self.total = 0UL
}

///|
/// One full stripe: each lane takes its word, adds it to a product, rotates and
/// multiplies again. The lanes never talk to each other, which is what lets the
/// loop be four independent chains of dependent operations.
fn Xxh::stripe(self : Xxh) -> Unit {
  if !self.started {
    self.seed_lanes()
    self.started = true
  }
  match self.kind {
    Xxh32 => {
      self.v1 = (
          turn32((self.v1 + word32(self.buf, 0) * prime32_2) & low32, 13) *
          prime32_1
        ) &
        low32
      self.v2 = (
          turn32((self.v2 + word32(self.buf, 4) * prime32_2) & low32, 13) *
          prime32_1
        ) &
        low32
      self.v3 = (
          turn32((self.v3 + word32(self.buf, 8) * prime32_2) & low32, 13) *
          prime32_1
        ) &
        low32
      self.v4 = (
          turn32((self.v4 + word32(self.buf, 12) * prime32_2) & low32, 13) *
          prime32_1
        ) &
        low32
    }
    Xxh64 => {
      self.v1 = turn64(self.v1 + word64(self.buf, 0) * prime64_2, 31) *
        prime64_1
      self.v2 = turn64(self.v2 + word64(self.buf, 8) * prime64_2, 31) *
        prime64_1
      self.v3 = turn64(self.v3 + word64(self.buf, 16) * prime64_2, 31) *
        prime64_1
      self.v4 = turn64(self.v4 + word64(self.buf, 24) * prime64_2, 31) *
        prime64_1
    }
  }
}

///|
/// Feed more bytes, a stripe at a time, holding back whatever does not fill one.
pub fn Xxh::update(self : Xxh, data : BytesView) -> Unit {
  let width = self.kind.block()
  self.total = self.total + data.length().to_uint64()
  let mut at = 0
  while at < data.length() {
    let room = width - self.held
    let left = data.length() - at
    let take = if left < room { left } else { room }
    for i in 0..<take {
      self.buf[self.held + i] = data[at + i]
    }
    self.held = self.held + take
    at = at + take
    if self.held == width {
      self.stripe()
      self.held = 0
    }
  }
}

///|
/// The accumulator after the stripes, before the tail: the four lanes merged,
/// or — for a message shorter than one stripe — the seed alone plus a constant.
fn Xxh::merge(self : Xxh) -> UInt64 {
  match self.kind {
    Xxh32 =>
      if self.started {
        (
          turn32(self.v1, 1) +
          turn32(self.v2, 7) +
          turn32(self.v3, 12) +
          turn32(self.v4, 18)
        ) &
        low32
      } else {
        (self.seed + prime32_5) & low32
      }
    Xxh64 =>
      if self.started {
        let mut h = turn64(self.v1, 1) +
          turn64(self.v2, 7) +
          turn64(self.v3, 12) +
          turn64(self.v4, 18)
        for v in [self.v1, self.v2, self.v3, self.v4] {
          h = h ^ (turn64(v * prime64_2, 31) * prime64_1)
          h = h * prime64_1 + prime64_4
        }
        h
      } else {
        self.seed + prime64_5
      }
  }
}

///|
/// The digest as a number.
///
/// The buffered partial stripe is folded in here: whole 4- or 8-byte words first,
/// then the remaining bytes one at a time, then the avalanche.
pub fn Xxh::value(self : Xxh) -> UInt64 {
  match self.kind {
    Xxh32 => self.tail32()
    Xxh64 => self.tail64()
  }
}

///|
fn Xxh::tail32(self : Xxh) -> UInt64 {
  let mut h = (self.merge() + self.total) & low32
  let mut at = 0
  while at + 4 <= self.held {
    h = (h + word32(self.buf, at) * prime32_3) & low32
    h = (turn32(h, 17) * prime32_4) & low32
    at = at + 4
  }
  while at < self.held {
    h = (h + self.buf[at].to_uint().to_uint64() * prime32_5) & low32
    h = (turn32(h, 11) * prime32_1) & low32
    at = at + 1
  }
  h = h ^ (h >> 15)
  h = (h * prime32_2) & low32
  h = h ^ (h >> 13)
  h = (h * prime32_3) & low32
  h ^ (h >> 16)
}

///|
fn Xxh::tail64(self : Xxh) -> UInt64 {
  let mut h = self.merge() + self.total
  let mut at = 0
  while at + 8 <= self.held {
    h = h ^ (turn64(word64(self.buf, at) * prime64_2, 31) * prime64_1)
    h = turn64(h, 27) * prime64_1 + prime64_4
    at = at + 8
  }
  if at + 4 <= self.held {
    h = h ^ (word32(self.buf, at) * prime64_1)
    h = turn64(h, 23) * prime64_2 + prime64_3
    at = at + 4
  }
  while at < self.held {
    h = h ^ (self.buf[at].to_uint().to_uint64() * prime64_5)
    h = turn64(h, 11) * prime64_1
    at = at + 1
  }
  h = h ^ (h >> 33)
  h = h * prime64_2
  h = h ^ (h >> 29)
  h = h * prime64_3
  h ^ (h >> 32)
}

///|
/// The digest as four or eight bytes, most significant first, which is how every
/// other digest in mooncrypt is written.
fn Xxh::bytes(self : Xxh) -> Bytes {
  let v = self.value()
  let width = self.kind.size()
  let out : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  for i in 0..<width {
    let shift = (width - 1 - i) * 8
    out[i] = ((v >> shift) & 0xFFUL).to_uint().to_byte()
  }
  Bytes::from_array(out)
}

///|
/// The xxHash of a whole message.
pub fn xxhash(
  data : BytesView,
  kind~ : Kind = Xxh64,
  seed~ : UInt64 = 0,
) -> UInt64 {
  let state = Xxh::new(kind~, seed~)
  state.update(data)
  state.value()
}

///|
pub extend Xxh with @spec.Hash::{write, finish, reset, size, block}

///|
pub impl @spec.Hash for Xxh with fn write(self, data) {
  self.update(data)
}

///|
pub impl @spec.Hash for Xxh with fn finish(self) {
  self.bytes()
}

///|
/// Back to the seed, ready for another message. The seed survives, because a
/// state created with one is that seed's state.
pub impl @spec.Hash for Xxh with fn reset(self) {
  self.restart()
}

///|
pub impl @spec.Hash for Xxh with fn size(self) {
  self.kind.size()
}

///|
pub impl @spec.Hash for Xxh with fn block(self) {
  self.kind.block()
}
