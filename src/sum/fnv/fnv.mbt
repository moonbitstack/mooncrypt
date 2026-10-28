// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which FNV.
///
/// Two widths and two orderings, and all four produce different answers. The
/// `_1a` variants xor the byte in before the multiply, which is what gives them
/// their better avalanche; the `_1` variants are the original and are kept
/// because existing formats use them.
pub(all) enum Kind {
  Fnv1_32
  Fnv1a_32
  Fnv1_64
  Fnv1a_64
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The offset basis: the value the digest starts at, which is the FNV prime
/// raised to a power rather than zero, so that an empty message still has a
/// digest.
fn Kind::basis(self : Kind) -> UInt64 {
  match self {
    Fnv1_32 | Fnv1a_32 => 0x811C9DC5UL
    Fnv1_64 | Fnv1a_64 => 0xCBF29CE484222325UL
  }
}

///|
/// The FNV prime: 2^24 + 2^8 + 0x93 for 32 bits, 2^40 + 2^8 + 0xB3 for 64.
fn Kind::prime(self : Kind) -> UInt64 {
  match self {
    Fnv1_32 | Fnv1a_32 => 0x01000193UL
    Fnv1_64 | Fnv1a_64 => 0x00000100000001B3UL
  }
}

///|
/// How many bytes the digest occupies.
pub fn Kind::size(self : Kind) -> Int32 {
  match self {
    Fnv1_32 | Fnv1a_32 => 4
    Fnv1_64 | Fnv1a_64 => 8
  }
}

///|
/// The stride, which for FNV is one byte.
pub fn Kind::block(self : Kind) -> Int32 {
  let _ = self
  1
}

///|
/// Whether this kind xors before it multiplies.
fn Kind::first(self : Kind) -> Bool {
  match self {
    Fnv1_32 | Fnv1_64 => false
    Fnv1a_32 | Fnv1a_64 => true
  }
}

///|
/// An FNV digest in progress.
///
/// The state is always 64 bits wide and only the low half is used for the 32-bit
/// kinds, because the multiply has to be truncated to the width anyway and
/// keeping one register is simpler than two.
pub struct Fnv {
  kind : Kind
  mut state : UInt64
}

///|
/// Start an FNV digest. The default is FNV-1a at 64 bits, which is the one new
/// code should use.
pub fn Fnv::new(kind~ : Kind = Fnv1a_64) -> Fnv {
  { kind, state: kind.basis(), }
}

///|
/// Feed more bytes.
pub fn Fnv::update(self : Fnv, data : BytesView) -> Unit {
  let prime = self.kind.prime()
  let size32 = self.kind.size() == 4
  let mut hash = self.state
  for i in 0..<data.length() {
    let byte = data[i].to_uint64()
    if self.kind.first() {
      hash = hash ^ byte
      hash = hash * prime
    } else {
      hash = hash * prime
      hash = hash ^ byte
    }
    if size32 {
      hash = hash & 0xFFFF_FFFFUL
    }
  }
  self.state = hash
}

///|
/// The digest of everything fed so far, as the number the formats that write it
/// store.
pub fn Fnv::value(self : Fnv) -> UInt64 {
  if self.kind.size() == 4 {
    self.state & 0xFFFF_FFFFUL
  } else {
    self.state
  }
}

///|
/// The digest as bytes, most significant first.
fn Fnv::bytes(self : Fnv) -> Bytes {
  let v = self.value()
  let width = self.kind.size()
  let out : Array[Byte] = []
  for i in 0..<width {
    let shift = (width - 1 - i) * 8
    out.push(((v >> shift) & 0xFFUL).to_byte())
  }
  Bytes::from_array(out)
}

///|
/// The FNV digest of a whole message.
pub fn fnv(data : BytesView, kind~ : Kind = Fnv1a_64) -> UInt64 {
  let state = Fnv::new(kind~)
  state.update(data)
  state.value()
}

///|
pub extend Fnv with @spec.Hash::{write, finish, reset, size, block}

///|
pub impl @spec.Hash for Fnv with fn write(self, data) {
  self.update(data)
}

///|
pub impl @spec.Hash for Fnv with fn finish(self) {
  self.bytes()
}

///|
pub impl @spec.Hash for Fnv with fn reset(self) {
  self.state = self.kind.basis()
}

///|
pub impl @spec.Hash for Fnv with fn size(self) {
  self.kind.size()
}

///|
pub impl @spec.Hash for Fnv with fn block(self) {
  self.kind.block()
}
