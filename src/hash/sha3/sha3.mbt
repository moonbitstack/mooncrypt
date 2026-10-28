// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which member of the Keccak family.
///
/// The four SHA-3 lengths and the two SHAKE lengths are the same permutation
/// with a different rate — a wider rate means fewer rounds of work per byte, so
/// SHAKE128 is the fastest and the weakest, and the numbers in the names are the
/// security level in bits, not the output size.
pub(all) enum Kind {
  Sha3_224
  Sha3_256
  Sha3_384
  Sha3_512
  Shake128
  Shake256
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The digest length in bytes. SHAKE has no fixed length; the value here is the
/// conventional default output, 32 or 64 bytes, used when a caller asks for a
/// `Hash` rather than a stream.
pub fn Kind::size(self : Kind) -> Int32 {
  match self {
    Sha3_224 => 28
    Sha3_256 => 32
    Sha3_384 => 48
    Sha3_512 => 64
    Shake128 => 32
    Shake256 => 64
  }
}

///|
/// The rate in bytes: how much of the 200-byte state a block of message fills
/// before the permutation runs. The rest is capacity, and the security level is
/// half of it.
pub fn Kind::block(self : Kind) -> Int32 {
  match self {
    Sha3_224 => 144
    Sha3_256 => 136
    Sha3_384 => 104
    Sha3_512 => 72
    Shake128 => 168
    Shake256 => 136
  }
}

///|
/// The domain-separation suffix (FIPS 202 §6.2, SP 800-185 §3.3): `0x06` for a
/// fixed-length digest, `0x1f` for an extendable one, `0x04` for cSHAKE. It is
/// what keeps a SHA3-256 digest from ever equalling the first 32 bytes of a
/// SHAKE256 output over the same message.
fn Kind::suffix(self : Kind) -> Byte {
  match self {
    Shake128 | Shake256 => b'\x1f'
    _ => b'\x06'
  }
}

///|
let rounds : FixedArray[UInt64] = [
  0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
  0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
  0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
  0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
  0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
  0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
]

///|
/// The rotation offset of lane `x + 5y` (FIPS 202 §3.2.2).
let rotations : FixedArray[Int32] = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18,
  2, 61, 56, 14,
]

///|
fn rotl(x : UInt64, n : Int32) -> UInt64 {
  if n == 0 {
    x
  } else {
    (x << n) | (x >> (64 - n))
  }
}

///|
/// Keccak-f[1600] (FIPS 202 §3.3): twenty-four rounds of five steps over a
/// 5×5 array of 64-bit lanes, held flat in lane order `x + 5y`.
fn permute(st : FixedArray[UInt64]) -> Unit {
  let c : FixedArray[UInt64] = FixedArray::make(5, 0UL)
  let b : FixedArray[UInt64] = FixedArray::make(25, 0UL)
  for round in 0..<24 {
    // θ
    for x in 0..<5 {
      c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20]
    }
    for x in 0..<5 {
      let d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
      for y in 0..<5 {
        st[x + 5 * y] = st[x + 5 * y] ^ d
      }
    }
    // ρ and π together: a lane moves to a column that depends on where it was.
    for x in 0..<5 {
      for y in 0..<5 {
        let at = x + 5 * y
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(st[at], rotations[at])
      }
    }
    // χ
    for y in 0..<5 {
      for x in 0..<5 {
        st[x + 5 * y] = b[x + 5 * y] ^
          (b[(x + 1) % 5 + 5 * y].lnot() & b[(x + 2) % 5 + 5 * y])
      }
    }
    // ι
    st[0] = st[0] ^ rounds[round]
  }
}

///|
/// A sponge: the state, how much of the current block has been filled, and
/// where in the squeeze the reader is.
priv struct Sponge {
  st : FixedArray[UInt64]
  rate : Int32
  suffix : Byte
  mut at : Int32
  mut padded : Bool
}

///|
fn Sponge::new(rate : Int32, suffix : Byte) -> Sponge {
  { st: FixedArray::make(25, 0UL), rate, suffix, at: 0, padded: false, }
}

///|
fn Sponge::copy(self : Sponge) -> Sponge {
  let st : FixedArray[UInt64] = FixedArray::make(25, 0UL)
  for i in 0..<25 {
    st[i] = self.st[i]
  }
  {
    st,
    rate: self.rate,
    suffix: self.suffix,
    at: self.at,
    padded: self.padded,
  }
}

///|
/// XOR one byte into the state. A lane is little-endian, so byte `i` of the
/// message lands in byte `i % 8` of lane `i / 8`.
fn Sponge::mix(self : Sponge, b : Byte) -> Unit {
  let shift = self.at % 8 * 8
  self.st[self.at / 8] = self.st[self.at / 8] ^
    (b.to_int().to_uint64() << shift)
}

///|
fn Sponge::absorb(self : Sponge, msg : BytesView) -> Unit {
  guard !self.padded else { abort("sha3: absorb after the message was closed") }
  for i in 0..<msg.length() {
    self.mix(msg[i])
    self.at += 1
    if self.at == self.rate {
      permute(self.st)
      self.at = 0
    }
  }
}

///|
/// The padded, closed state: the suffix and the final `0x80` share a byte when
/// the message ends exactly one byte short of the rate, which is why they are
/// XORed rather than assigned.
fn Sponge::close(self : Sponge) -> Unit {
  if !self.padded {
    self.mix(self.suffix)
    self.st[(self.rate - 1) / 8] = self.st[(self.rate - 1) / 8] ^
      (0x80UL << ((self.rate - 1) % 8 * 8))
    self.at = self.rate
    self.padded = true
  }
}

///|
fn Sponge::squeeze(self : Sponge, n : Int32) -> Bytes {
  self.close()
  let out : Array[Byte] = []
  for _ in 0..<n {
    if self.at == self.rate {
      permute(self.st)
      self.at = 0
    }
    let lane = self.st[self.at / 8]
    let shift = self.at % 8 * 8
    out.push(((lane >> shift) & 0xFFUL).to_byte())
    self.at += 1
  }
  Bytes::from_array(out)
}

///|
/// A SHA-3 computation in progress.
struct Hasher {
  kind : Kind
  sponge : Sponge
}

///|
/// A fresh hasher, SHA3-256 unless another member is named.
pub fn Hasher::new(kind~ : Kind = Sha3_256) -> Hasher {
  { kind, sponge: Sponge::new(kind.block(), kind.suffix()), }
}

///|
/// Hash one whole message.
pub fn hash(msg : BytesView, kind~ : Kind = Sha3_256) -> Bytes {
  let h = Hasher::new(kind~)
  h.write(msg)
  h.finish()
}

///|
pub extend Hasher with @spec.Hash::{block, finish, reset, size, write}

///|
pub impl @spec.Hash for Hasher with fn write(self : Hasher, msg : BytesView) -> Unit {
  self.sponge.absorb(msg)
}

///|
/// Reads on a copy of the state, so a caller may keep writing afterwards — the
/// same rule SHA-2 follows here.
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  self.sponge.copy().squeeze(self.kind.size())
}

///|
pub impl @spec.Hash for Hasher with fn reset(self : Hasher) -> Unit {
  for i in 0..<25 {
    self.sponge.st[i] = 0UL
  }
  self.sponge.at = 0
  self.sponge.padded = false
}

///|
pub impl @spec.Hash for Hasher with fn size(self : Hasher) -> Int32 {
  self.kind.size()
}

///|
pub impl @spec.Hash for Hasher with fn block(self : Hasher) -> Int32 {
  self.kind.block()
}

///|
/// An extendable-output function: absorb a message, then read as many bytes as
/// needed. Reading advances, so two reads return consecutive output rather than
/// the same bytes twice.
///
/// Constructed with a `name` and `custom` it is cSHAKE, which is how KMAC and
/// any other SP 800-185 construction separates its domain from every other use
/// of the same permutation.
struct Xof {
  prefix : Bytes
  sponge : Sponge
}

///|
fn cat(a : BytesView, b : BytesView) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<a.length() {
    out.push(a[i])
  }
  for i in 0..<b.length() {
    out.push(b[i])
  }
  Bytes::from_array(out)
}

///|
/// A SHAKE, or a cSHAKE when `name` or `custom` is non-empty (SP 800-185 §3.3).
///
/// The two strings are not secret. `name` distinguishes one function from
/// another and is fixed by the standard that defines the function; `custom`
/// distinguishes one application from another. Both empty means plain SHAKE,
/// whose suffix differs — 0x1f rather than 0x04 — so the two can never collide.
pub fn Xof::new(
  kind~ : Kind = Shake128,
  name~ : BytesView = b""[:],
  custom~ : BytesView = b""[:],
) -> Xof {
  // Both strings empty means SHAKE, and SP 800-185 is explicit that cSHAKE
  // with nothing to customise *is* SHAKE — so the encodings are not applied at
  // all. Encoding two empty strings would still add four bytes of length
  // fields and produce a different function.
  let plain = name.length() == 0 && custom.length() == 0
  let customization = if plain {
    b""
  } else {
    cat(encode_string(name), encode_string(custom))
  }
  let sponge = Sponge::new(
    kind.block(),
    if customization.length() == 0 {
      kind.suffix()
    } else {
      b'\x04'
    },
  )
  let prefix = if customization.length() == 0 {
    b""
  } else {
    bytepad(customization[:], kind.block())
  }
  sponge.absorb(prefix[:])
  { prefix, sponge, }
}

///|
/// Absorb more message.
pub fn Xof::absorb(self : Xof, msg : BytesView) -> Unit {
  self.sponge.absorb(msg)
}

///|
/// Read `len` bytes, continuing where the last read stopped.
pub fn Xof::squeeze(self : Xof, len : Int32) -> Bytes {
  self.sponge.squeeze(len)
}

///|
/// Start over, keeping the rate and the customisation.
pub fn Xof::reset(self : Xof) -> Unit {
  for i in 0..<25 {
    self.sponge.st[i] = 0UL
  }
  self.sponge.at = 0
  self.sponge.padded = false
  self.sponge.absorb(self.prefix[:])
}

///|
/// One whole message through SHAKE128.
pub fn shake128(msg : BytesView, len : Int32) -> Bytes {
  let x = Xof::new(kind=Shake128)
  x.absorb(msg)
  x.squeeze(len)
}

///|
/// One whole message through SHAKE256.
pub fn shake256(msg : BytesView, len : Int32) -> Bytes {
  let x = Xof::new(kind=Shake256)
  x.absorb(msg)
  x.squeeze(len)
}

///|
/// One whole message through cSHAKE128.
pub fn cshake128(
  msg : BytesView,
  len : Int32,
  custom~ : BytesView = b""[:],
  name~ : BytesView = b""[:],
) -> Bytes {
  let x = Xof::new(kind=Shake128, name~, custom~)
  x.absorb(msg)
  x.squeeze(len)
}

///|
/// One whole message through cSHAKE256.
pub fn cshake256(
  msg : BytesView,
  len : Int32,
  custom~ : BytesView = b""[:],
  name~ : BytesView = b""[:],
) -> Bytes {
  let x = Xof::new(kind=Shake256, name~, custom~)
  x.absorb(msg)
  x.squeeze(len)
}

// ------------------------------------------------- the SP 800-185 encodings
//
// KMAC is cSHAKE over an encoded key and an encoded output length, so these
// four are part of the same standard and live beside the sponge that consumes
// them rather than in the package that happens to call them first.

///|
/// `left_encode(x)`: the length of `x` in bytes, then `x`, both big-endian
/// (SP 800-185 §2.3.1).
pub fn left_encode(x : UInt64) -> Bytes {
  let mut n : Int32 = 1
  while x >> (n * 8) != 0UL && n < 8 {
    n += 1
  }
  let out : Array[Byte] = []
  out.push(n.to_byte())
  for i = n - 1; i >= 0; i = i - 1 {
    out.push(((x >> (i * 8)) & 0xFFUL).to_byte())
  }
  Bytes::from_array(out)
}

///|
/// `right_encode(x)`: `x` big-endian, then its length in bytes
/// (SP 800-185 §2.3.1). What tells a reader where an output length ends.
pub fn right_encode(x : UInt64) -> Bytes {
  let mut n : Int32 = 1
  while x >> (n * 8) != 0UL && n < 8 {
    n += 1
  }
  let out : Array[Byte] = []
  for i = n - 1; i >= 0; i = i - 1 {
    out.push(((x >> (i * 8)) & 0xFFUL).to_byte())
  }
  out.push(n.to_byte())
  Bytes::from_array(out)
}

///|
/// `encode_string(s)`: the bit length, then the bytes (SP 800-185 §2.3.2).
pub fn encode_string(s : BytesView) -> Bytes {
  cat(left_encode(s.length().to_uint64() * 8UL), s)
}

///|
/// `bytepad(x, w)`: `x` padded with zeroes to a multiple of `w`, after its own
/// length. A rate-sized `w` makes the following message start on a block
/// boundary, which is what keeps a key from being read as message.
pub fn bytepad(x : BytesView, w : Int32) -> Bytes {
  let out : Array[Byte] = []
  let head = left_encode(w.to_uint64())
  for i in 0..<head.length() {
    out.push(head[i])
  }
  for i in 0..<x.length() {
    out.push(x[i])
  }
  while out.length() % w != 0 {
    out.push(b'\x00')
  }
  Bytes::from_array(out)
}
