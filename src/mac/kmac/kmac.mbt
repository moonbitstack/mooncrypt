// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which KMAC. The number is the security level in bits and picks the cSHAKE
/// underneath, so it also sets the largest key that fits in one block.
pub(all) enum Kind {
  Kmac128
  Kmac256
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The conventional tag length in bytes, 32 or 64. KMAC itself has no fixed
/// length; this is what [`Kmac`] uses when the length is not given.
pub fn Kind::size(self : Kind) -> Int32 {
  match self {
    Kmac128 => 32
    Kmac256 => 64
  }
}

///|
/// The cSHAKE rate in bytes, which is also the longest key KMAC accepts
/// (SP 800-185 §4.2 requires the encoded key to fit in one block).
pub fn Kind::block(self : Kind) -> Int32 {
  match self {
    Kmac128 => 168
    Kmac256 => 136
  }
}

///|
/// The cSHAKE this KMAC is built on.
fn Kind::shake(self : Kind) -> @sha3.Kind {
  match self {
    Kmac128 => @sha3.Shake128
    Kmac256 => @sha3.Shake256
  }
}

///|
/// The name cSHAKE is customised with, which is what keeps a KMAC output from
/// ever being a cSHAKE output over the same bytes.
let name : Bytes = b"KMAC"

///|
/// `bytepad(encode_string(K), rate)`: the key, length-prefixed and padded to a
/// whole block, so the message that follows cannot be read as part of the key.
fn key_block(key : BytesView, kind : Kind) -> Bytes {
  guard key.length() <= kind.block() else {
    abort(
      "kmac: a \{key.length()}-byte key does not fit the \{kind.block()}-byte block",
    )
  }
  @sha3.bytepad(@sha3.encode_string(key)[:], kind.block())
}

///|
/// A KMAC computation in progress, with the tag length fixed at construction.
struct Kmac {
  xof : @sha3.Xof
  size : Int32
  mut out : Bytes
  mut closed : Bool
}

///|
/// Key a KMAC. `custom` separates the uses of one key: two tags computed under
/// different strings are independent even when the key and message are the same.
pub fn Kmac::new(
  key : BytesView,
  kind~ : Kind = Kmac128,
  custom~ : BytesView = b""[:],
) -> Kmac {
  let xof = @sha3.Xof::new(kind=kind.shake(), name=name[:], custom~)
  xof.absorb(key_block(key, kind)[:])
  { xof, size: kind.size(), out: b"", closed: false, }
}

///|
fn Kmac::feed(self : Kmac, msg : BytesView) -> Unit {
  guard !self.closed else { abort("kmac: write after the tag was read") }
  self.xof.absorb(msg)
}

///|
/// The tag. Reading twice answers the same bytes, because the output length is
/// absorbed into the sponge the first time and a second absorption would be a
/// different function.
fn Kmac::read(self : Kmac) -> Bytes {
  if !self.closed {
    self.xof.absorb(@sha3.right_encode(self.size.to_uint64() * 8UL)[:])
    self.out = self.xof.squeeze(self.size)
    self.closed = true
  }
  self.out
}

///|
pub extend Kmac with @spec.Mac::{finish, size, write}

///|
pub impl @spec.Mac for Kmac with fn write(self : Kmac, msg : BytesView) -> Unit {
  self.feed(msg)
}

///|
pub impl @spec.Mac for Kmac with fn finish(self : Kmac) -> Bytes {
  self.read()
}

///|
pub impl @spec.Mac for Kmac with fn size(self : Kmac) -> Int32 {
  self.size
}

///|
/// One whole message through KMAC, with a tag of `len` bytes.
pub fn mac(
  key : BytesView,
  msg : BytesView,
  kind~ : Kind = Kmac128,
  len~ : Int32,
  custom~ : BytesView = b""[:],
) -> Bytes {
  let m = Kmac::new(key, kind~, custom~)
  m.xof.absorb(msg)
  m.xof.absorb(@sha3.right_encode(len.to_uint64() * 8UL)[:])
  m.xof.squeeze(len)
}

///|
/// The extendable-output form: absorb a message, then read as many bytes as
/// needed. The output length is not part of the sponge, so the first sixteen
/// bytes of a sixty-four-byte tag are the whole sixteen-byte tag.
struct KmacXof {
  xof : @sha3.Xof
  mut closed : Bool
}

///|
pub fn KmacXof::new(
  key : BytesView,
  kind~ : Kind = Kmac128,
  custom~ : BytesView = b""[:],
) -> KmacXof {
  let xof = @sha3.Xof::new(kind=kind.shake(), name=name[:], custom~)
  xof.absorb(key_block(key, kind)[:])
  { xof, closed: false, }
}

///|
pub fn KmacXof::write(self : KmacXof, msg : BytesView) -> Unit {
  guard !self.closed else { abort("kmac: write after the stream was closed") }
  self.xof.absorb(msg)
}

///|
/// Read `len` bytes, continuing where the last read stopped.
pub fn KmacXof::squeeze(self : KmacXof, len : Int32) -> Bytes {
  if !self.closed {
    self.xof.absorb(@sha3.right_encode(0UL)[:])
    self.closed = true
  }
  self.xof.squeeze(len)
}

///|
/// One whole message through KMACXOF.
pub fn xof(
  key : BytesView,
  msg : BytesView,
  len~ : Int32,
  kind~ : Kind = Kmac128,
  custom~ : BytesView = b""[:],
) -> Bytes {
  let m = KmacXof::new(key, kind~, custom~)
  m.xof.absorb(msg)
  m.xof.absorb(@sha3.right_encode(0UL)[:])
  m.xof.squeeze(len)
}
