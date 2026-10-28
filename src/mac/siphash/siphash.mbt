// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The key length in bytes. SipHash is defined for exactly 16.
pub let key_size : Int32 = 16

///|
/// The tag length in bytes.
pub let tag_size : Int32 = 8

///|
fn turn(x : UInt64, by : Int32) -> UInt64 {
  (x << by) | (x >> (64 - by))
}

///|
/// The little-endian 64-bit word at `at`.
fn word(buf : FixedArray[Byte], at : Int32) -> UInt64 {
  let mut v = 0UL
  for i in 0..<8 {
    v = v | (buf[at + i].to_uint().to_uint64() << (8 * i))
  }
  v
}

///|
/// The four 64-bit lanes.
///
/// They live in their own type so that one SipRound can be written once and
/// called from both the absorbing and the finalising side, without an array or a
/// tuple being allocated per eight bytes of message.
struct Lanes {
  mut v0 : UInt64
  mut v1 : UInt64
  mut v2 : UInt64
  mut v3 : UInt64
}

///|
/// One SipRound, as the paper writes it: two additions, four rotates and four
/// xors, arranged so that the next round can start on the result without a
/// dependency stall.
fn Lanes::round(self : Lanes) -> Unit {
  self.v0 = self.v0 + self.v1
  self.v1 = turn(self.v1, 13)
  self.v1 = self.v1 ^ self.v0
  self.v0 = turn(self.v0, 32)
  self.v2 = self.v2 + self.v3
  self.v3 = turn(self.v3, 16)
  self.v3 = self.v3 ^ self.v2
  self.v0 = self.v0 + self.v3
  self.v3 = turn(self.v3, 21)
  self.v3 = self.v3 ^ self.v0
  self.v2 = self.v2 + self.v1
  self.v1 = turn(self.v1, 17)
  self.v1 = self.v1 ^ self.v2
  self.v2 = turn(self.v2, 32)
}

///|
fn Lanes::rounds(self : Lanes, count : Int32) -> Unit {
  for _ in 0..<count {
    self.round()
  }
}

///|
fn Lanes::squeeze(self : Lanes) -> UInt64 {
  self.v0 ^ self.v1 ^ self.v2 ^ self.v3
}

///|
/// A SipHash-2-4 in progress.
///
/// The buffer needs at most seven bytes: a full eight-byte word is mixed in the
/// moment it is available, and only a trailing partial word waits for the length,
/// which goes into the top byte of the last block.
pub struct SipHash {
  lanes : Lanes
  buf : FixedArray[Byte]
  mut held : Int32
  mut total : UInt64
}

///|
/// Key a SipHash-2-4. The key must be exactly [`key_size`] bytes; anything else
/// is refused rather than padded, because a key that silently became shorter
/// would be a weaker MAC that still looked like a working one.
pub fn SipHash::new(key : BytesView) -> SipHash raise @spec.Broken {
  guard key.length() == key_size else {
    raise @spec.Broken::Size(want=key_size, got=key.length())
  }
  let mut k0 = 0UL
  let mut k1 = 0UL
  for i in 0..<8 {
    k0 = k0 | (key[i].to_uint().to_uint64() << (8 * i))
    k1 = k1 | (key[8 + i].to_uint().to_uint64() << (8 * i))
  }
  {
    lanes: {
      v0: k0 ^ 0x736F_6D65_7073_6575UL,
      v1: k1 ^ 0x646F_7261_6E64_6F6DUL,
      v2: k0 ^ 0x6C79_6765_6E65_7261UL,
      v3: k1 ^ 0x7465_6462_7974_6573UL,
    },
    buf: FixedArray::make(8, b'\x00'),
    held: 0,
    total: 0UL,
  }
}

///|
/// Mix one word in: xor it into the last lane, two rounds, xor it into the first.
/// Two rounds of compression per word is the "2" in SipHash-2-4.
fn SipHash::absorb(self : SipHash, m : UInt64) -> Unit {
  self.lanes.v3 = self.lanes.v3 ^ m
  self.lanes.rounds(2)
  self.lanes.v0 = self.lanes.v0 ^ m
}

///|
/// Feed more bytes. Whole eight-byte words are mixed in as they arrive; whatever
/// does not fill one is held until [`value`](#value).
pub fn SipHash::update(self : SipHash, data : BytesView) -> Unit {
  self.total = self.total + data.length().to_uint64()
  let mut at = 0
  while at < data.length() {
    let room = 8 - self.held
    let left = data.length() - at
    let take = if left < room { left } else { room }
    for i in 0..<take {
      self.buf[self.held + i] = data[at + i]
    }
    self.held = self.held + take
    at = at + take
    if self.held == 8 {
      self.absorb(word(self.buf, 0))
      self.held = 0
    }
  }
}

///|
/// The tag as a number.
///
/// The last block carries the message length in its top byte, so a message and
/// the same message with a zero byte appended hash differently — without it,
/// padding ambiguities would let an attacker move bytes between messages. The
/// finalisation is four rounds, the "4" in the name.
///
/// The state is copied rather than consumed, so this can be called more than once.
pub fn SipHash::value(self : SipHash) -> UInt64 {
  let mut last = (self.total & 0xFFUL) << 56
  for i in 0..<self.held {
    last = last | (self.buf[i].to_uint().to_uint64() << (8 * i))
  }
  let lanes = {
    v0: self.lanes.v0,
    v1: self.lanes.v1,
    v2: self.lanes.v2,
    v3: self.lanes.v3 ^ last,
  }
  lanes.rounds(2)
  lanes.v0 = lanes.v0 ^ last
  lanes.v2 = lanes.v2 ^ 0xFFUL
  lanes.rounds(4)
  lanes.squeeze()
}

///|
/// The tag as eight bytes, most significant first — the convention every other
/// digest in mooncrypt follows. SipHash itself writes the number, and the hash
/// tables that use it compare the number.
fn SipHash::bytes(self : SipHash) -> Bytes {
  let v = self.value()
  let out : FixedArray[Byte] = FixedArray::make(tag_size, b'\x00')
  for i in 0..<tag_size {
    out[i] = ((v >> ((tag_size - 1 - i) * 8)) & 0xFFUL).to_uint().to_byte()
  }
  Bytes::from_array(out)
}

///|
/// The SipHash-2-4 tag of a whole message.
pub fn siphash(key : BytesView, msg : BytesView) -> Bytes raise @spec.Broken {
  let state = SipHash::new(key)
  state.update(msg)
  state.bytes()
}

///|
pub extend SipHash with @spec.Mac::{write, finish, size}

///|
pub impl @spec.Mac for SipHash with fn write(self, msg) {
  self.update(msg)
}

///|
pub impl @spec.Mac for SipHash with fn finish(self) {
  self.bytes()
}

///|
pub impl @spec.Mac for SipHash with fn size(self) {
  let _ = self
  tag_size
}
