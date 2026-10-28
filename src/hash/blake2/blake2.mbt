// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which BLAKE2. `b` is the 64-bit variant and `s` the 32-bit one; the digest
/// length, the salt length and the personalisation length all follow from that.
pub(all) enum Kind {
  Blake2b
  Blake2s
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The longest digest this variant can produce: 64 or 32 bytes.
pub fn Kind::size(self : Kind) -> Int32 {
  match self {
    Blake2b => 64
    Blake2s => 32
  }
}

///|
/// The block length: 128 or 64 bytes.
pub fn Kind::block(self : Kind) -> Int32 {
  match self {
    Blake2b => 128
    Blake2s => 64
  }
}

///|
/// The salt and personalisation lengths, 16 or 8 bytes.
pub fn Kind::salt_size(self : Kind) -> Int32 {
  match self {
    Blake2b => 16
    Blake2s => 8
  }
}

///|
let iv64 : FixedArray[UInt64] = [
  0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
  0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL,
]

///|
let iv32 : FixedArray[UInt32] = [
  0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU,
  0x5BE0CD19U,
]

///|
/// The message schedule (RFC 7693 §2.7). Ten rows for BLAKE2s's ten rounds; the
/// twelve rounds of BLAKE2b reuse the first two.
let sigma : FixedArray[FixedArray[Int32]] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

///|
fn rotr64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
/// A `BytesView` copied into a zero-filled array of a fixed size, which is how
/// the parameter block reads a salt that may be absent.
fn padded(v : BytesView, n : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let take = if v.length() < n { v.length() } else { n }
  for i in 0..<take {
    out[i] = v[i]
  }
  out
}

///|
fn read64(buf : FixedArray[Byte], off : Int32) -> UInt64 {
  let mut v = 0UL
  for b in 0..<8 {
    v = v | (buf[off + b].to_int().to_uint64() << (b * 8))
  }
  v
}

///|
fn read32(buf : FixedArray[Byte], off : Int32) -> UInt32 {
  let mut v = 0U
  for b in 0..<4 {
    v = v | (buf[off + b].to_int().reinterpret_as_uint() << (b * 8))
  }
  v
}

///|
fn g64(
  v : FixedArray[UInt64],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
  x : UInt64,
  y : UInt64,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = rotr64(v[d] ^ v[a], 32)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 24)
  v[a] = v[a] + v[b] + y
  v[d] = rotr64(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 63)
}

///|
fn g32(
  v : FixedArray[UInt32],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
  x : UInt32,
  y : UInt32,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = rotr32(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotr32(v[b] ^ v[c], 12)
  v[a] = v[a] + v[b] + y
  v[d] = rotr32(v[d] ^ v[a], 8)
  v[c] = v[c] + v[d]
  v[b] = rotr32(v[b] ^ v[c], 7)
}

///|
fn compress64(
  h : FixedArray[UInt64],
  block : FixedArray[Byte],
  t : UInt64,
  last : Bool,
) -> Unit {
  let m : FixedArray[UInt64] = FixedArray::make(16, 0UL)
  for i in 0..<16 {
    m[i] = read64(block, i * 8)
  }
  let v : FixedArray[UInt64] = FixedArray::make(16, 0UL)
  for i in 0..<8 {
    v[i] = h[i]
    v[i + 8] = iv64[i]
  }
  v[12] = v[12] ^ t
  if last {
    v[14] = v[14].lnot()
  }
  for round in 0..<12 {
    let s = sigma[round % 10]
    g64(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
    g64(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
    g64(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
    g64(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
    g64(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
    g64(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
    g64(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
    g64(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
  }
  for i in 0..<8 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
fn compress32(
  h : FixedArray[UInt32],
  block : FixedArray[Byte],
  t : UInt64,
  last : Bool,
) -> Unit {
  let m : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i in 0..<16 {
    m[i] = read32(block, i * 4)
  }
  let v : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i in 0..<8 {
    v[i] = h[i]
    v[i + 8] = iv32[i]
  }
  v[12] = v[12] ^ (t & 0xFFFFFFFFUL).to_uint()
  v[13] = v[13] ^ (t >> 32).to_uint()
  if last {
    v[14] = v[14].lnot()
  }
  for round in 0..<10 {
    let s = sigma[round]
    g32(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
    g32(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
    g32(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
    g32(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
    g32(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
    g32(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
    g32(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
    g32(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
  }
  for i in 0..<8 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
fn le_bytes64(words : FixedArray[UInt64], n : Int32) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<((n + 7) / 8) {
    for b in 0..<8 {
      out.push(((words[i] >> (b * 8)) & 0xFFUL).to_byte())
    }
  }
  Bytes::from_array(out[0:n].to_owned())
}

///|
fn le_bytes32(words : FixedArray[UInt32], n : Int32) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<((n + 3) / 4) {
    for b in 0..<4 {
      out.push(((words[i] >> (b * 8)) & 0xFFU).to_byte())
    }
  }
  Bytes::from_array(out[0:n].to_owned())
}

///|
/// A BLAKE2 computation in progress, in whichever width.
struct Hasher {
  kind : Kind
  len : Int32
  key : Bytes
  salt : Bytes
  person : Bytes
  core : Core
}

///|
priv enum Core {
  Wide(Wide)
  Narrow(Narrow)
}

///|
priv struct Wide {
  h : FixedArray[UInt64]
  buf : FixedArray[Byte]
  mut used : Int32
  mut t : UInt64
}

///|
priv struct Narrow {
  h : FixedArray[UInt32]
  buf : FixedArray[Byte]
  mut used : Int32
  mut t : UInt64
}

///|
/// The state a fresh hasher of this shape starts from: the parameter block
/// folded into the initial vector, and the key — if any — sitting in the buffer
/// as the first block.
fn build(
  kind : Kind,
  len : Int32,
  key : BytesView,
  salt : BytesView,
  person : BytesView,
) -> Core {
  let kk = key.length().to_uint64()
  let nn = len.to_uint64()
  match kind {
    Blake2b => {
      let h : FixedArray[UInt64] = FixedArray::make(8, 0UL)
      for i in 0..<8 {
        h[i] = iv64[i]
      }
      h[0] = h[0] ^ (0x01010000UL ^ (kk << 8) ^ nn)
      let s = padded(salt, 16)
      h[4] = h[4] ^ read64(s, 0)
      h[5] = h[5] ^ read64(s, 8)
      let p = padded(person, 16)
      h[6] = h[6] ^ read64(p, 0)
      h[7] = h[7] ^ read64(p, 8)
      let buf : FixedArray[Byte] = FixedArray::make(128, b'\x00')
      for i in 0..<key.length() {
        buf[i] = key[i]
      }
      Wide({ h, buf, used: if key.length() > 0 { 128 } else { 0 }, t: 0, })
    }
    Blake2s => {
      let h : FixedArray[UInt32] = FixedArray::make(8, 0U)
      for i in 0..<8 {
        h[i] = iv32[i]
      }
      h[0] = h[0] ^ (0x01010000U ^ (kk.to_uint() << 8) ^ nn.to_uint())
      let s = padded(salt, 8)
      h[4] = h[4] ^ read32(s, 0)
      h[5] = h[5] ^ read32(s, 4)
      let p = padded(person, 8)
      h[6] = h[6] ^ read32(p, 0)
      h[7] = h[7] ^ read32(p, 4)
      let buf : FixedArray[Byte] = FixedArray::make(64, b'\x00')
      for i in 0..<key.length() {
        buf[i] = key[i]
      }
      Narrow({ h, buf, used: if key.length() > 0 { 64 } else { 0 }, t: 0, })
    }
  }
}

///|
/// A fresh hasher.
///
/// `len` is the digest length, and 0 means the full length for the variant.
/// `salt` and `person` are fields of the parameter block, so their lengths must
/// be exactly 0 or the variant's salt size — a short one is not zero-padded,
/// it is a different parameter block. `key` is what makes this a MAC; it may be
/// at most 64 bytes for `b` and 32 for `s`.
pub fn Hasher::new(
  kind~ : Kind = Blake2b,
  len~ : Int32 = 0,
  key~ : BytesView = b""[:],
  salt~ : BytesView = b""[:],
  person~ : BytesView = b""[:],
) -> Hasher {
  let size = if len == 0 { kind.size() } else { len }
  guard size > 0 && size <= kind.size() else {
    abort("blake2: \{size} bytes is not a digest length this variant has")
  }
  guard key.length() <= kind.size() else {
    abort(
      "blake2: a \{key.length()}-byte key is longer than the variant allows",
    )
  }
  guard salt.length() == 0 || salt.length() == kind.salt_size() else {
    abort("blake2: salt must be \{kind.salt_size()} bytes")
  }
  guard person.length() == 0 || person.length() == kind.salt_size() else {
    abort("blake2: personalisation must be \{kind.salt_size()} bytes")
  }
  {
    kind,
    len: size,
    key: key.to_owned(),
    salt: salt.to_owned(),
    person: person.to_owned(),
    core: build(kind, size, key, salt, person),
  }
}

///|
/// Hash one whole message.
pub fn hash(
  msg : BytesView,
  kind~ : Kind = Blake2b,
  len~ : Int32 = 0,
  key~ : BytesView = b""[:],
  salt~ : BytesView = b""[:],
  person~ : BytesView = b""[:],
) -> Bytes {
  let h = Hasher::new(kind~, len~, key~, salt~, person~)
  h.write(msg)
  h.finish()
}

///|
/// One whole message as a keyed MAC of the variant's full length.
pub fn mac(key : BytesView, msg : BytesView, kind~ : Kind = Blake2b) -> Bytes {
  hash(msg, kind~, key~)
}

///|
pub extend Hasher with @spec.Hash::{block, finish, reset, size, write}

///|
pub impl @spec.Hash for Hasher with fn write(self : Hasher, msg : BytesView) -> Unit {
  match self.core {
    Wide(s) => wide_write(s, msg)
    Narrow(s) => narrow_write(s, msg)
  }
}

///|
/// The last block is compressed here and nowhere else: BLAKE2 holds one block
/// back, because the final block is marked as final and a block that was
/// already compressed cannot be told otherwise.
///
/// It runs on copies, so a caller may read a digest and keep writing — the
/// reading is what makes the copy worth it.
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  match self.core {
    Wide(s) => {
      let h : FixedArray[UInt64] = FixedArray::make(8, 0UL)
      for i in 0..<8 {
        h[i] = s.h[i]
      }
      let buf : FixedArray[Byte] = FixedArray::make(128, b'\x00')
      for i in 0..<s.used {
        buf[i] = s.buf[i]
      }
      compress64(h, buf, s.t + s.used.to_uint64(), true)
      le_bytes64(h, self.len)
    }
    Narrow(s) => {
      let h : FixedArray[UInt32] = FixedArray::make(8, 0U)
      for i in 0..<8 {
        h[i] = s.h[i]
      }
      let buf : FixedArray[Byte] = FixedArray::make(64, b'\x00')
      for i in 0..<s.used {
        buf[i] = s.buf[i]
      }
      compress32(h, buf, s.t + s.used.to_uint64(), true)
      le_bytes32(h, self.len)
    }
  }
}

///|
/// Back to the parameterised state, key block and all.
pub impl @spec.Hash for Hasher with fn reset(self : Hasher) -> Unit {
  let fresh = build(
    self.kind,
    self.len,
    self.key[:],
    self.salt[:],
    self.person[:],
  )
  match (self.core, fresh) {
    (Wide(s), Wide(f)) => {
      for i in 0..<8 {
        s.h[i] = f.h[i]
      }
      for i in 0..<128 {
        s.buf[i] = f.buf[i]
      }
      s.used = f.used
      s.t = 0
    }
    (Narrow(s), Narrow(f)) => {
      for i in 0..<8 {
        s.h[i] = f.h[i]
      }
      for i in 0..<64 {
        s.buf[i] = f.buf[i]
      }
      s.used = f.used
      s.t = 0
    }
    _ => abort("blake2: the state changed width under a reset")
  }
}

///|
pub impl @spec.Hash for Hasher with fn size(self : Hasher) -> Int32 {
  self.len
}

///|
pub impl @spec.Hash for Hasher with fn block(self : Hasher) -> Int32 {
  self.kind.block()
}

///|
fn wide_write(s : Wide, msg : BytesView) -> Unit {
  let mut at = 0
  while at < msg.length() {
    if s.used == 128 {
      s.t += 128UL
      compress64(s.h, s.buf, s.t, false)
      s.used = 0
    }
    let room = 128 - s.used
    let left = msg.length() - at
    let take = if room < left { room } else { left }
    for i in 0..<take {
      s.buf[s.used + i] = msg[at + i]
    }
    s.used += take
    at += take
  }
}

///|
fn narrow_write(s : Narrow, msg : BytesView) -> Unit {
  let mut at = 0
  while at < msg.length() {
    if s.used == 64 {
      s.t += 64UL
      compress32(s.h, s.buf, s.t, false)
      s.used = 0
    }
    let room = 64 - s.used
    let left = msg.length() - at
    let take = if room < left { room } else { left }
    for i in 0..<take {
      s.buf[s.used + i] = msg[at + i]
    }
    s.used += take
    at += take
  }
}
