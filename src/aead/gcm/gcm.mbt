// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Carry-less multiplication of two 64-bit words, the low 64 bits of the product (BearSSL's
/// `bmul64`). Each operand is split into four sets of every fourth bit, so the carries an
/// integer multiply makes fall on bits the masks then clear: GF(2) arithmetic from ordinary
/// multiplies, with no branch and no table indexed by secret data.
fn bmul64(x : UInt64, y : UInt64) -> UInt64 {
  let m0 = 0x1111111111111111UL
  let m1 = 0x2222222222222222UL
  let m2 = 0x4444444444444444UL
  let m3 = 0x8888888888888888UL
  let (x0, x1, x2, x3) = (x & m0, x & m1, x & m2, x & m3)
  let (y0, y1, y2, y3) = (y & m0, y & m1, y & m2, y & m3)
  let z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
  let z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
  let z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
  let z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
  (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3)
}

///|
/// The bits of a word in reverse order. With `bmul64` it gives the high half of a product:
/// reverse both operands, multiply, reverse back.
fn rev64(x : UInt64) -> UInt64 {
  let x = ((x & 0x5555555555555555UL) << 1) | ((x >> 1) & 0x5555555555555555UL)
  let x = ((x & 0x3333333333333333UL) << 2) | ((x >> 2) & 0x3333333333333333UL)
  let x = ((x & 0x0F0F0F0F0F0F0F0FUL) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0FUL)
  let x = ((x & 0x00FF00FF00FF00FFUL) << 8) | ((x >> 8) & 0x00FF00FF00FF00FFUL)
  let x = ((x & 0x0000FFFF0000FFFFUL) << 16) |
    ((x >> 16) & 0x0000FFFF0000FFFFUL)
  (x << 32) | (x >> 32)
}

///|
fn be64(b : BytesView, at : Int32) -> UInt64 {
  let mut v = 0UL
  for i in 0..<8 {
    v = (v << 8) | b[at + i].to_uint64()
  }
  v
}

///|
fn put_be64(out : FixedArray[Byte], at : Int32, v : UInt64) -> Unit {
  for i in 0..<8 {
    out[at + i] = (v >> (56 - 8 * i)).to_byte()
  }
}

///|
/// The hash subkey H in the halves and reversed halves the multiply wants, worked out once.
priv struct Subkey {
  h0 : UInt64
  h1 : UInt64
  h2 : UInt64
  h0r : UInt64
  h1r : UInt64
  h2r : UInt64
}

///|
fn Subkey::new(h : BytesView) -> Subkey {
  let h1 = be64(h, 0)
  let h0 = be64(h, 8)
  let h0r = rev64(h0)
  let h1r = rev64(h1)
  { h0, h1, h2: h0 ^ h1, h0r, h1r, h2r: h0r ^ h1r, }
}

///|
/// A GHASH accumulator: the running value Y, high half and low half.
priv struct Ghash {
  key : Subkey
  mut y1 : UInt64
  mut y0 : UInt64
}

///|
fn Ghash::new(key : Subkey) -> Ghash {
  { key, y1: 0, y0: 0, }
}

///|
/// Fold in `data` (SP 800-38D §6.4), a short final block padded with zeros: Y = (Y ^ X) * H
/// for each block, by BearSSL's `ghash_ctmul64`. Karatsuba makes the 128-bit product from three
/// 64-bit ones per half, then the product is reduced by x^128 + x^7 + x^2 + x + 1 with shifts.
fn Ghash::update(self : Ghash, data : BytesView) -> Unit {
  let k = self.key
  let mut y0 = self.y0
  let mut y1 = self.y1
  let mut at = 0
  let pad = FixedArray::make(16, b'\x00')
  while at < data.length() {
    let left = data.length() - at
    let src = if left >= 16 {
      data[at:at + 16]
    } else {
      pad.fill(b'\x00')
      for i in 0..<left {
        pad[i] = data[at + i]
      }
      pad.unsafe_reinterpret_as_bytes()[:]
    }
    at += 16
    y1 = y1 ^ be64(src, 0)
    y0 = y0 ^ be64(src, 8)
    let y0r = rev64(y0)
    let y1r = rev64(y1)
    let y2 = y0 ^ y1
    let y2r = y0r ^ y1r
    let z0 = bmul64(y0, k.h0)
    let z1 = bmul64(y1, k.h1)
    let z2 = bmul64(y2, k.h2) ^ z0 ^ z1
    let z0h = bmul64(y0r, k.h0r)
    let z1h = bmul64(y1r, k.h1r)
    let z2h = bmul64(y2r, k.h2r) ^ z0h ^ z1h
    let z0h = rev64(z0h) >> 1
    let z1h = rev64(z1h) >> 1
    let z2h = rev64(z2h) >> 1
    let v0 = z0
    let v1 = z0h ^ z2
    let v2 = z1 ^ z2h
    let v3 = z1h
    let v3 = (v3 << 1) | (v2 >> 63)
    let v2 = (v2 << 1) | (v1 >> 63)
    let v1 = (v1 << 1) | (v0 >> 63)
    let v0 = v0 << 1
    let v2 = v2 ^ v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7)
    let v1 = v1 ^ (v0 << 63) ^ (v0 << 62) ^ (v0 << 57)
    let v3 = v3 ^ v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7)
    let v2 = v2 ^ (v1 << 63) ^ (v1 << 62) ^ (v1 << 57)
    y0 = v2
    y1 = v3
  }
  self.y0 = y0
  self.y1 = y1
}

///|
/// Fold in the lengths block: the two lengths in bits, 64 bits each, big-endian.
fn Ghash::lengths(self : Ghash, a : Int32, c : Int32) -> Unit {
  let blk = FixedArray::make(16, b'\x00')
  put_be64(blk, 0, a.to_uint64() * 8)
  put_be64(blk, 8, c.to_uint64() * 8)
  self.update(blk.unsafe_reinterpret_as_bytes()[:])
}

///|
fn Ghash::value(self : Ghash) -> FixedArray[Byte] {
  let out = FixedArray::make(16, b'\x00')
  put_be64(out, 0, self.y1)
  put_be64(out, 8, self.y0)
  out
}

///|
/// Increment the low 32 bits of a counter block, big-endian, modulo 2^32.
fn inc32(ctr : FixedArray[Byte]) -> Unit {
  for i = 15; i >= 12; i = i - 1 {
    ctr[i] = ctr[i] + 1
    if ctr[i] != 0 {
      break
    }
  }
}

///|
/// The tag length every implementation writes unless told otherwise: the full
/// 128 bits, which is the only length SP 800-38D appendix C leaves unqualified.
pub let tag : Int32 = 16

///|
/// Galois/Counter Mode over a block cipher (NIST SP 800-38D).
///
/// It is built on any 128-bit block cipher rather than on AES alone, because the
/// mode is defined that way: `@gcm.Gcm::new(@aes.Cipher::new(key))` is AES-GCM,
/// and an SM4 that satisfies [`@spec.Block`] is SM4-GCM with no further code.
struct Gcm {
  cipher : &@spec.Block
  subkey : Subkey
  tag : Int32
}

///|
/// Wrap a block cipher in GCM.
///
/// `tag` is the authentication tag length in bytes. The default is the full 16;
/// SP 800-38D §5.2.1.2 also allows 15, 14, 13 and 12, and 8 or 4 only for
/// applications whose own analysis says so — appendix C works out how much
/// forgery resistance each one costs, so a shorter tag is a decision to take
/// deliberately rather than a default to inherit.
///
/// The cipher must have a 16-byte block; GCM is not defined for any other.
pub fn Gcm::new(
  cipher : &@spec.Block,
  tag~ : Int32 = tag,
) -> Gcm raise @spec.Broken {
  guard cipher.block() == 16 else {
    raise @spec.Size(want=16, got=cipher.block())
  }
  guard tag == 16 ||
    tag == 15 ||
    tag == 14 ||
    tag == 13 ||
    tag == 12 ||
    tag == 8 ||
    tag == 4 else {
    abort("gcm: a \{tag}-byte tag is not one SP 800-38D defines")
  }
  let zero = Bytes::make(16, b'\x00')
  { cipher, subkey: Subkey::new(cipher.encrypt(zero[:])[:]), tag, }
}

///|
/// The tag length in bytes this instance writes and checks.
pub fn Gcm::size(self : Gcm) -> Int32 {
  self.tag
}

///|
/// The pre-counter block J0 (SP 800-38D §7.1 step 2).
///
/// A 96-bit nonce is the common case and gets the cheap construction; any other
/// length goes through GHASH, which is what makes a nonce of any length legal
/// and also why 96 bits is what everyone uses.
fn Gcm::start(self : Gcm, nonce : BytesView) -> FixedArray[Byte] {
  if nonce.length() == 12 {
    let j0 = FixedArray::make(16, b'\x00')
    for i in 0..<12 {
      j0[i] = nonce[i]
    }
    j0[15] = b'\x01'
    return j0
  }
  let g = Ghash::new(self.subkey)
  g.update(nonce)
  g.lengths(0, nonce.length())
  g.value()
}

///|
/// CTR-mode keystream XOR, starting from J0 incremented once — the data counter
/// begins at J0+1 (SP 800-38D §7.1 step 3).
fn Gcm::gctr(self : Gcm, j0 : FixedArray[Byte], input : BytesView) -> Bytes {
  let counter = FixedArray::make(16, b'\x00')
  FixedArray::unsafe_blit(counter, 0, j0, 0, 16)
  inc32(counter)
  let out = FixedArray::make(input.length(), b'\x00')
  let mut off = 0
  while off < input.length() {
    let ks = self.cipher.encrypt(counter.unsafe_reinterpret_as_bytes()[:])
    let n = @cmp.minimum(input.length() - off, 16)
    for j in 0..<n {
      out[off + j] = input[off + j] ^ ks[j]
    }
    inc32(counter)
    off = off + 16
  }
  out.unsafe_reinterpret_as_bytes()
}

///|
/// `E(J0) XOR GHASH(A || C || lengths)`, truncated to the tag length
/// (SP 800-38D §7.1 steps 5 and 6).
fn Gcm::seal_tag(
  self : Gcm,
  j0 : FixedArray[Byte],
  aad : BytesView,
  cipher : BytesView,
) -> Bytes {
  let g = Ghash::new(self.subkey)
  g.update(aad)
  g.update(cipher)
  g.lengths(aad.length(), cipher.length())
  let s = g.value()
  let mask = self.cipher.encrypt(j0.unsafe_reinterpret_as_bytes()[:])
  let out = FixedArray::make(self.tag, b'\x00')
  for i in 0..<self.tag {
    out[i] = mask[i] ^ s[i]
  }
  out.unsafe_reinterpret_as_bytes()
}

///|
/// Encrypt and authenticate, returning the ciphertext with its tag appended.
///
/// The nonce is at least one octet; an empty one aborts. It must never repeat under one key: GCM's confidentiality and its
/// authentication both collapse if it does, and recovering the hash subkey from
/// two messages sharing a nonce is arithmetic rather than cryptanalysis. That is
/// the caller's to guarantee, because only the caller knows where its nonces come
/// from.
pub fn Gcm::seal(
  self : Gcm,
  nonce~ : BytesView,
  plain~ : BytesView,
  aad~ : BytesView = b""[:],
) -> Bytes {
  guard nonce.length() > 0 else {
    abort("gcm: an empty nonce, which SP 800-38D §5.2.1.1 does not allow")
  }
  let j0 = self.start(nonce)
  let body = self.gctr(j0, plain)
  body + self.seal_tag(j0, aad, body[:])
}

///|
/// Check the tag and, only then, decrypt.
///
/// It raises rather than returning an option because "the tag did not match" is
/// the one outcome a caller must not quietly read as empty plaintext. Nothing
/// decrypted is returned before the tag is checked, so a caller cannot act on
/// plaintext that was never authenticated.
pub fn Gcm::open(
  self : Gcm,
  nonce~ : BytesView,
  cipher~ : BytesView,
  aad~ : BytesView = b""[:],
) -> Bytes raise @spec.Broken {
  guard cipher.length() >= self.tag else {
    raise @spec.Size(want=self.tag, got=cipher.length())
  }
  guard nonce.length() > 0 else { raise @spec.Size(want=1, got=0) }
  let cut = cipher.length() - self.tag
  let j0 = self.start(nonce)
  let want = self.seal_tag(j0, aad, cipher[0:cut])
  guard @spec.eq(want[:], cipher[cut:]) else { raise @spec.Tag }
  self.gctr(j0, cipher[0:cut])
}

///|
pub impl @spec.Aead for Gcm with fn seal(self, nonce~, plain~, aad~) {
  self.seal(nonce~, plain~, aad~)
}

///|
pub impl @spec.Aead for Gcm with fn open(self, nonce~, cipher~, aad~) {
  self.open(nonce~, cipher~, aad~)
}
