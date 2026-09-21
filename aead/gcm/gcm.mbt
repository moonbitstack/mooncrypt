// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Multiply two 128-bit blocks in GF(2^128) under the GCM reduction polynomial
/// `x^128 + x^7 + x^2 + x + 1` (SP 800-38D §6.3).
///
/// Blocks are big-endian with bit 0 the most significant bit of byte 0, which is
/// the field's own convention and the reason this looks reversed next to an
/// ordinary bignum multiply. The loop is the plain shift-and-reduce: no table,
/// so no table lookup indexed by key material.
fn gf_mul(x : FixedArray[Int], y : FixedArray[Int]) -> FixedArray[Int] {
  let z = FixedArray::make(16, 0)
  let v = FixedArray::make(16, 0)
  for i in 0..<16 {
    v[i] = x[i]
  }
  for i in 0..<128 {
    if ((y[i / 8] >> (7 - i % 8)) & 1) == 1 {
      for j in 0..<16 {
        z[j] = z[j] ^ v[j]
      }
    }
    let lsb = v[15] & 1
    for j = 15; j > 0; j = j - 1 {
      v[j] = ((v[j] >> 1) | ((v[j - 1] & 1) << 7)) & 0xff
    }
    v[0] = (v[0] >> 1) & 0xff
    if lsb == 1 {
      v[0] = v[0] ^ 0xe1
    }
  }
  z
}

///|
/// GHASH over block-aligned `data` (SP 800-38D §6.4): fold each block in with XOR
/// and multiply by the hash subkey.
fn ghash(h : FixedArray[Int], data : BytesView) -> FixedArray[Int] {
  let y = FixedArray::make(16, 0)
  for blk in 0..<(data.length() / 16) {
    for j in 0..<16 {
      y[j] = y[j] ^ data[blk * 16 + j].to_int()
    }
    let m = gf_mul(y, h)
    for j in 0..<16 {
      y[j] = m[j]
    }
  }
  y
}

///|
/// Increment the low 32 bits of a counter block, big-endian, modulo 2^32.
fn inc32(ctr : FixedArray[Int]) -> Unit {
  for i = 15; i >= 12; i = i - 1 {
    ctr[i] = (ctr[i] + 1) & 0xff
    if ctr[i] != 0 {
      break
    }
  }
}

///|
/// The bytes of a block as ints, for the field work.
fn ints(b : BytesView) -> FixedArray[Int] {
  let a = FixedArray::make(16, 0)
  for i in 0..<16 {
    a[i] = b[i].to_int()
  }
  a
}

///|
/// A block of ints back as bytes, for the cipher.
fn block(a : FixedArray[Int]) -> Bytes {
  let out = Array::make(16, b'\x00')
  for i in 0..<16 {
    out[i] = a[i].to_byte()
  }
  Bytes::from_array(out)
}

///|
/// Append a 64-bit big-endian integer.
fn put64(buf : Buffer, v : Int64) -> Unit {
  for i = 7; i >= 0; i = i - 1 {
    buf.write_byte((v >> (i * 8)).to_byte())
  }
}

///|
/// The tag length every implementation writes unless told otherwise: the full
/// 128 bits, which is the only length SP 800-38D appendix C leaves unqualified.
pub let tag : Int = 16

///|
/// Galois/Counter Mode over a block cipher (NIST SP 800-38D).
///
/// It is built on any 128-bit block cipher rather than on AES alone, because the
/// mode is defined that way: `@gcm.Gcm::new(@aes.Cipher::new(key))` is AES-GCM,
/// and an SM4 that satisfies [`@spec.Block`] is SM4-GCM with no further code.
pub struct Gcm {
  cipher : &@spec.Block
  subkey : FixedArray[Int]
  tag : Int
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
  tag? : Int = tag,
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
  { cipher, subkey: ints(cipher.encrypt(zero[:])[:]), tag, }
}

///|
/// The tag length in bytes this instance writes and checks.
pub fn Gcm::size(self : Gcm) -> Int {
  self.tag
}

///|
/// The pre-counter block J0 (SP 800-38D §7.1 step 2).
///
/// A 96-bit nonce is the common case and gets the cheap construction; any other
/// length goes through GHASH, which is what makes a nonce of any length legal
/// and also why 96 bits is what everyone uses.
fn Gcm::start(self : Gcm, nonce : BytesView) -> FixedArray[Int] {
  if nonce.length() == 12 {
    let j0 = FixedArray::make(16, 0)
    for i in 0..<12 {
      j0[i] = nonce[i].to_int()
    }
    j0[15] = 1
    return j0
  }
  let buf = Buffer()
  buf.write_bytesview(nonce)
  while buf.length() % 16 != 0 {
    buf.write_byte(b'\x00')
  }
  put64(buf, 0L)
  put64(buf, nonce.length().to_int64() * 8L)
  ghash(self.subkey, buf.to_bytes()[:])
}

///|
/// CTR-mode keystream XOR, starting from J0 incremented once — the data counter
/// begins at J0+1 (SP 800-38D §7.1 step 3).
fn Gcm::gctr(self : Gcm, j0 : FixedArray[Int], input : BytesView) -> Bytes {
  let counter = FixedArray::make(16, 0)
  for i in 0..<16 {
    counter[i] = j0[i]
  }
  inc32(counter)
  let out = Buffer()
  let mut off = 0
  while off < input.length() {
    let ks = self.cipher.encrypt(block(counter)[:])
    let n = if input.length() - off < 16 { input.length() - off } else { 16 }
    for j in 0..<n {
      out.write_byte((input[off + j].to_int() ^ ks[j].to_int()).to_byte())
    }
    inc32(counter)
    off = off + 16
  }
  out.to_bytes()
}

///|
/// `E(J0) XOR GHASH(A || C || lengths)`, truncated to the tag length
/// (SP 800-38D §7.1 steps 5 and 6).
fn Gcm::seal_tag(
  self : Gcm,
  j0 : FixedArray[Int],
  aad : BytesView,
  cipher : BytesView,
) -> Bytes {
  let buf = Buffer()
  buf.write_bytesview(aad)
  while buf.length() % 16 != 0 {
    buf.write_byte(b'\x00')
  }
  buf.write_bytesview(cipher)
  while buf.length() % 16 != 0 {
    buf.write_byte(b'\x00')
  }
  put64(buf, aad.length().to_int64() * 8L)
  put64(buf, cipher.length().to_int64() * 8L)
  let s = ghash(self.subkey, buf.to_bytes()[:])
  let mask = self.cipher.encrypt(block(j0)[:])
  let out = Array::make(self.tag, b'\x00')
  for i in 0..<self.tag {
    out[i] = (mask[i].to_int() ^ s[i]).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// Encrypt and authenticate, returning the ciphertext with its tag appended.
///
/// The nonce must never repeat under one key: GCM's confidentiality and its
/// authentication both collapse if it does, and recovering the hash subkey from
/// two messages sharing a nonce is arithmetic rather than cryptanalysis. That is
/// the caller's to guarantee, because only the caller knows where its nonces come
/// from.
pub fn Gcm::seal(
  self : Gcm,
  nonce~ : BytesView,
  plain~ : BytesView,
  aad? : BytesView = b""[:],
) -> Bytes {
  let j0 = self.start(nonce)
  let body = self.gctr(j0, plain)
  let out = Buffer()
  out.write_bytes(body)
  out.write_bytes(self.seal_tag(j0, aad, body[:]))
  out.to_bytes()
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
  aad? : BytesView = b""[:],
) -> Bytes raise @spec.Broken {
  guard cipher.length() >= self.tag else {
    raise @spec.Size(want=self.tag, got=cipher.length())
  }
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
