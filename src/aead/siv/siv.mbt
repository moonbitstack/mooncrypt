// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The tag length in bytes, which for SIV is also the length of the synthetic IV.
pub let tag : Int32 = 16

///|
/// The block every block cipher here has to be.
let width : Int32 = 16

///|
/// Split a key into the two halves SIV wants.
///
/// RFC 5297 §2.6 divides the key into K1, which drives the CMAC, and K2, which
/// drives the counter. The halves must be independent: reusing one key for both
/// halves would let the CTR keystream be related to the CMAC output, and the
/// construction's security argument assumes they are separate.
pub fn halves(key : BytesView) -> (Bytes, Bytes) raise @spec.Broken {
  guard key.length() % 2 == 0 && key.length() >= 2 else {
    raise @spec.Broken::Size(want=2, got=key.length())
  }
  let half = key.length() / 2
  (key[0:half].to_owned(), key[half:].to_owned())
}

///|
/// SIV over two 128-bit block ciphers.
///
/// The two ciphers are keyed separately — see [`halves`] — and the same object
/// can seal any number of messages. It also keeps one CMAC context between
/// calls so that the two subkeys are not recomputed for every block of every
/// message.
pub struct Siv {
  ///
  /// The CMAC that produces the synthetic IV, keyed with K1.
  mac : @cmac.Cmac
  ///
  /// The cipher the counter mode runs on, keyed with K2.
  ctr : &@spec.Block
}

///|
/// Wrap two block ciphers in SIV.
///
/// `mac` produces and checks the synthetic IV and must be keyed with K1; `ctr`
/// encrypts and must be keyed with K2. Both must have a sixteen-byte block.
pub fn Siv::new(
  mac : &@spec.Block,
  ctr : &@spec.Block,
) -> Siv raise @spec.Broken {
  guard mac.block() == width else {
    raise @spec.Broken::Size(want=width, got=mac.block())
  }
  guard ctr.block() == width else {
    raise @spec.Broken::Size(want=width, got=ctr.block())
  }
  { mac: @cmac.Cmac::new(mac, tag=width), ctr, }
}

///|
/// The tag length in bytes.
pub fn Siv::size(self : Siv) -> Int32 {
  self.mac.size()
}

///|
/// One CMAC of `msg` under K1, reusing the context.
fn Siv::cmac(self : Siv, msg : BytesView) -> FixedArray[Byte] {
  self.mac.reset()
  self.mac.write(msg)
  let out = self.mac.finish()
  let block : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  for i in 0..<width {
    block[i] = out[i]
  }
  block
}

///|
/// Multiply by x in GF(2^128), RFC 5297 §2.3: shift left one bit and, if a bit
/// fell off the top, xor the reduction polynomial into the last byte.
fn dbl(block : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  let mut carry = 0
  for i in 0..<width {
    let at = width - 1 - i
    let v = block[at].to_int()
    out[at] = (((v << 1) & 0xFF) | carry).to_byte()
    carry = (v >> 7) & 1
  }
  if carry != 0 {
    out[15] = (out[15].to_int() ^ 0x87).to_byte()
  }
  out
}

///|
/// `a xor b`, both sixteen bytes.
fn xor(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  for i in 0..<width {
    out[i] = (a[i].to_int() ^ b[i].to_int()).to_byte()
  }
  out
}

///|
/// RFC 5297 §2.1: a one bit, then zeroes, out to a block. `data` must be
/// shorter than a block.
fn pad(data : BytesView) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  for i in 0..<data.length() {
    out[i] = data[i]
  }
  out[data.length()] = b'\x80'
  out
}

///|
/// RFC 5297 §2.1: xor `d` onto the end of `data`, which must be at least as long
/// as `d`.
fn xorend(data : BytesView, d : FixedArray[Byte]) -> Bytes {
  let out : Array[Byte] = []
  let start = data.length() - width
  for i in 0..<start {
    out.push(data[i])
  }
  for i in 0..<width {
    out.push((data[start + i].to_int() ^ d[i].to_int()).to_byte())
  }
  Bytes::from_array(out)
}

///|
/// The synthetic IV: RFC 5297 §2.4, over a vector of associated data ending in
/// the plaintext.
///
/// The loop doubles the running value for every component it absorbs, so the
/// position of a component in the vector is part of what it commits to. The last
/// component is treated differently from the rest — if it fills a whole block it
/// is xored with the running value in place, and if it does not it is padded to
/// one first — which is what stops a message ending in extra zero bytes from
/// authenticating as the same thing as a shorter one.
fn Siv::iv(self : Siv, ads : Array[BytesView], last : BytesView) -> Bytes {
  let zero : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  let mut d = self.cmac(Bytes::from_array(zero)[:])
  for ad in ads {
    d = xor(dbl(d), self.cmac(ad))
  }
  let t = if last.length() >= width {
    xorend(last, d)
  } else {
    let padded = pad(last)
    Bytes::from_array(xor(dbl(d), padded))
  }
  Bytes::from_array(self.cmac(t[:]))
}

///|
/// Add one to the low 64 bits of the counter block, in place.
///
/// RFC 5297 §2.5 clears bits 31 and 63 of the IV before the counter starts, so
/// a carry out of the low 64 bits cannot happen and a plain 64-bit increment is
/// indistinguishable from a 128-bit one. That is the whole reason those two bits
/// are cleared.
fn bump(counter : FixedArray[Byte]) -> Unit {
  let mut i = 15
  while i >= 8 {
    let v = (counter[i].to_int() + 1) & 0xFF
    counter[i] = v.to_byte()
    if v != 0 {
      return
    }
    i = i - 1
  }
}

///|
/// Counter mode over `data`, starting from the synthetic IV, with a fresh
/// keystream block for every sixteen bytes. The same call encrypts and decrypts,
/// because it is the same xor either way.
fn Siv::count(self : Siv, iv : BytesView, data : BytesView) -> Bytes {
  let counter : FixedArray[Byte] = FixedArray::make(width, b'\x00')
  for i in 0..<width {
    counter[i] = iv[i]
  }
  counter[8] = (counter[8].to_int() & 0x7F).to_byte()
  counter[12] = (counter[12].to_int() & 0x7F).to_byte()
  let out : FixedArray[Byte] = FixedArray::make(data.length(), b'\x00')
  let mut at = 0
  while at < data.length() {
    let stream = self.ctr.encrypt(Bytes::from_array(counter))
    let take = if data.length() - at < width {
      data.length() - at
    } else {
      width
    }
    for i in 0..<take {
      out[at + i] = (data[at + i].to_int() ^ stream[i].to_int()).to_byte()
    }
    at = at + take
    bump(counter)
  }
  Bytes::from_array(out)
}

///|
/// Seal with a vector of associated data, RFC 5297 §2.6.
///
/// The result is the synthetic IV followed by the ciphertext — the IV first,
/// unlike GCM and CCM, which append the tag. A non-empty `nonce` becomes the
/// last associated data component, which is the nonce-based mode of §2.6: it
/// costs nothing extra and makes a repeated message look different.
///
/// Passing the components as a vector rather than one string is the point of
/// SIV: `["user", "1"]` and `["user1"]` are different messages, and a header
/// that is parsed in two places can be authenticated field by field without
/// having to be re-serialised.
pub fn Siv::seal_with(
  self : Siv,
  plain : BytesView,
  ads : Array[BytesView],
  nonce~ : BytesView = b"",
) -> Bytes {
  let all = if nonce.length() > 0 {
    let v = ads.copy()
    v.push(nonce)
    v
  } else {
    ads
  }
  let iv = self.iv(all, plain)
  iv + self.count(iv[:], plain)
}

///|
/// Open with a vector of associated data, RFC 5297 §2.7.
///
/// Authenticates before anything is returned, and compares the recomputed IV to
/// the one that came with the ciphertext in constant time.
pub fn Siv::open_with(
  self : Siv,
  box : BytesView,
  ads : Array[BytesView],
  nonce~ : BytesView = b"",
) -> Bytes raise @spec.Broken {
  guard box.length() >= tag else {
    raise @spec.Broken::Size(want=tag, got=box.length())
  }
  let iv = box[0:tag]
  let body = box[tag:]
  let plain = self.count(iv, body)
  let all = if nonce.length() > 0 {
    let v = ads.copy()
    v.push(nonce)
    v
  } else {
    ads
  }
  let want = self.iv(all, plain[:])
  guard @spec.eq(want[:], iv) else { raise @spec.Broken::Tag }
  plain
}

///|
/// Seal with one associated data string, which is all most callers have.
pub fn Siv::seal(
  self : Siv,
  nonce~ : BytesView,
  plain~ : BytesView,
  aad~ : BytesView = b"",
) -> Bytes {
  self.seal_with(plain, [aad], nonce~)
}

///|
/// Open with one associated data string.
pub fn Siv::open(
  self : Siv,
  nonce~ : BytesView,
  cipher~ : BytesView,
  aad~ : BytesView = b"",
) -> Bytes raise @spec.Broken {
  self.open_with(cipher, [aad], nonce~)
}

///|
/// Seal in one call, with a context that lives just long enough.
pub fn seal(
  mac : &@spec.Block,
  ctr : &@spec.Block,
  nonce~ : BytesView,
  plain~ : BytesView,
  aad~ : BytesView = b"",
) -> Bytes raise @spec.Broken {
  Siv::new(mac, ctr).seal(nonce~, plain~, aad~)
}

///|
/// Open in one call.
pub fn open(
  mac : &@spec.Block,
  ctr : &@spec.Block,
  nonce~ : BytesView,
  cipher~ : BytesView,
  aad~ : BytesView = b"",
) -> Bytes raise @spec.Broken {
  Siv::new(mac, ctr).open(nonce~, cipher~, aad~)
}

///|
/// For an empty associated data string, the one-string form would authenticate
/// a single empty component, which is not the same computation as authenticating
/// no component at all. That difference is deliberate — it is what RFC 5297
/// gives when it is handed one empty string — and this comment exists so nobody
/// "fixes" it.
pub impl @spec.Aead for Siv with fn seal(self, nonce~, plain~, aad~) {
  self.seal(nonce~, plain~, aad~)
}

///|
pub impl @spec.Aead for Siv with fn open(self, nonce~, cipher~, aad~) {
  self.open(nonce~, cipher~, aad~)
}
