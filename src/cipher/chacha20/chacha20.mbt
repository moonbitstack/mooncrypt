// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The key length in bytes.
pub let key_size : Int32 = 32

///|
/// The nonce length in bytes.
pub let nonce_size : Int32 = 12

///|
/// A ChaCha20 key, ready to produce keystream for any nonce and counter.
pub struct Cipher {
  priv key : FixedArray[UInt32]
}

///|
fn le32(b : BytesView, at : Int32) -> UInt32 {
  b[at].to_uint() |
  (b[at + 1].to_uint() << 8) |
  (b[at + 2].to_uint() << 16) |
  (b[at + 3].to_uint() << 24)
}

///|
fn rotl(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
fn quarter(
  s : FixedArray[UInt32],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
) -> Unit {
  s[a] = s[a] + s[b]
  s[d] = rotl(s[d] ^ s[a], 16)
  s[c] = s[c] + s[d]
  s[b] = rotl(s[b] ^ s[c], 12)
  s[a] = s[a] + s[b]
  s[d] = rotl(s[d] ^ s[a], 8)
  s[c] = s[c] + s[d]
  s[b] = rotl(s[b] ^ s[c], 7)
}

///|
/// The cipher for a 32-byte `key`.
pub fn Cipher::new(key : BytesView) -> Cipher raise @spec.Broken {
  guard key.length() == key_size else {
    raise Size(want=key_size, got=key.length())
  }
  { key: FixedArray::makei(8, i => le32(key, 4 * i)), }
}

///|
/// The block-function output for `counter` and `nonce`: the state after 20
/// rounds, plus the state it started from.
fn Cipher::state(
  self : Cipher,
  counter : UInt32,
  nonce : FixedArray[UInt32],
) -> FixedArray[UInt32] {
  let init : FixedArray[UInt32] = [
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574,
    self.key[0],
    self.key[1],
    self.key[2],
    self.key[3],
    self.key[4],
    self.key[5],
    self.key[6],
    self.key[7],
    counter,
    nonce[0],
    nonce[1],
    nonce[2],
  ]
  let s = FixedArray::makei(16, i => init[i])
  for _ in 0..<10 {
    quarter(s, 0, 4, 8, 12)
    quarter(s, 1, 5, 9, 13)
    quarter(s, 2, 6, 10, 14)
    quarter(s, 3, 7, 11, 15)
    quarter(s, 0, 5, 10, 15)
    quarter(s, 1, 6, 11, 12)
    quarter(s, 2, 7, 8, 13)
    quarter(s, 3, 4, 9, 14)
  }
  for i in 0..<16 {
    s[i] = s[i] + init[i]
  }
  s
}

///|
fn nonce_words(nonce : BytesView) -> FixedArray[UInt32] raise @spec.Broken {
  guard nonce.length() == nonce_size else {
    raise Size(want=nonce_size, got=nonce.length())
  }
  FixedArray::makei(3, i => le32(nonce, 4 * i))
}

///|
/// One 64-byte keystream block for `counter` and `nonce` (RFC 8439 §2.3).
pub fn Cipher::block(
  self : Cipher,
  counter : UInt32,
  nonce : BytesView,
) -> Bytes raise @spec.Broken {
  let s = self.state(counter, nonce_words(nonce))
  Bytes::makei(64, i => (s[i / 4] >> (8 * (i % 4))).to_byte())
}

///|
/// `data` XORed with the keystream that starts at block `counter` (RFC 8439
/// §2.4): encryption and decryption are the same operation. The counter starts
/// at 0, as libsodium's does; AEAD_CHACHA20_POLY1305 starts the payload at 1.
pub fn Cipher::xor(
  self : Cipher,
  nonce~ : BytesView,
  data : BytesView,
  counter~ : UInt32 = 0,
) -> Bytes raise @spec.Broken {
  let n = nonce_words(nonce)
  let out = Array::make(data.length(), b'\x00')
  let mut block = counter
  let mut at = 0
  while at < data.length() {
    let s = self.state(block, n)
    let len = if data.length() - at < 64 { data.length() - at } else { 64 }
    for i in 0..<len {
      out[at + i] = data[at + i] ^ (s[i / 4] >> (8 * (i % 4))).to_byte()
    }
    at += 64
    block += 1
  }
  Bytes::from_array(out)
}

///|
/// HChaCha20, draft-irtf-cfrg-xchacha §2.2.
///
/// The same twenty rounds as [`Cipher::block`], with two changes: the nonce is
/// sixteen bytes and takes the whole fourth row, and the feed-forward addition
/// of the input state is left out. What comes back is therefore not keystream
/// but a value that looks like a key — which is exactly how XChaCha20 turns a
/// twenty-four byte nonce into the twelve-byte nonce ChaCha20 has room for.
///
/// The halves of the output that are kept are the first and last rows, the two
/// the nonce did not touch, so the derived key depends on the whole key and the
/// whole nonce.
pub fn hchacha20(
  key : BytesView,
  nonce : BytesView,
) -> Bytes raise @spec.Broken {
  guard key.length() == key_size else {
    raise Size(want=key_size, got=key.length())
  }
  guard nonce.length() == 16 else { raise Size(want=16, got=nonce.length()) }
  let s : FixedArray[UInt32] = FixedArray::make(16, 0)
  let constants : FixedArray[UInt32] = [
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
  ]
  for i in 0..<16 {
    if i < 4 {
      s[i] = constants[i]
    } else if i < 12 {
      s[i] = le32(key, 4 * (i - 4))
    } else {
      s[i] = le32(nonce, 4 * (i - 12))
    }
  }
  for _ in 0..<10 {
    quarter(s, 0, 4, 8, 12)
    quarter(s, 1, 5, 9, 13)
    quarter(s, 2, 6, 10, 14)
    quarter(s, 3, 7, 11, 15)
    quarter(s, 0, 5, 10, 15)
    quarter(s, 1, 6, 11, 12)
    quarter(s, 2, 7, 8, 13)
    quarter(s, 3, 4, 9, 14)
  }
  let out : Array[Byte] = []
  for i in [0, 1, 2, 3, 12, 13, 14, 15] {
    for b in 0..<4 {
      out.push((s[i] >> (8 * b)).to_byte())
    }
  }
  Bytes::from_array(out)
}
