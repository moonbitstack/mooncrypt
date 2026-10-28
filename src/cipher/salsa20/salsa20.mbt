// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The key length in bytes.
///
/// Salsa20 also defines a sixteen-byte key, which uses a different constant in
/// the middle of the state; only the thirty-two byte form is here, because it is
/// the one that appears in every protocol that uses Salsa20 at all.
pub let key_size : Int32 = 32

///|
/// The nonce length in bytes. Salsa20 proper has sixty-four bits of nonce and
/// sixty-four of counter, which is what XSalsa20 extends with a longer nonce.
pub let nonce_size : Int32 = 8

///|
/// A Salsa20 key, ready to produce keystream for any nonce and counter.
pub struct Cipher {
  key : FixedArray[UInt32]
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
/// The Salsa20 quarter round: four additions, four rotations and four xors, on
/// four words of the state.
///
/// The rotated word is added to the *previous* output rather than to the original
/// state word, which is what makes the round a chain rather than four independent
/// mixtures — and is the one place Salsa20 differs from ChaCha20's round.
fn quarter(
  s : FixedArray[UInt32],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
) -> Unit {
  s[b] = s[b] ^ rotl(s[a] + s[d], 7)
  s[c] = s[c] ^ rotl(s[b] + s[a], 9)
  s[d] = s[d] ^ rotl(s[c] + s[b], 13)
  s[a] = s[a] ^ rotl(s[d] + s[c], 18)
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
/// The state the block function starts from: four constants, the key, the nonce
/// and the block counter.
///
/// The layout is the one thing worth checking twice. The constants sit on the
/// diagonal, the key fills two columns either side of it, and the nonce and
/// counter share the middle — so a version that puts the nonce where the counter
/// belongs produces keystream that is perfectly random and completely wrong.
fn Cipher::state(
  self : Cipher,
  counter : UInt64,
  nonce : FixedArray[UInt32],
) -> FixedArray[UInt32] {
  FixedArray::from_array([
    0x61707865, // "expa"
    self.key[0],
    self.key[1],
    self.key[2],
    self.key[3],
    0x3320646e, // "nd 3"
    nonce[0],
    nonce[1],
    (counter & 0xFFFFFFFFUL).to_uint(),
    (counter >> 32).to_uint(),
    0x79622d32, // "2-by"
    self.key[4],
    self.key[5],
    self.key[6],
    self.key[7],
    0x6b206574, // "te k"
  ])
}

///|
/// The twenty rounds, then the feed-forward addition of the starting state.
fn Cipher::core(
  self : Cipher,
  counter : UInt64,
  nonce : FixedArray[UInt32],
) -> FixedArray[UInt32] {
  let init = self.state(counter, nonce)
  let s = FixedArray::makei(16, i => init[i])
  for _ in 0..<10 {
    // Column round: the four columns of the matrix.
    quarter(s, 0, 4, 8, 12)
    quarter(s, 5, 9, 13, 1)
    quarter(s, 10, 14, 2, 6)
    quarter(s, 15, 3, 7, 11)
    // Row round: the four rows.
    quarter(s, 0, 1, 2, 3)
    quarter(s, 5, 6, 7, 4)
    quarter(s, 10, 11, 8, 9)
    quarter(s, 15, 12, 13, 14)
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
  FixedArray::makei(2, i => le32(nonce, 4 * i))
}

///|
/// One 64-byte keystream block for `counter` and `nonce`.
///
/// The counter is 64 bits. That is not academic: a 32-bit counter wraps after
/// 256 GiB of keystream, and two blocks that share a counter share their keystream
/// entirely.
pub fn Cipher::block(
  self : Cipher,
  counter : UInt64,
  nonce : BytesView,
) -> Bytes raise @spec.Broken {
  let s = self.core(counter, nonce_words(nonce))
  Bytes::makei(64, i => (s[i / 4] >> (8 * (i % 4))).to_byte())
}

///|
/// `data` XORed with the keystream that starts at block `counter`: encryption and
/// decryption are the same operation.
pub fn Cipher::xor(
  self : Cipher,
  nonce~ : BytesView,
  data : BytesView,
  counter~ : UInt64 = 0UL,
) -> Bytes raise @spec.Broken {
  let n = nonce_words(nonce)
  let out = Array::make(data.length(), b'\x00')
  let mut block = counter
  let mut at = 0
  while at < data.length() {
    let s = self.core(block, n)
    let len = if data.length() - at < 64 { data.length() - at } else { 64 }
    for i in 0..<len {
      out[at + i] = data[at + i] ^ (s[i / 4] >> (8 * (i % 4))).to_byte()
    }
    at += 64
    block += 1UL
  }
  Bytes::from_array(out)
}

///|
/// `n` bytes of keystream from the start.
pub fn stream(
  key : BytesView,
  nonce : BytesView,
  n : Int32,
) -> Bytes raise @spec.Broken {
  Cipher::new(key).xor(nonce~, zeroes(n))
}

///|
/// Encrypt `data` in one call, starting from block zero.
pub fn salsa20(
  key : BytesView,
  nonce : BytesView,
  data : BytesView,
) -> Bytes raise @spec.Broken {
  Cipher::new(key).xor(nonce~, data)
}

///|
fn zeroes(n : Int32) -> Bytes {
  Bytes::make(n, b'\x00')
}
