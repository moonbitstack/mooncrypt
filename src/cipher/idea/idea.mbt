// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The block length in bytes.
pub let block : Int32 = 8

///|
/// The key length in bytes: one, 16.
pub let key_size : Int32 = 16

///|
/// Multiplication modulo 2^16 + 1, the zero word standing for 2^16.
fn mul(a : Int32, b : Int32) -> Int32 {
  if a == 0 {
    return (0x10001 - b) & 0xFFFF
  }
  if b == 0 {
    return (0x10001 - a) & 0xFFFF
  }
  let p = a.to_int64() * b.to_int64()
  let lo = (p & 0xFFFFL).to_int()
  let hi = (p >> 16).to_int()
  (lo - hi + (if lo < hi { 1 } else { 0 })) & 0xFFFF
}

///|
/// The inverse under `mul`. 0 and 1 are their own: 0 stands for 2^16, which is -1.
fn inverse(x : Int32) -> Int32 {
  if x <= 1 {
    return x
  }
  // Extended Euclid over 2^16 + 1, which is prime.
  let mut r0 = 0x10001
  let mut r1 = x
  let mut t0 = 0
  let mut t1 = 1
  while r1 != 0 {
    let q = r0 / r1
    let r = r0 - q * r1
    r0 = r1
    r1 = r
    let t = t0 - q * t1
    t0 = t1
    t1 = t
  }
  (if t0 < 0 { t0 + 0x10001 } else { t0 }) & 0xFFFF
}

///|
fn negate(x : Int32) -> Int32 {
  (0x10000 - x) & 0xFFFF
}

///|
/// An IDEA key schedule: 52 subkeys for encryption and their inverses for decryption.
pub struct Cipher {
  ek : FixedArray[Int32]
  dk : FixedArray[Int32]
}

///|
/// Expand a 16-byte key: eight 16-bit subkeys at a time, the key turned left by 25 bits between
/// each eight.
pub fn Cipher::new(key : BytesView) -> Cipher raise @spec.Broken {
  guard key.length() == key_size else {
    raise Size(want=key_size, got=key.length())
  }
  let mut hi = 0UL
  let mut lo = 0UL
  for i in 0..<8 {
    hi = (hi << 8) | key[i].to_uint64()
    lo = (lo << 8) | key[8 + i].to_uint64()
  }
  let ek = FixedArray::make(52, 0)
  for i in 0..<52 {
    let j = i % 8
    if i > 0 && j == 0 {
      let h = hi
      hi = (hi << 25) | (lo >> 39)
      lo = (lo << 25) | (h >> 39)
    }
    let word = if j < 4 {
      hi >> (48 - 16 * j)
    } else {
      lo >> (48 - 16 * (j - 4))
    }
    ek[i] = (word & 0xFFFFUL).to_int()
  }
  { ek, dk: invert(ek), }
}

///|
/// The decryption subkeys: the encryption ones in reverse order, multiplicative ones inverted,
/// additive ones negated, and the additive pair of every round but the first and last swapped,
/// which undoes the middle words' exchange.
fn invert(ek : FixedArray[Int32]) -> FixedArray[Int32] {
  let dk = FixedArray::make(52, 0)
  for r in 0..<9 {
    let e = 48 - 6 * r
    let d = 6 * r
    let outer = r == 0 || r == 8
    dk[d] = inverse(ek[e])
    dk[d + 1] = negate(ek[e + (if outer { 1 } else { 2 })])
    dk[d + 2] = negate(ek[e + (if outer { 2 } else { 1 })])
    dk[d + 3] = inverse(ek[e + 3])
    if r < 8 {
      dk[d + 4] = ek[e - 2]
      dk[d + 5] = ek[e - 1]
    }
  }
  dk
}

///|
fn run(z : FixedArray[Int32], input : BytesView) -> Bytes {
  let w = (i : Int32) => {
    (input[2 * i].to_int() << 8) | input[2 * i + 1].to_int()
  }
  let mut x1 = w(0)
  let mut x2 = w(1)
  let mut x3 = w(2)
  let mut x4 = w(3)
  for r in 0..<8 {
    let k = 6 * r
    x1 = mul(x1, z[k])
    x2 = (x2 + z[k + 1]) & 0xFFFF
    x3 = (x3 + z[k + 2]) & 0xFFFF
    x4 = mul(x4, z[k + 3])
    let t2 = mul(x1 ^ x3, z[k + 4])
    let t1 = mul((t2 + (x2 ^ x4)) & 0xFFFF, z[k + 5])
    let t0 = (t1 + t2) & 0xFFFF
    x1 = x1 ^ t1
    x4 = x4 ^ t0
    let middle = x2 ^ t0
    x2 = x3 ^ t1
    x3 = middle
  }
  // The output transformation undoes the last round's exchange of the middle words.
  let out = [
    mul(x1, z[48]),
    (x3 + z[49]) & 0xFFFF,
    (x2 + z[50]) & 0xFFFF,
    mul(x4, z[51]),
  ]
  Bytes::makei(8, i => {
    let v = out[i / 2]
    (if i % 2 == 0 { v >> 8 } else { v & 0xFF }).to_byte()
  })
}

///|
/// Encrypt one 8-byte block.
pub fn Cipher::encrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("idea: a block is 8 bytes, not \{input.length()}")
  }
  run(self.ek, input)
}

///|
/// Decrypt one 8-byte block.
pub fn Cipher::decrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("idea: a block is 8 bytes, not \{input.length()}")
  }
  run(self.dk, input)
}

///|
/// The block length in bytes.
pub fn Cipher::block(self : Cipher) -> Int32 {
  ignore(self)
  block
}

///|
/// Overwrite both subkey sets.
pub fn Cipher::wipe(self : Cipher) -> Unit {
  self.ek.fill(0)
  self.dk.fill(0)
}

///|
pub impl @spec.Block for Cipher with fn block(self) {
  self.block()
}

///|
pub impl @spec.Block for Cipher with fn encrypt(self, input) {
  self.encrypt(input)
}

///|
pub impl @spec.Block for Cipher with fn decrypt(self, input) {
  self.decrypt(input)
}

///|
pub impl @spec.Block for Cipher with fn encrypt_blocks(self, input) {
  @spec.blockwise(input, block, b => self.encrypt(b))
}

///|
pub impl @spec.Block for Cipher with fn decrypt_blocks(self, input) {
  @spec.blockwise(input, block, b => self.decrypt(b))
}

///|
pub extend Cipher with @spec.Block::{decrypt_blocks, encrypt_blocks}
