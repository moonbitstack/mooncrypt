// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The block length, in bytes. AES is defined for one block size only; the key
/// is what varies.
pub let block : Int = 16

///|
/// The S-box (FIPS 197 §5.1.1): the multiplicative inverse in GF(2^8) followed
/// by the fixed affine transform.
let sbox : FixedArray[Byte] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
  0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
  0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
  0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
  0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
  0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
  0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
  0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
  0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
  0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
  0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
  0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16,
]

///|
/// The inverse S-box (FIPS 197 §5.3.2), derived from [`sbox`] at load rather
/// than written out again: a second table is a second thing to get wrong, and
/// the two must be inverses for decryption to mean anything.
let unsbox : FixedArray[Byte] = {
  let out = FixedArray::make(256, b'\x00')
  for i in 0..<256 {
    out[sbox[i].to_int()] = i.to_byte()
  }
  out
}

///|
/// The round constants (FIPS 197 §5.2): the high byte of each Rcon word, which
/// is `x^(i-1)` in GF(2^8). Fourteen rounds need ten of them at most.
let rcon : FixedArray[Byte] = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]

///|
/// Multiply by x in GF(2^8) with the AES reduction polynomial (FIPS 197 §4.2).
fn xtime(b : Int) -> Int {
  let s = (b << 1) & 0xff
  if (b & 0x80) != 0 {
    s ^ 0x1b
  } else {
    s
  }
}

///|
/// Multiply in GF(2^8). Only the inverse cipher needs the general form; the
/// forward direction gets by on [`xtime`] alone.
fn gmul(a : Int, b : Int) -> Int {
  let mut x = a
  let mut y = b
  let mut out = 0
  while y != 0 {
    if (y & 1) != 0 {
      out = out ^ x
    }
    x = xtime(x)
    y = y >> 1
  }
  out
}

///|
/// An expanded key.
///
/// The schedule is held in a [`FixedArray`] so it can be erased; see
/// [`@spec.wipe`] for why that matters and what it does not promise.
pub struct Cipher {
  schedule : FixedArray[Byte]
  rounds : Int
}

///|
/// Expand a key, which is 16, 24 or 32 bytes for AES-128, AES-192 or AES-256.
///
/// The key length is the only thing that distinguishes the three, so there is
/// no variant to name: `new` reads it off the key, as every AES interface in use
/// does. A length that is none of the three raises rather than being rounded to
/// one, because a key that is not the key is not a smaller mistake than no key.
pub fn Cipher::new(key : BytesView) -> Cipher raise @spec.Broken {
  let nk = match key.length() {
    16 => 4
    24 => 6
    32 => 8
    got => raise @spec.Size(want=16, got~)
  }
  let rounds = nk + 6
  let total = 16 * (rounds + 1)
  let w = FixedArray::make(total, b'\x00')
  for i in 0..<(nk * 4) {
    w[i] = key[i]
  }
  for i = nk * 4; i < total; i = i + 4 {
    let mut t0 = w[i - 4].to_int()
    let mut t1 = w[i - 3].to_int()
    let mut t2 = w[i - 2].to_int()
    let mut t3 = w[i - 1].to_int()
    let word = i / 4
    if word % nk == 0 {
      // RotWord, then SubWord, then the round constant into the first byte.
      let r0 = sbox[t1].to_int()
      let r1 = sbox[t2].to_int()
      let r2 = sbox[t3].to_int()
      let r3 = sbox[t0].to_int()
      t0 = r0 ^ rcon[word / nk - 1].to_int()
      t1 = r1
      t2 = r2
      t3 = r3
    } else if nk > 6 && word % nk == 4 {
      // AES-256 only: a second SubWord halfway through each key's worth of
      // words, without the rotation.
      t0 = sbox[t0].to_int()
      t1 = sbox[t1].to_int()
      t2 = sbox[t2].to_int()
      t3 = sbox[t3].to_int()
    }
    w[i] = (w[i - nk * 4].to_int() ^ t0).to_byte()
    w[i + 1] = (w[i - nk * 4 + 1].to_int() ^ t1).to_byte()
    w[i + 2] = (w[i - nk * 4 + 2].to_int() ^ t2).to_byte()
    w[i + 3] = (w[i - nk * 4 + 3].to_int() ^ t3).to_byte()
  }
  { schedule: w, rounds, }
}

///|
/// The key length in bytes: 16, 24 or 32.
pub fn Cipher::size(self : Cipher) -> Int {
  (self.rounds - 6) * 4
}

///|
/// The block length in bytes, which is 16 whatever the key.
pub fn Cipher::block(self : Cipher) -> Int {
  ignore(self)
  block
}

///|
/// Forget the expanded key. See [`@spec.wipe`] for what that is worth.
pub fn Cipher::wipe(self : Cipher) -> Unit {
  @spec.wipe(self.schedule)
}

///|
/// Encrypt one block (FIPS 197 §5.1 Cipher).
///
/// The state is column-major: byte `k` is row `k % 4`, column `k / 4`.
pub fn Cipher::encrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("aes: a block is \{block} bytes, not \{input.length()}")
  }
  let s = FixedArray::make(16, 0)
  for i in 0..<16 {
    s[i] = input[i].to_int() ^ self.schedule[i].to_int()
  }
  let t = FixedArray::make(16, 0)
  for round in 1..<=self.rounds {
    for i in 0..<16 {
      s[i] = sbox[s[i]].to_int()
    }
    // ShiftRows: row r rotates left by r.
    for r in 0..<4 {
      for c in 0..<4 {
        t[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
      }
    }
    for i in 0..<16 {
      s[i] = t[i]
    }
    // MixColumns, which the last round leaves out.
    if round != self.rounds {
      for c in 0..<4 {
        let a0 = s[4 * c]
        let a1 = s[4 * c + 1]
        let a2 = s[4 * c + 2]
        let a3 = s[4 * c + 3]
        s[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
        s[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
        s[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
        s[4 * c + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)
      }
    }
    for i in 0..<16 {
      s[i] = s[i] ^ self.schedule[16 * round + i].to_int()
    }
  }
  let out = Array::make(16, b'\x00')
  for i in 0..<16 {
    out[i] = s[i].to_byte()
  }
  Bytes::from_array(out)
}

///|
/// Decrypt one block (FIPS 197 §5.3 InvCipher).
pub fn Cipher::decrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("aes: a block is \{block} bytes, not \{input.length()}")
  }
  let s = FixedArray::make(16, 0)
  for i in 0..<16 {
    s[i] = input[i].to_int() ^ self.schedule[16 * self.rounds + i].to_int()
  }
  let t = FixedArray::make(16, 0)
  for round = self.rounds - 1; round >= 0; round = round - 1 {
    // InvShiftRows: row r rotates right by r.
    for r in 0..<4 {
      for c in 0..<4 {
        t[r + 4 * c] = s[r + 4 * ((c - r + 4) % 4)]
      }
    }
    for i in 0..<16 {
      s[i] = unsbox[t[i]].to_int()
    }
    for i in 0..<16 {
      s[i] = s[i] ^ self.schedule[16 * round + i].to_int()
    }
    // InvMixColumns, which the first round undone leaves out.
    if round != 0 {
      for c in 0..<4 {
        let a0 = s[4 * c]
        let a1 = s[4 * c + 1]
        let a2 = s[4 * c + 2]
        let a3 = s[4 * c + 3]
        s[4 * c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        s[4 * c + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        s[4 * c + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        s[4 * c + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)
      }
    }
  }
  let out = Array::make(16, b'\x00')
  for i in 0..<16 {
    out[i] = s[i].to_byte()
  }
  Bytes::from_array(out)
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
