// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The block length, in bytes. AES is defined for one block size only; the key
/// is what varies.
pub let block : Int32 = 16

///|
/// An expanded key, in the bit-plane layout the bitsliced core reads.
///
/// It is held in a [`FixedArray`] so it can be erased; see [`@spec.wipe`] for
/// what that is worth and what it does not promise.
pub struct Cipher {
  rounds : Int32
  enc : FixedArray[UInt64]
}

///|
/// Expand a key, which is 16, 24 or 32 bytes for AES-128, AES-192 or AES-256.
///
/// The key length is the only thing that distinguishes the three, so there is
/// no variant to name: `new` reads it off the key, as every AES interface in use
/// does. A length that is none of the three raises rather than being rounded to
/// one, because a key that is not the key is not a smaller mistake than no key.
pub fn Cipher::new(key : BytesView) -> Cipher raise @spec.Broken {
  match key.length() {
    16 | 24 | 32 => ()
    got => raise @spec.Size(want=16, got~)
  }
  let (rounds, enc) = round_keys(key)
  { rounds, enc, }
}

///|
/// The key length in bytes: 16, 24 or 32.
pub fn Cipher::size(self : Cipher) -> Int32 {
  (self.rounds - 6) * 4
}

///|
/// The block length in bytes, which is 16 whatever the key.
pub fn Cipher::block(self : Cipher) -> Int32 {
  ignore(self)
  block
}

///|
/// Forget the expanded key. See [`@spec.wipe`] for what that is worth.
pub fn Cipher::wipe(self : Cipher) -> Unit {
  for i in 0..<self.enc.length() {
    self.enc[i] = 0UL
  }
}

///|
/// Encrypt one block.
///
/// The state is transposed into eight bit planes and advanced by the bitsliced
/// core, which always moves four blocks' worth of bits; the other three lanes
/// are zero and discarded. A caller encrypting many blocks at once should use
/// [`encrypt_blocks`], where those lanes carry real data.
pub fn Cipher::encrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("aes: a block is \{block} bytes, not \{input.length()}")
  }
  run(self.rounds, self.enc, input, false)
}

///|
/// Decrypt one block.
pub fn Cipher::decrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("aes: a block is \{block} bytes, not \{input.length()}")
  }
  run(self.rounds, self.enc, input, true)
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
/// Encrypt every [`block`]-byte slice of `input` at once, four lanes in flight.
pub impl @spec.Block for Cipher with fn encrypt_blocks(self, input) {
  guard input.length() % block == 0 else {
    abort(
      "aes: the input is not a whole number of blocks (\{input.length()} bytes, block is \{block})",
    )
  }
  run(self.rounds, self.enc, input, false)
}

///|
/// Decrypt every [`block`]-byte slice of `input` at once.
pub impl @spec.Block for Cipher with fn decrypt_blocks(self, input) {
  guard input.length() % block == 0 else {
    abort(
      "aes: the input is not a whole number of blocks (\{input.length()} bytes, block is \{block})",
    )
  }
  run(self.rounds, self.enc, input, true)
}

///|
pub extend Cipher with @spec.Block::{decrypt_blocks, encrypt_blocks}
