// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The key length in bytes.
pub let key_size : Int32 = 32

///|
/// The nonce length in bytes.
pub let nonce_size : Int32 = 24

///|
/// How many bytes of the nonce HChaCha20 consumes, which is also the ChaCha20
/// key length.
let split : Int32 = 16

///|
/// An XChaCha20 key, ready to produce keystream for any nonce and counter.
///
/// The key is kept rather than the derived subkeys, because a subkey belongs to
/// one nonce and a cipher is made once and used with many.
pub struct Cipher {
  priv key : FixedArray[Byte]
}

///|
/// The cipher for a 32-byte `key`.
pub fn Cipher::new(key : BytesView) -> Cipher raise @spec.Broken {
  guard key.length() == key_size else {
    raise @spec.Broken::Size(want=key_size, got=key.length())
  }
  let held : FixedArray[Byte] = FixedArray::make(key_size, b'\x00')
  for i in 0..<key_size {
    held[i] = key[i]
  }
  { key: held, }
}

///|
/// The subkey HChaCha20 derives from a 32-byte `key` and a 16-byte `nonce`.
///
/// This is ChaCha20's block function with the feed-forward left out, so what
/// comes back is a value that looks like a key. It is public because it is
/// useful on its own — libsodium's sealed boxes derive a key from a shared
/// secret and a nonce the same way — and because it is the one part of XChaCha20
/// a reader is likely to want to check in isolation.
pub fn subkey(key : BytesView, nonce : BytesView) -> Bytes raise @spec.Broken {
  guard key.length() == key_size else {
    raise @spec.Broken::Size(want=key_size, got=key.length())
  }
  guard nonce.length() == split else {
    raise @spec.Broken::Size(want=split, got=nonce.length())
  }
  @chacha20.hchacha20(key, nonce)
}

///|
/// The twelve-byte ChaCha20 nonce that goes with a twenty-four byte XChaCha20
/// nonce: four zero bytes, then the last eight of the input.
///
/// The zeros are not padding. They fill the high half of the 96-bit nonce field,
/// and both the draft and libsodium specify them, so leaving them out gives a
/// different keystream and messages that no other implementation can read.
fn tail(nonce : BytesView) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(@chacha20.nonce_size, b'\x00')
  for i in 4..<@chacha20.nonce_size {
    out[i] = nonce[split + i - 4]
  }
  Bytes::from_array(out)
}

///|
/// The subkey this cipher derives for `nonce`, which must be twenty-four bytes.
fn Cipher::subkey(
  self : Cipher,
  nonce : BytesView,
) -> @chacha20.Cipher raise @spec.Broken {
  guard nonce.length() == nonce_size else {
    raise @spec.Broken::Size(want=nonce_size, got=nonce.length())
  }
  let derived = subkey(Bytes::from_array(self.key)[:], nonce[0:split])
  @chacha20.Cipher::new(derived[:])
}

///|
/// One 64-byte keystream block for `counter` and a 24-byte `nonce`.
pub fn Cipher::block(
  self : Cipher,
  counter : UInt32,
  nonce : BytesView,
) -> Bytes raise @spec.Broken {
  self.subkey(nonce).block(counter, tail(nonce))
}

///|
/// `data` XORed with the keystream that starts at block `counter`. Encryption
/// and decryption are the same operation.
///
/// The counter starts at 0, matching [`@chacha20`]; XChaCha20-Poly1305 starts its
/// payload at 1 because block 0 is spent on the Poly1305 key.
pub fn Cipher::xor(
  self : Cipher,
  nonce~ : BytesView,
  data : BytesView,
  counter~ : UInt32 = 0,
) -> Bytes raise @spec.Broken {
  self.subkey(nonce).xor(nonce=tail(nonce), data, counter~)
}
