// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The longest key the algorithm has room for.
///
/// The key is used to seed a permutation of 256 bytes, so anything longer than
/// 256 bytes would be folded back onto itself. Shorter keys are the practical
/// case: 5, 13 and 16 bytes cover WEP, WPA-TKIP and Kerberos.
pub let max_key_size : Int32 = 256

///|
/// An RC4 keystream.
///
/// The state advances as bytes are produced, so one `Cipher` encrypts a stream
/// and cannot be rewound. Two messages under the same key therefore need two
/// instances — or, in practice, two keys, because reusing one is what broke WEP.
pub struct Cipher {
  state : FixedArray[Byte]
  mut i : Byte
  mut j : Byte
}

///|
/// Key the cipher: the key-scheduling algorithm of RFC 6229 §2.1.
///
/// The permutation starts as the identity and is then shuffled by the key, one
/// swap per byte. A key of zero bytes is refused — it has no entropy to begin
/// with, and accepting it would make an empty key and a missing key both
/// "RC4 with nothing".
pub fn Cipher::new(key : BytesView) -> Cipher raise @spec.Broken {
  guard key.length() > 0 else { raise Size(want=1, got=0) }
  guard key.length() <= max_key_size else {
    raise Size(want=max_key_size, got=key.length())
  }
  let state = FixedArray::makei(256, i => i.to_byte())
  let mut j = 0
  for i in 0..<256 {
    j = (j + state[i].to_int() + key[i % key.length()].to_int()) % 256
    let tmp = state[i]
    state[i] = state[j]
    state[j] = tmp
  }
  { state, i: b'\x00', j: b'\x00', }
}

///|
/// The next byte of keystream (RFC 6229 §2.2).
///
/// One swap and two lookups: the generator is four lines long, which is why it
/// could be implemented from memory in every language, and why the statistical
/// weakness is worth taking seriously rather than checking for.
pub fn Cipher::next(self : Cipher) -> Byte {
  self.i = (self.i.to_int() + 1).to_byte()
  self.j = (self.j.to_int() + self.state[self.i.to_int()].to_int()).to_byte()
  let tmp = self.state[self.i.to_int()]
  self.state[self.i.to_int()] = self.state[self.j.to_int()]
  self.state[self.j.to_int()] = tmp
  let at = (
      self.state[self.i.to_int()].to_int() +
      self.state[self.j.to_int()].to_int()
    ) %
    256
  self.state[at]
}

///|
/// The next `n` bytes of keystream.
pub fn Cipher::keystream(self : Cipher, n : Int32) -> Bytes {
  let out = Array::make(n, b'\x00')
  for i in 0..<n {
    out[i] = self.next()
  }
  Bytes::from_array(out)
}

///|
/// `data` XORed with the keystream that follows the current state: encryption
/// and decryption are the same operation, which is what a stream cipher means.
pub fn Cipher::xor(self : Cipher, data : BytesView) -> Bytes {
  let out = Array::make(data.length(), b'\x00')
  for i in 0..<data.length() {
    out[i] = data[i] ^ self.next()
  }
  Bytes::from_array(out)
}

///|
/// Encrypt `data` in one call, starting from the beginning of the keystream.
pub fn rc4(key : BytesView, data : BytesView) -> Bytes raise @spec.Broken {
  Cipher::new(key).xor(data)
}

///|
/// The first `n` bytes of keystream for `key`, without consuming a cipher.
pub fn keystream(key : BytesView, n : Int32) -> Bytes raise @spec.Broken {
  Cipher::new(key).keystream(n)
}
