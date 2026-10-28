// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The block length in bytes. Sixty-four bits, which is why this cipher is only
/// safe inside something that does not care about birthday bounds — bcrypt, for
/// instance, encrypts a fixed 24-byte string and nothing else.
pub let block : Int32 = 8

///|
/// The shortest key the original specification allows.
pub let min_key : Int32 = 4

///|
/// The longest key the original specification allows.
pub let max_key : Int32 = 56

///|
/// How many bytes the bcrypt key schedule may feed it: 72 characters plus the
/// terminator that the format appends.
pub let eks_max_key : Int32 = 73

///|
/// A Blowfish key schedule. The subkeys are the whole state; there is nothing
/// else to keep.
pub struct Cipher {
  ///
  /// Eighteen round subkeys, mixed into the halves before and after the rounds.
  p : FixedArray[UInt32]
  ///
  /// Four 256-word S-boxes, laid end to end, so box `n` starts at `n * 256`.
  s : FixedArray[UInt32]
}

///|
/// A key schedule that has not been keyed yet: the digits of pi, and nothing
/// else.
fn fresh() -> Cipher {
  let p : FixedArray[UInt32] = FixedArray::make(18, 0U)
  for i in 0..<18 {
    p[i] = p_initial[i]
  }
  let s : FixedArray[UInt32] = FixedArray::make(1024, 0U)
  for i in 0..<1024 {
    s[i] = s_initial[i]
  }
  { p, s, }
}

///|
/// Four bytes of a byte string, read cyclically, as one big-endian word.
///
/// Both the key and the salt are consumed this way: the schedule keeps eating
/// words and wraps around when it runs out, so a four-byte key and a
/// seventy-byte key are equally usable and a sixteen-byte salt is reused
/// thousands of times in one setup.
fn stream_word(data : BytesView, at : Int32) -> UInt32 {
  let n = data.length()
  let mut w = 0U
  for i in 0..<4 {
    w = (w << 8) | data[(at + i) % n].to_int().reinterpret_as_uint()
  }
  w
}

///|
/// The Feistel function: the four S-box lookups that make a round non-linear.
fn f(cipher : Cipher, x : UInt32) -> UInt32 {
  let s = cipher.s
  let a = s[(x >> 24).reinterpret_as_int()]
  let b = s[256 + ((x >> 16) & 0xFFU).reinterpret_as_int()]
  let c = s[512 + ((x >> 8) & 0xFFU).reinterpret_as_int()]
  let d = s[768 + (x & 0xFFU).reinterpret_as_int()]
  ((a + b) ^ c) + d
}

///|
/// Sixteen rounds, then the final whitening. The swap at the end undoes the one
/// the last round did, which is why the two halves come out the right way round
/// without a separate path.
fn encipher(cipher : Cipher, xl : UInt32, xr : UInt32) -> (UInt32, UInt32) {
  let p = cipher.p
  let mut l = xl
  let mut r = xr
  for i in 0..<16 {
    l = l ^ p[i]
    r = r ^ f(cipher, l)
    let t = l
    l = r
    r = t
  }
  let t = l
  l = r
  r = t
  l = l ^ p[17]
  r = r ^ p[16]
  (l, r)
}

///|
/// The same network run backwards: the subkeys are consumed in reverse order.
fn decipher(cipher : Cipher, xl : UInt32, xr : UInt32) -> (UInt32, UInt32) {
  let p = cipher.p
  let mut l = xl
  let mut r = xr
  let mut i = 17
  while i > 1 {
    l = l ^ p[i]
    r = r ^ f(cipher, l)
    let t = l
    l = r
    r = t
    i = i - 1
  }
  let t = l
  l = r
  r = t
  l = l ^ p[0]
  r = r ^ p[1]
  (l, r)
}

///|
/// Mix the key into the P-array, cyclically, which is the first thing every
/// Blowfish key schedule does.
fn mix_key(cipher : Cipher, key : BytesView) -> Unit {
  let mut at = 0
  for i in 0..<18 {
    cipher.p[i] = cipher.p[i] ^ stream_word(key, at)
    at = at + 4
  }
}

///|
/// The plain Blowfish key schedule: replace every subkey, P first and then the
/// S-boxes, with the output of encrypting the previous subkey.
fn expand_key(cipher : Cipher, key : BytesView) -> Unit {
  mix_key(cipher, key)
  let mut l = 0U
  let mut r = 0U
  for i in 0..<9 {
    let (a, b) = encipher(cipher, l, r)
    cipher.p[2 * i] = a
    cipher.p[2 * i + 1] = b
    l = a
    r = b
  }
  for box in 0..<4 {
    for i in 0..<128 {
      let (a, b) = encipher(cipher, l, r)
      cipher.s[box * 256 + 2 * i] = a
      cipher.s[box * 256 + 2 * i + 1] = b
      l = a
      r = b
    }
  }
}

///|
/// EksBlowfish's salted key schedule: before each subkey is replaced, the salt
/// is folded into the running block. Without this, the dependence on the salt
/// would be an ordinary key schedule and bcrypt's cost argument would not hold.
///
/// The position in the salt runs on across the P-array and the S-boxes without
/// being reset — one continuous stream of words, wrapping when it runs out.
fn expand_state(cipher : Cipher, salt : BytesView, key : BytesView) -> Unit {
  mix_key(cipher, key)
  let mut l = 0U
  let mut r = 0U
  let mut at = 0
  for i in 0..<9 {
    l = l ^ stream_word(salt, at)
    r = r ^ stream_word(salt, at + 4)
    at = at + 8
    let (a, b) = encipher(cipher, l, r)
    cipher.p[2 * i] = a
    cipher.p[2 * i + 1] = b
    l = a
    r = b
  }
  for box in 0..<4 {
    for i in 0..<128 {
      l = l ^ stream_word(salt, at)
      r = r ^ stream_word(salt, at + 4)
      at = at + 8
      let (a, b) = encipher(cipher, l, r)
      cipher.s[box * 256 + 2 * i] = a
      cipher.s[box * 256 + 2 * i + 1] = b
      l = a
      r = b
    }
  }
}

///|
/// Key the cipher the ordinary way.
///
/// The key must be between [`min_key`] and [`max_key`] bytes, the range the
/// original specification names.
pub fn Cipher::new(key : BytesView) -> Cipher raise @spec.Broken {
  guard key.length() >= min_key else {
    raise @spec.Broken::Size(want=min_key, got=key.length())
  }
  guard key.length() <= max_key else {
    raise @spec.Broken::Size(want=max_key, got=key.length())
  }
  let cipher = fresh()
  expand_key(cipher, key)
  cipher
}

///|
/// The expensive key schedule bcrypt is built on: one salted pass, then `2^cost`
/// rounds of rekeying with the password and with the salt alternately.
///
/// Every round throws away the whole schedule and rebuilds it, which is why a
/// guess at a password costs one full setup rather than one block encryption.
/// The salt is always sixteen bytes, because that is the only width the format
/// stores; the key may be up to [`eks_max_key`] bytes, since bcrypt appends a
/// terminator to the password.
pub fn Cipher::new_eks(
  salt : BytesView,
  key : BytesView,
  cost : Int32,
) -> Cipher {
  guard salt.length() == 16 else {
    abort("blowfish: an EksBlowfish salt is 16 bytes, not \{salt.length()}")
  }
  guard key.length() >= 1 && key.length() <= eks_max_key else {
    abort("blowfish: an EksBlowfish key is 1 to 73 bytes, not \{key.length()}")
  }
  guard cost >= 4 && cost <= 30 else {
    abort("blowfish: an EksBlowfish cost is 4 to 30, not \{cost}")
  }
  let cipher = fresh()
  expand_state(cipher, salt, key)
  for _ in 0..<(1 << cost) {
    expand_key(cipher, key)
    expand_key(cipher, salt)
  }
  cipher
}

///|
/// Encrypt one block.
pub fn Cipher::encrypt(self : Cipher, data : BytesView) -> Bytes {
  guard data.length() == block else {
    abort("blowfish: a block is 8 bytes, not \{data.length()}")
  }
  let (l, r) = encipher(self, be32(data, 0), be32(data, 4))
  be_bytes(l, r)
}

///|
/// Decrypt one block.
pub fn Cipher::decrypt(self : Cipher, data : BytesView) -> Bytes {
  guard data.length() == block else {
    abort("blowfish: a block is 8 bytes, not \{data.length()}")
  }
  let (l, r) = decipher(self, be32(data, 0), be32(data, 4))
  be_bytes(l, r)
}

///|
/// The block length in bytes.
pub fn Cipher::block(self : Cipher) -> Int32 {
  let _ = self
  block
}

///|
/// Overwrite the subkeys. After a bcrypt derivation the schedule is as secret as
/// the password, so it should not be left for a later allocation to hand back
/// out.
pub fn Cipher::wipe(self : Cipher) -> Unit {
  for i in 0..<18 {
    self.p[i] = 0U
  }
  for i in 0..<1024 {
    self.s[i] = 0U
  }
}

///|
/// A big-endian word from a byte string.
fn be32(data : BytesView, off : Int32) -> UInt32 {
  (data[off].to_int().reinterpret_as_uint() << 24) |
  (data[off + 1].to_int().reinterpret_as_uint() << 16) |
  (data[off + 2].to_int().reinterpret_as_uint() << 8) |
  data[off + 3].to_int().reinterpret_as_uint()
}

///|
/// Two words as eight big-endian bytes.
fn be_bytes(l : UInt32, r : UInt32) -> Bytes {
  Bytes::from_array([
    ((l >> 24) & 0xFFU).to_byte(),
    ((l >> 16) & 0xFFU).to_byte(),
    ((l >> 8) & 0xFFU).to_byte(),
    (l & 0xFFU).to_byte(),
    ((r >> 24) & 0xFFU).to_byte(),
    ((r >> 16) & 0xFFU).to_byte(),
    ((r >> 8) & 0xFFU).to_byte(),
    (r & 0xFFU).to_byte(),
  ])
}

///|
pub impl @spec.Block for Cipher with fn block(self) {
  self.block()
}

///|
pub impl @spec.Block for Cipher with fn encrypt(self, data) {
  self.encrypt(data)
}

///|
pub impl @spec.Block for Cipher with fn decrypt(self, data) {
  self.decrypt(data)
}
