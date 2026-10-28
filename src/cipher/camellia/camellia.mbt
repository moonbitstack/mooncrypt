// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The block length in bytes. Camellia is defined for one block size only; the
/// key is what varies, over 128, 192 or 256 bits.
pub let block : Int32 = 16

///|
/// Sigma1 through Sigma6 (RFC 3713 §2.2): the six constants the key schedule
/// feeds to the round function as if they were subkeys. They are the first 128
/// bits of the SHA-256 initial values and their bitwise complements, which is
/// why they look like the middle of a hash function.
let sigma : FixedArray[UInt64] = [
  0xA09E667F3BCC908BUL, 0xB67AE8584CAA73B2UL, 0xC6EF372FE94F82BEUL, 0x54FF53A5F1D36F1CUL,
  0x10E527FADE682D1DUL, 0xB05688C2B3E6C1FDUL,
]

///|
/// SBOX1 (RFC 3713 §2.4.2).
///
/// The other three boxes are not written out: the RFC defines them as rotations
/// of this one, and deriving them is both shorter and impossible to get subtly
/// wrong in a transcription.
let sbox1 : FixedArray[Byte] = [
  112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65, //
   35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189, //
   134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26, //
   166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77, //
   139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153, //
   223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215, //
   20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34, //
   254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80, //
   170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210, //
   16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148, //
   135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226, //
   82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46, //
   233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89, //
   120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250, //
   114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164, //
   64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158,
]

///|
/// A 128-bit value, as the two halves the key schedule rotates.
///
/// Camellia derives every subkey by rotating a 128-bit word by an odd number of
/// bits and taking one half of it, so this is the type the schedule is actually
/// written in terms of — a single `UInt64` would lose half the rotations.
priv struct Wide {
  hi : UInt64
  lo : UInt64
}

///|
/// A Camellia key, with both directions already scheduled.
///
/// Decryption uses the same network as encryption with every list reversed, so
/// the two schedules are built once here and the entry point is all that differs
/// between [`encrypt`] and [`decrypt`].
pub struct Cipher {
  kw : FixedArray[UInt64]
  k : FixedArray[UInt64]
  ke : FixedArray[UInt64]
  back_kw : FixedArray[UInt64]
  back_k : FixedArray[UInt64]
  back_ke : FixedArray[UInt64]
}

///|
fn be64(b : BytesView, at : Int32) -> UInt64 {
  let mut out = 0UL
  for i in 0..<8 {
    out = (out << 8) | b[at + i].to_uint64()
  }
  out
}

///|
fn put64(out : Array[Byte], value : UInt64) -> Unit {
  for i in 0..<8 {
    out.push(((value >> (56 - 8 * i)) & 0xFFUL).to_byte())
  }
}

///|
fn rotl(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
/// An eight-bit rotation, which is all the derivation of SBOX2, SBOX3 and SBOX4
/// needs.
fn rotl8(x : UInt32, n : Int32) -> UInt32 {
  ((x << n) | (x >> (8 - n))) & 0xFF
}

///|
/// SBOX1.
fn box1(x : UInt32) -> UInt32 {
  (sbox1[(x & 0xFFU).reinterpret_as_int()].to_int() & 0xFF).reinterpret_as_uint()
}

///|
/// SBOX2: SBOX1's output rotated left by one.
fn box2(x : UInt32) -> UInt32 {
  rotl8(box1(x), 1)
}

///|
/// SBOX3: SBOX1's output rotated left by seven — equivalently, right by one.
fn box3(x : UInt32) -> UInt32 {
  rotl8(box1(x), 7)
}

///|
/// SBOX4: SBOX1's input rotated left by one.
fn box4(x : UInt32) -> UInt32 {
  box1(rotl8(x & 0xFF, 1))
}

///|
/// One byte of a 64-bit word, counting from the most significant end.
fn byte_at(v : UInt64, n : Int32) -> UInt32 {
  ((v >> n) & 0xFFUL).to_uint()
}

///|
/// The round function (RFC 3713 §2.4.1): add the subkey, substitute, then diffuse
/// with a byte permutation in which every output byte is the exclusive or of six
/// or seven input bytes.
///
/// That permutation is what makes this a Feistel round rather than a shuffle: it
/// spreads one changed S-box output across seven bytes of the next round's input,
/// which is the diffusion the FIPS 46-3 permutation table gives DES but far
/// stronger.
fn f(x : UInt64, k : UInt64) -> UInt64 {
  let t = x ^ k
  let t1 = box1(byte_at(t, 56))
  let t2 = box2(byte_at(t, 48))
  let t3 = box3(byte_at(t, 40))
  let t4 = box4(byte_at(t, 32))
  let t5 = box2(byte_at(t, 24))
  let t6 = box3(byte_at(t, 16))
  let t7 = box4(byte_at(t, 8))
  let t8 = box1(byte_at(t, 0))
  let y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
  let y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
  let y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
  let y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
  let y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
  let y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
  let y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
  let y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
  (y1.to_uint64() << 56) |
  (y2.to_uint64() << 48) |
  (y3.to_uint64() << 40) |
  (y4.to_uint64() << 32) |
  (y5.to_uint64() << 24) |
  (y6.to_uint64() << 16) |
  (y7.to_uint64() << 8) |
  y8.to_uint64()
}

///|
/// The FL function (RFC 3713 §2.4.2).
///
/// It is not a permutation of the round function's kind: it multiplies half the
/// word by a subkey-dependent value before xoring, which is linear over GF(2) but
/// not over the byte structure — and that is exactly the property that lets six
/// rounds of FL/FLINV stand in for several Feistel rounds against meet-in-the
/// middle.
fn fl(x : UInt64, k : UInt64) -> UInt64 {
  let mut x1 = (x >> 32).to_uint()
  let mut x2 = x.to_uint()
  let k1 = (k >> 32).to_uint()
  let k2 = k.to_uint()
  x2 = x2 ^ rotl(x1 & k1, 1)
  x1 = x1 ^ (x2 | k2)
  (x1.to_uint64() << 32) | x2.to_uint64()
}

///|
/// The inverse of [`fl`], which is why the two can be interleaved without the
/// network losing invertibility.
fn flinv(x : UInt64, k : UInt64) -> UInt64 {
  let mut x1 = (x >> 32).to_uint()
  let mut x2 = x.to_uint()
  let k1 = (k >> 32).to_uint()
  let k2 = k.to_uint()
  x1 = x1 ^ (x2 | k2)
  x2 = x2 ^ rotl(x1 & k1, 1)
  (x1.to_uint64() << 32) | x2.to_uint64()
}

///|
/// Rotate a 128-bit value left, which is how every subkey in the schedule is
/// reached.
fn Wide::rol(self : Wide, n : Int32) -> Wide {
  let n = (n % 128 + 128) % 128
  if n == 0 {
    self
  } else if n < 64 {
    {
      hi: (self.hi << n) | (self.lo >> (64 - n)),
      lo: (self.lo << n) | (self.hi >> (64 - n)),
    }
  } else if n == 64 {
    { hi: self.lo, lo: self.hi, }
  } else {
    let m = n - 64
    {
      hi: (self.lo << m) | (self.hi >> (64 - m)),
      lo: (self.hi << m) | (self.lo >> (64 - m)),
    }
  }
}

///|
/// The left half of a rotated word — one 64-bit subkey.
fn left(v : Wide, n : Int32) -> UInt64 {
  v.rol(n).hi
}

///|
/// The right half of a rotated word — the other 64-bit subkey.
fn right(v : Wide, n : Int32) -> UInt64 {
  v.rol(n).lo
}

///|
/// The key schedule (RFC 3713 §2.2).
///
/// KL is the leftmost 128 bits of the key. KR is the rest of it, except that a
/// 192-bit key has only 64 bits of remainder, so those are followed by their own
/// complement — a trick that keeps KR 128 bits wide without inventing key
/// material. KA and KB are then derived by running the round function a few
/// times over KL, KR and the sigma constants.
pub fn Cipher::new(key : BytesView) -> Cipher raise @spec.Broken {
  let size = key.length()
  // `want` reports the longest accepted length; all three are valid, so this is
  // the only honest single number to give.
  guard size == 16 || size == 24 || size == 32 else {
    raise Size(want=32, got=size)
  }
  let kl = { hi: be64(key, 0), lo: be64(key, 8), }
  let kr = if size == 16 {
    { hi: 0UL, lo: 0UL, }
  } else if size == 24 {
    let tail = be64(key, 16)
    { hi: tail, lo: tail ^ 0xFFFFFFFFFFFFFFFFUL, }
  } else {
    { hi: be64(key, 16), lo: be64(key, 24), }
  }

  let mut d1 = kl.hi ^ kr.hi
  let mut d2 = kl.lo ^ kr.lo
  d2 = d2 ^ f(d1, sigma[0])
  d1 = d1 ^ f(d2, sigma[1])
  d1 = d1 ^ kl.hi
  d2 = d2 ^ kl.lo
  d2 = d2 ^ f(d1, sigma[2])
  d1 = d1 ^ f(d2, sigma[3])
  let ka = { hi: d1, lo: d2, }
  d1 = ka.hi ^ kr.hi
  d2 = ka.lo ^ kr.lo
  d2 = d2 ^ f(d1, sigma[4])
  d1 = d1 ^ f(d2, sigma[5])
  let kb = { hi: d1, lo: d2, }

  let (kw, k, ke) : (FixedArray[UInt64], FixedArray[UInt64], FixedArray[UInt64]) = if size ==
    16 {
    (
      [left(kl, 0), right(kl, 0), left(ka, 111), right(ka, 111)],
      [
        left(ka, 0),
        right(ka, 0), //
        left(kl, 15),
        right(kl, 15), //
        left(ka, 15),
        right(ka, 15), //
        left(kl, 45),
        right(kl, 45), //
        // The one real asymmetry in the 128-bit list: k10 is the right half of
        // KL rotated by 60, not of KA. RFC 3713 §2.2 says so and the test
        // vectors agree with it.
        left(ka, 45), //
        right(kl, 60), //
        left(ka, 60),
        right(ka, 60), //
        left(kl, 94),
        right(kl, 94), //
        left(ka, 94),
        right(ka, 94), //
        left(kl, 111),
        right(kl, 111),
      ],
      [left(ka, 30), right(ka, 30), left(kl, 77), right(kl, 77)],
    )
  } else {
    (
      [left(kl, 0), right(kl, 0), left(kb, 111), right(kb, 111)],
      [
        left(kb, 0),
        right(kb, 0), //
        left(kr, 15),
        right(kr, 15), //
        left(ka, 15),
        right(ka, 15), //
        left(kb, 30),
        right(kb, 30), //
        left(kl, 45),
        right(kl, 45), //
        left(ka, 45),
        right(ka, 45), //
        left(kr, 60),
        right(kr, 60), //
        left(kb, 60),
        right(kb, 60), //
        left(kl, 77),
        right(kl, 77), //
        left(kr, 94),
        right(kr, 94), //
        left(ka, 94),
        right(ka, 94), //
        left(kl, 111),
        right(kl, 111),
      ],
      [
        left(kr, 30),
        right(kr, 30), //
        left(kl, 60),
        right(kl, 60), //
        left(ka, 77),
        right(ka, 77),
      ],
    )
  }
  {
    kw,
    k,
    ke,
    // The same schedule read backwards (§2.3.3), which is the whole of
    // decryption. The four whitening words are swapped in pairs rather than
    // simply reversed, because reversing the network exchanges the roles of the
    // two halves and the pre- and post-whitening along with them.
    back_kw: [kw[2], kw[3], kw[0], kw[1]],
    back_k: backwards(k),
    back_ke: backwards(ke),
  }
}

///|
/// A copy of a subkey list in the opposite order, which is how decryption undoes
/// encryption.
fn backwards(keys : FixedArray[UInt64]) -> FixedArray[UInt64] {
  let n = keys.length()
  let out = FixedArray::make(n, 0UL)
  for i in 0..<n {
    out[i] = keys[n - 1 - i]
  }
  out
}

///|
/// The Feistel network of RFC 3713 §2.3, written once for both round counts and
/// both directions: a decryption is this same function over the reversed lists.
///
/// Eighteen rounds for a 128-bit key and twenty-four otherwise, with a FL/FLINV
/// layer after every six — the layer is skipped after the last group because
/// there is no following round for it to protect.
fn run(
  kw : FixedArray[UInt64],
  k : FixedArray[UInt64],
  ke : FixedArray[UInt64],
  input : BytesView,
) -> Bytes {
  let mut d1 = be64(input, 0) ^ kw[0]
  let mut d2 = be64(input, 8) ^ kw[1]
  let groups = k.length() / 6
  for g in 0..<groups {
    let at = g * 6
    d2 = d2 ^ f(d1, k[at])
    d1 = d1 ^ f(d2, k[at + 1])
    d2 = d2 ^ f(d1, k[at + 2])
    d1 = d1 ^ f(d2, k[at + 3])
    d2 = d2 ^ f(d1, k[at + 4])
    d1 = d1 ^ f(d2, k[at + 5])
    if g < groups - 1 {
      d1 = fl(d1, ke[2 * g])
      d2 = flinv(d2, ke[2 * g + 1])
    }
  }
  let out : Array[Byte] = []
  put64(out, d2 ^ kw[2])
  put64(out, d1 ^ kw[3])
  Bytes::from_array(out)
}

///|
/// Encrypt one 16-byte block.
pub fn Cipher::encrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("camellia: a block is 16 bytes, not \{input.length()}")
  }
  run(self.kw, self.k, self.ke, input)
}

///|
/// Decrypt one 16-byte block.
pub fn Cipher::decrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("camellia: a block is 16 bytes, not \{input.length()}")
  }
  run(self.back_kw, self.back_k, self.back_ke, input)
}

///|
/// The block length in bytes.
pub fn Cipher::block(self : Cipher) -> Int32 {
  ignore(self)
  block
}

///|
/// Overwrite a word schedule.
fn clear(keys : FixedArray[UInt64]) -> Unit {
  for i in 0..<keys.length() {
    keys[i] = 0UL
  }
}

///|
/// Overwrite both schedules.
///
/// The key is at most 256 bits but the schedule is up to twenty-four subkeys and
/// two whitening sets, and anyone holding them can decrypt everything the key
/// can without ever seeing the key. They are wiped for the same reason a key is.
pub fn Cipher::wipe(self : Cipher) -> Unit {
  clear(self.kw)
  clear(self.k)
  clear(self.ke)
  clear(self.back_kw)
  clear(self.back_k)
  clear(self.back_ke)
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
