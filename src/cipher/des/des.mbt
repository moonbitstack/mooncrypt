// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The key length in bytes. Eight, but only 56 of the 64 bits are key material:
/// the low bit of every byte is a parity bit that DES ignores.
pub let key_size : Int32 = 8

///|
/// The block length in bytes.
pub let block : Int32 = 8

///|
/// The Triple DES key length in bytes: three DES keys, used encrypt-decrypt-encrypt.
pub let triple_key_size : Int32 = 24

///|
/// A DES key, expanded into its sixteen forty-eight-bit round keys.
pub struct Cipher {
  rk : FixedArray[UInt64]
}

///|
/// A Triple DES key: three DES keys, applied in the order E-D-E.
pub struct TripleDes {
  first : Cipher
  second : Cipher
  third : Cipher
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
/// Apply a bit-permutation table: bit `i` of the output is bit `table[i]` of the
/// input, counting from one at the most significant end.
///
/// That one-based, most-significant-first numbering is straight out of FIPS 46-3
/// and is why this reads nothing like the rest of the code — the tables were
/// published in those terms and translating them would only add a chance of
/// getting it wrong.
fn permute(
  input : UInt64,
  table : FixedArray[Int32],
  in_bits : Int32,
) -> UInt64 {
  let mut out = 0UL
  for i in 0..<table.length() {
    out = (out << 1) | ((input >> (in_bits - table[i])) & 1UL)
  }
  out
}

///|
/// The sixteen round keys of FIPS 46-3 §3.2: permute the key to 56 bits, split it
/// in half, rotate the halves by the schedule, and squeeze each pair through PC-2.
pub fn Cipher::new(key : BytesView) -> Cipher raise @spec.Broken {
  guard key.length() == key_size else {
    raise Size(want=key_size, got=key.length())
  }
  let pc1 = permute(be64(key, 0), pc1_table, 64)
  let mut c = (pc1 >> 28) & 0xFFFFFFFUL
  let mut d = pc1 & 0xFFFFFFFUL
  let rk = FixedArray::make(16, 0UL)
  for i in 0..<16 {
    let by = rotation[i]
    c = ((c << by) | (c >> (28 - by))) & 0xFFFFFFFUL
    d = ((d << by) | (d >> (28 - by))) & 0xFFFFFFFUL
    rk[i] = permute((c << 28) | d, pc2_table, 56)
  }
  { rk, }
}

///|
/// The Feistel function: expand the right half to forty-eight bits, mix in the
/// round key, run the eight substitutions, and permute the result.
///
/// The S-boxes are the only nonlinear part of DES, and the only part that is not
/// a permutation — six bits in, four bits out, so this is where the security
/// lives.
fn f(r : UInt64, k : UInt64) -> UInt64 {
  let e = permute(r, expand_table, 32) ^ k
  let mut mixed = 0UL
  for i in 0..<8 {
    let chunk = ((e >> (42 - 6 * i)) & 0x3FUL).to_int()
    // The outer two bits pick the row, the middle four the column.
    let row = ((chunk >> 4) & 2) | (chunk & 1)
    let col = (chunk >> 1) & 0xF
    mixed = (mixed << 4) | s_boxes[i * 64 + row * 16 + col].to_uint64()
  }
  permute(mixed, p_table, 32)
}

///|
/// Encrypt one 8-byte block.
pub fn Cipher::encrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("des: a block is 8 bytes, not \{input.length()}")
  }
  let ip = permute(be64(input, 0), ip_table, 64)
  let mut l = ip >> 32
  let mut r = ip & 0xFFFFFFFFUL
  for i in 0..<16 {
    let next = l ^ f(r, self.rk[i])
    l = r
    r = next
  }
  // The halves are swapped one last time before the final permutation, which is
  // the same as feeding them in reverse.
  let out : Array[Byte] = []
  put64(out, permute((r << 32) | l, fp_table, 64))
  Bytes::from_array(out)
}

///|
/// Decrypt one 8-byte block: the same cipher with the round keys in reverse.
pub fn Cipher::decrypt(self : Cipher, input : BytesView) -> Bytes {
  guard input.length() == block else {
    abort("des: a block is 8 bytes, not \{input.length()}")
  }
  let ip = permute(be64(input, 0), ip_table, 64)
  let mut l = ip >> 32
  let mut r = ip & 0xFFFFFFFFUL
  for i in 0..<16 {
    let next = l ^ f(r, self.rk[15 - i])
    l = r
    r = next
  }
  let out : Array[Byte] = []
  put64(out, permute((r << 32) | l, fp_table, 64))
  Bytes::from_array(out)
}

///|
/// The block length in bytes.
pub fn Cipher::block(self : Cipher) -> Int32 {
  ignore(self)
  block
}

///|
/// Overwrite the round keys.
///
/// There are sixteen of them, each forty-eight bits, so a whole DES schedule
/// holds nearly the entire key — and unlike the key it is not parity-masked.
pub fn Cipher::wipe(self : Cipher) -> Unit {
  for i in 0..<16 {
    self.rk[i] = 0UL
  }
}

///|
/// Overwrite all three round-key schedules.
pub fn TripleDes::wipe(self : TripleDes) -> Unit {
  self.first.wipe()
  self.second.wipe()
  self.third.wipe()
}

///|
/// Key Triple DES.
///
/// The key is three DES keys and the operation is encrypt with the first, decrypt
/// with the second, encrypt with the third — E-D-E, chosen so that a key of
/// `K ‖ K ‖ K` is exactly single DES and a deployment could be upgraded one
/// endpoint at a time.
pub fn TripleDes::new(key : BytesView) -> TripleDes raise @spec.Broken {
  guard key.length() == triple_key_size else {
    raise Size(want=triple_key_size, got=key.length())
  }
  {
    first: Cipher::new(key[0:8]),
    second: Cipher::new(key[8:16]),
    third: Cipher::new(key[16:24]),
  }
}

///|
/// Key Triple DES from a sixteen-byte key, the two-key form where the third key
/// repeats the first.
///
/// Two-key triple DES gives about 80 bits of security rather than 112, which is
/// why it was deprecated before the three-key form was. It is still what a lot of
/// stored data was encrypted with.
pub fn TripleDes::from_two_keys(
  key : BytesView,
) -> TripleDes raise @spec.Broken {
  guard key.length() == 16 else { raise Size(want=16, got=key.length()) }
  {
    first: Cipher::new(key[0:8]),
    second: Cipher::new(key[8:16]),
    third: Cipher::new(key[0:8]),
  }
}

///|
/// Encrypt one 8-byte block.
pub fn TripleDes::encrypt(self : TripleDes, input : BytesView) -> Bytes {
  self.third.encrypt(self.second.decrypt(self.first.encrypt(input))[:])
}

///|
/// Decrypt one 8-byte block: E-D-E in reverse, which is D-E-D.
pub fn TripleDes::decrypt(self : TripleDes, input : BytesView) -> Bytes {
  self.first.decrypt(self.second.encrypt(self.third.decrypt(input)[:])[:])
}

///|
/// The block length in bytes.
pub fn TripleDes::block(self : TripleDes) -> Int32 {
  ignore(self)
  block
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
pub impl @spec.Block for TripleDes with fn block(self) {
  self.block()
}

///|
pub impl @spec.Block for TripleDes with fn encrypt(self, input) {
  self.encrypt(input)
}

///|
pub impl @spec.Block for TripleDes with fn decrypt(self, input) {
  self.decrypt(input)
}

// ------------------------------------------------------------------- tables
//
// All from FIPS 46-3. Note that the numbering is one-based and starts at the most
// significant bit, so `58` means "the fifty-eighth bit counted from the left".

///|
/// The initial permutation (FIPS 46-3 §3.2, table IP).
let ip_table : FixedArray[Int32] = [
  58, 50, 42, 34, 26, 18, 10, 2, //
   60, 52, 44, 36, 28, 20, 12, 4, //
   62, 54, 46, 38, 30, 22, 14, 6, //
   64, 56, 48, 40, 32, 24, 16, 8, //
   57, 49, 41, 33, 25, 17, 9, 1, //
   59, 51, 43, 35, 27, 19, 11, 3, //
   61, 53, 45, 37, 29, 21, 13, 5, //
   63, 55, 47, 39, 31, 23, 15, 7,
]

///|
/// The final permutation, the inverse of the initial one.
let fp_table : FixedArray[Int32] = [
  40, 8, 48, 16, 56, 24, 64, 32, //
   39, 7, 47, 15, 55, 23, 63, 31, //
   38, 6, 46, 14, 54, 22, 62, 30, //
   37, 5, 45, 13, 53, 21, 61, 29, //
   36, 4, 44, 12, 52, 20, 60, 28, //
   35, 3, 43, 11, 51, 19, 59, 27, //
   34, 2, 42, 10, 50, 18, 58, 26, //
   33, 1, 41, 9, 49, 17, 57, 25,
]

///|
/// The expansion of the right half from thirty-two bits to forty-eight, which
/// makes the same bit feed two different S-boxes.
let expand_table : FixedArray[Int32] = [
  32, 1, 2, 3, 4, 5, //
   4, 5, 6, 7, 8, 9, //
   8, 9, 10, 11, 12, 13, //
   12, 13, 14, 15, 16, 17, //
   16, 17, 18, 19, 20, 21, //
   20, 21, 22, 23, 24, 25, //
   24, 25, 26, 27, 28, 29, //
   28, 29, 30, 31, 32, 1,
]

///|
/// The permutation applied after the substitutions (table P).
let p_table : FixedArray[Int32] = [
  16, 7, 20, 21, 29, 12, 28, 17, //
   1, 15, 23, 26, 5, 18, 31, 10, //
   2, 8, 24, 14, 32, 27, 3, 9, //
   19, 13, 30, 6, 22, 11, 4, 25,
]

///|
/// The first permuted choice of the key schedule: sixty-four bits to fifty-six,
/// dropping the eight parity bits.
let pc1_table : FixedArray[Int32] = [
  57, 49, 41, 33, 25, 17, 9, //
   1, 58, 50, 42, 34, 26, 18, //
   10, 2, 59, 51, 43, 35, 27, //
   19, 11, 3, 60, 52, 44, 36, //
   63, 55, 47, 39, 31, 23, 15, //
   7, 62, 54, 46, 38, 30, 22, //
   14, 6, 61, 53, 45, 37, 29, //
   21, 13, 5, 28, 20, 12, 4,
]

///|
/// The second permuted choice: fifty-six to forty-eight, which is why each round
/// key only sees forty-eight of the fifty-six key bits.
let pc2_table : FixedArray[Int32] = [
  14, 17, 11, 24, 1, 5, //
   3, 28, 15, 6, 21, 10, //
   23, 19, 12, 4, 26, 8, //
   16, 7, 27, 20, 13, 2, //
   41, 52, 31, 37, 47, 55, //
   30, 40, 51, 45, 33, 48, //
   44, 49, 39, 56, 34, 53, //
   46, 42, 50, 36, 29, 32,
]

///|
/// How far the two halves of the key rotate each round: one bit, then one again,
/// then two for the remaining fourteen.
let rotation : FixedArray[Int32] = [
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
]

///|
/// The eight substitution boxes, one after another: box `i` occupies entries
/// `i * 64` to `i * 64 + 63`, and within a box the row is the outer two bits and
/// the column the middle four.
let s_boxes : FixedArray[UInt32] = [
  // S1
  14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, //
   0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, //
   4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, //
   15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
  // S2
   15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, //
   3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, //
   0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, //
   13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
  // S3
   10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, //
   13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, //
   13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, //
   1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
  // S4
   7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, //
   13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, //
   10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, //
   3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
  // S5
   2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, //
   14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, //
   4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, //
   11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
  // S6
   12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, //
   10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, //
   9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, //
   4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
  // S7
   4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, //
   13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, //
   1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, //
   6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
  // S8
   13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, //
   1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, //
   7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, //
   2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
]
