// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The bit-sliced AES core. Four blocks are transposed into eight 64-bit planes,
// so the S-box becomes a fixed Boolean circuit with no table lookup and no
// data-dependent branch, and the four blocks advance together.
//
// Every function here is a direct transcription of BearSSL's `aes_ct64.c`,
// `aes_ct64_enc.c` and `aes_ct64_dec.c` (Thomas Pornin, MIT licence); the
// transposition, the Boyar-Peralta circuit and the round order are that code's,
// not a re-derivation. The provenance is noted per function.

///|
let one : UInt64 = 0xFFFFFFFFFFFFFFFFUL

///|
let m1 : UInt64 = 0x1111111111111111UL

///|
let m2 : UInt64 = 0x2222222222222222UL

///|
let m4 : UInt64 = 0x4444444444444444UL

///|
let m8 : UInt64 = 0x8888888888888888UL

///|
/// The round constants, the high byte of `x^(i-1)` in GF(2^8).
let round_constant : FixedArray[Int32] = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
]

///|
/// One 32-bit word, little-endian, out of a byte buffer.
fn word_at(buf : FixedArray[Byte], at : Int32) -> UInt64 {
  buf[at].to_int().to_uint64() |
  (buf[at + 1].to_int().to_uint64() << 8) |
  (buf[at + 2].to_int().to_uint64() << 16) |
  (buf[at + 3].to_int().to_uint64() << 24)
}

///|
/// `SWAPN` from `aes_ct64.c`: move the bits selected by `cl` down/up between two
/// words, `ch` being the complement.
fn swap_bits(
  q : FixedArray[UInt64],
  a : Int32,
  b : Int32,
  cl : UInt64,
  ch : UInt64,
  s : Int32,
) -> Unit {
  let x = q[a]
  let y = q[b]
  q[a] = (x & cl) | ((y & cl) << s)
  q[b] = ((x & ch) >> s) | (y & ch)
}

///|
/// `br_aes_ct64_ortho`: the 8x8 bit-matrix transpose that turns four blocks of
/// bytes into eight bit planes.
fn transpose(q : FixedArray[UInt64]) -> Unit {
  swap_bits(q, 0, 1, 0x5555555555555555UL, 0xAAAAAAAAAAAAAAAAUL, 1)
  swap_bits(q, 2, 3, 0x5555555555555555UL, 0xAAAAAAAAAAAAAAAAUL, 1)
  swap_bits(q, 4, 5, 0x5555555555555555UL, 0xAAAAAAAAAAAAAAAAUL, 1)
  swap_bits(q, 6, 7, 0x5555555555555555UL, 0xAAAAAAAAAAAAAAAAUL, 1)
  swap_bits(q, 0, 2, 0x3333333333333333UL, 0xCCCCCCCCCCCCCCCCUL, 2)
  swap_bits(q, 1, 3, 0x3333333333333333UL, 0xCCCCCCCCCCCCCCCCUL, 2)
  swap_bits(q, 4, 6, 0x3333333333333333UL, 0xCCCCCCCCCCCCCCCCUL, 2)
  swap_bits(q, 5, 7, 0x3333333333333333UL, 0xCCCCCCCCCCCCCCCCUL, 2)
  swap_bits(q, 0, 4, 0x0F0F0F0F0F0F0F0FUL, 0xF0F0F0F0F0F0F0F0UL, 4)
  swap_bits(q, 1, 5, 0x0F0F0F0F0F0F0F0FUL, 0xF0F0F0F0F0F0F0F0UL, 4)
  swap_bits(q, 2, 6, 0x0F0F0F0F0F0F0F0FUL, 0xF0F0F0F0F0F0F0F0UL, 4)
  swap_bits(q, 3, 7, 0x0F0F0F0F0F0F0F0FUL, 0xF0F0F0F0F0F0F0F0UL, 4)
}

///|
/// `br_aes_ct64_interleave_in`: four 32-bit words into two 64-bit halves of the
/// bit-plane form.
fn interleave_words(
  x0 : UInt64,
  x1 : UInt64,
  x2 : UInt64,
  x3 : UInt64,
) -> (UInt64, UInt64) {
  let mut a0 = x0 | (x0 << 16)
  let mut a1 = x1 | (x1 << 16)
  let mut a2 = x2 | (x2 << 16)
  let mut a3 = x3 | (x3 << 16)
  a0 = a0 & 0x0000FFFF0000FFFFUL
  a1 = a1 & 0x0000FFFF0000FFFFUL
  a2 = a2 & 0x0000FFFF0000FFFFUL
  a3 = a3 & 0x0000FFFF0000FFFFUL
  a0 = a0 | (a0 << 8)
  a1 = a1 | (a1 << 8)
  a2 = a2 | (a2 << 8)
  a3 = a3 | (a3 << 8)
  a0 = a0 & 0x00FF00FF00FF00FFUL
  a1 = a1 & 0x00FF00FF00FF00FFUL
  a2 = a2 & 0x00FF00FF00FF00FFUL
  a3 = a3 & 0x00FF00FF00FF00FFUL
  (a0 | (a2 << 8), a1 | (a3 << 8))
}

///|
/// `br_aes_ct64_interleave_in`, over the 16 bytes of one block.
fn interleave_in(block : FixedArray[Byte], at : Int32) -> (UInt64, UInt64) {
  interleave_words(
    word_at(block, at),
    word_at(block, at + 4),
    word_at(block, at + 8),
    word_at(block, at + 12),
  )
}

///|
fn put_le32(out : FixedArray[Byte], at : Int32, w : UInt64) -> Unit {
  out[at] = (w & 0xFFUL).to_byte()
  out[at + 1] = ((w >> 8) & 0xFFUL).to_byte()
  out[at + 2] = ((w >> 16) & 0xFFUL).to_byte()
  out[at + 3] = ((w >> 24) & 0xFFUL).to_byte()
}

///|
/// `br_aes_ct64_interleave_out`: the inverse of [`interleave_in`], into 16
/// bytes of one block.
fn interleave_out(
  q0 : UInt64,
  q1 : UInt64,
  out : FixedArray[Byte],
  at : Int32,
) -> Unit {
  let mut x0 = q0 & 0x00FF00FF00FF00FFUL
  let mut x1 = q1 & 0x00FF00FF00FF00FFUL
  let mut x2 = (q0 >> 8) & 0x00FF00FF00FF00FFUL
  let mut x3 = (q1 >> 8) & 0x00FF00FF00FF00FFUL
  x0 = x0 | (x0 >> 8)
  x1 = x1 | (x1 >> 8)
  x2 = x2 | (x2 >> 8)
  x3 = x3 | (x3 >> 8)
  x0 = x0 & 0x0000FFFF0000FFFFUL
  x1 = x1 & 0x0000FFFF0000FFFFUL
  x2 = x2 & 0x0000FFFF0000FFFFUL
  x3 = x3 & 0x0000FFFF0000FFFFUL
  put_le32(out, at, (x0 | (x0 >> 16)) & 0xFFFFFFFFUL)
  put_le32(out, at + 4, (x1 | (x1 >> 16)) & 0xFFFFFFFFUL)
  put_le32(out, at + 8, (x2 | (x2 >> 16)) & 0xFFFFFFFFUL)
  put_le32(out, at + 12, (x3 | (x3 >> 16)) & 0xFFFFFFFFUL)
}

///|
/// `br_aes_ct64_bitslice_Sbox`: the Boyar-Peralta circuit, transcribed gate for
/// gate. `q[0]` is the low bit plane and `q[7]` the high, which is why the
/// inputs are read in reverse.
fn bitslice_sbox(q : FixedArray[UInt64]) -> Unit {
  let x0 = q[7]
  let x1 = q[6]
  let x2 = q[5]
  let x3 = q[4]
  let x4 = q[3]
  let x5 = q[2]
  let x6 = q[1]
  let x7 = q[0]
  // Top linear transformation.
  let y14 = x3 ^ x5
  let y13 = x0 ^ x6
  let y9 = x0 ^ x3
  let y8 = x0 ^ x5
  let t0 = x1 ^ x2
  let y1 = t0 ^ x7
  let y4 = y1 ^ x3
  let y12 = y13 ^ y14
  let y2 = y1 ^ x0
  let y5 = y1 ^ x6
  let y3 = y5 ^ y8
  let t1 = x4 ^ y12
  let y15 = t1 ^ x5
  let y20 = t1 ^ x1
  let y6 = y15 ^ x7
  let y10 = y15 ^ t0
  let y11 = y20 ^ y9
  let y7 = x7 ^ y11
  let y17 = y10 ^ y11
  let y19 = y10 ^ y8
  let y16 = t0 ^ y11
  let y21 = y13 ^ y16
  let y18 = x0 ^ y16
  // Non-linear section.
  let t2 = y12 & y15
  let t3 = y3 & y6
  let t4 = t3 ^ t2
  let t5 = y4 & x7
  let t6 = t5 ^ t2
  let t7 = y13 & y16
  let t8 = y5 & y1
  let t9 = t8 ^ t7
  let t10 = y2 & y7
  let t11 = t10 ^ t7
  let t12 = y9 & y11
  let t13 = y14 & y17
  let t14 = t13 ^ t12
  let t15 = y8 & y10
  let t16 = t15 ^ t12
  let t17 = t4 ^ t14
  let t18 = t6 ^ t16
  let t19 = t9 ^ t14
  let t20 = t11 ^ t16
  let t21 = t17 ^ y20
  let t22 = t18 ^ y19
  let t23 = t19 ^ y21
  let t24 = t20 ^ y18
  let t25 = t21 ^ t22
  let t26 = t21 & t23
  let t27 = t24 ^ t26
  let t28 = t25 & t27
  let t29 = t28 ^ t22
  let t30 = t23 ^ t24
  let t31 = t22 ^ t26
  let t32 = t31 & t30
  let t33 = t32 ^ t24
  let t34 = t23 ^ t33
  let t35 = t27 ^ t33
  let t36 = t24 & t35
  let t37 = t36 ^ t34
  let t38 = t27 ^ t36
  let t39 = t29 & t38
  let t40 = t25 ^ t39
  let t41 = t40 ^ t37
  let t42 = t29 ^ t33
  let t43 = t29 ^ t40
  let t44 = t33 ^ t37
  let t45 = t42 ^ t41
  let z0 = t44 & y15
  let z1 = t37 & y6
  let z2 = t33 & x7
  let z3 = t43 & y16
  let z4 = t40 & y1
  let z5 = t29 & y7
  let z6 = t42 & y11
  let z7 = t45 & y17
  let z8 = t41 & y10
  let z9 = t44 & y12
  let z10 = t37 & y3
  let z11 = t33 & y4
  let z12 = t43 & y13
  let z13 = t40 & y5
  let z14 = t29 & y2
  let z15 = t42 & y9
  let z16 = t45 & y14
  let z17 = t41 & y8
  // Bottom linear transformation.
  let t46 = z15 ^ z16
  let t47 = z10 ^ z11
  let t48 = z5 ^ z13
  let t49 = z9 ^ z10
  let t50 = z2 ^ z12
  let t51 = z2 ^ z5
  let t52 = z7 ^ z8
  let t53 = z0 ^ z3
  let t54 = z6 ^ z7
  let t55 = z16 ^ z17
  let t56 = z12 ^ t48
  let t57 = t50 ^ t53
  let t58 = z4 ^ t46
  let t59 = z3 ^ t54
  let t60 = t46 ^ t57
  let t61 = z14 ^ t57
  let t62 = t52 ^ t58
  let t63 = t49 ^ t58
  let t64 = z4 ^ t59
  let t65 = t61 ^ t62
  let t66 = z1 ^ t63
  let s0 = t59 ^ t63
  let s6 = t56 ^ (t62 ^ one)
  let s7 = t48 ^ (t60 ^ one)
  let t67 = t64 ^ t65
  let s3 = t53 ^ t66
  let s4 = t51 ^ t66
  let s5 = t47 ^ t65
  let s1 = t64 ^ (s3 ^ one)
  let s2 = t55 ^ (t67 ^ one)
  q[7] = s0
  q[6] = s1
  q[5] = s2
  q[4] = s3
  q[3] = s4
  q[2] = s5
  q[1] = s6
  q[0] = s7
}

///|
/// `br_aes_ct64_bitslice_invSbox`: the inverse S-box, the forward circuit with
/// the affine map applied on both sides.
fn bitslice_inv_sbox(q : FixedArray[UInt64]) -> Unit {
  let mut a0 = q[0] ^ one
  let mut a1 = q[1] ^ one
  let mut a2 = q[2]
  let mut a3 = q[3]
  let mut a4 = q[4]
  let mut a5 = q[5] ^ one
  let mut a6 = q[6] ^ one
  let mut a7 = q[7]
  q[7] = a1 ^ a4 ^ a6
  q[6] = a0 ^ a3 ^ a5
  q[5] = a7 ^ a2 ^ a4
  q[4] = a6 ^ a1 ^ a3
  q[3] = a5 ^ a0 ^ a2
  q[2] = a4 ^ a7 ^ a1
  q[1] = a3 ^ a6 ^ a0
  q[0] = a2 ^ a5 ^ a7
  bitslice_sbox(q)
  a0 = q[0] ^ one
  a1 = q[1] ^ one
  a2 = q[2]
  a3 = q[3]
  a4 = q[4]
  a5 = q[5] ^ one
  a6 = q[6] ^ one
  a7 = q[7]
  q[7] = a1 ^ a4 ^ a6
  q[6] = a0 ^ a3 ^ a5
  q[5] = a7 ^ a2 ^ a4
  q[4] = a6 ^ a1 ^ a3
  q[3] = a5 ^ a0 ^ a2
  q[2] = a4 ^ a7 ^ a1
  q[1] = a3 ^ a6 ^ a0
  q[0] = a2 ^ a5 ^ a7
}

///|
/// `add_round_key` from `aes_ct64_enc.c`.
fn add_round_key(
  q : FixedArray[UInt64],
  skey : FixedArray[UInt64],
  at : Int32,
) -> Unit {
  for i in 0..<8 {
    q[i] = q[i] ^ skey[at + i]
  }
}

///|
/// `shift_rows` from `aes_ct64_enc.c`: the row rotation is a mask-and-shift on
/// each bit plane.
fn shift_rows(q : FixedArray[UInt64]) -> Unit {
  for i in 0..<8 {
    let x = q[i]
    q[i] = (x & 0x000000000000FFFFUL) |
      ((x & 0x00000000FFF00000UL) >> 4) |
      ((x & 0x00000000000F0000UL) << 12) |
      ((x & 0x0000FF0000000000UL) >> 8) |
      ((x & 0x000000FF00000000UL) << 8) |
      ((x & 0xF000000000000000UL) >> 12) |
      ((x & 0x0FFF000000000000UL) << 4)
  }
}

///|
/// `inv_shift_rows` from `aes_ct64_dec.c`.
fn inv_shift_rows(q : FixedArray[UInt64]) -> Unit {
  for i in 0..<8 {
    let x = q[i]
    q[i] = (x & 0x000000000000FFFFUL) |
      ((x & 0x000000000FFF0000UL) << 4) |
      ((x & 0x00000000F0000000UL) >> 12) |
      ((x & 0x000000FF00000000UL) << 8) |
      ((x & 0x0000FF0000000000UL) >> 8) |
      ((x & 0x000F000000000000UL) << 12) |
      ((x & 0xFFF0000000000000UL) >> 4)
  }
}

///|
/// The 32-bit halves swapped.
fn rotr32(x : UInt64) -> UInt64 {
  (x << 32) | (x >> 32)
}

///|
/// `mix_columns` from `aes_ct64_enc.c`.
fn mix_columns(q : FixedArray[UInt64]) -> Unit {
  let q0 = q[0]
  let q1 = q[1]
  let q2 = q[2]
  let q3 = q[3]
  let q4 = q[4]
  let q5 = q[5]
  let q6 = q[6]
  let q7 = q[7]
  let r0 = (q0 >> 16) | (q0 << 48)
  let r1 = (q1 >> 16) | (q1 << 48)
  let r2 = (q2 >> 16) | (q2 << 48)
  let r3 = (q3 >> 16) | (q3 << 48)
  let r4 = (q4 >> 16) | (q4 << 48)
  let r5 = (q5 >> 16) | (q5 << 48)
  let r6 = (q6 >> 16) | (q6 << 48)
  let r7 = (q7 >> 16) | (q7 << 48)
  q[0] = q7 ^ r7 ^ r0 ^ rotr32(q0 ^ r0)
  q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr32(q1 ^ r1)
  q[2] = q1 ^ r1 ^ r2 ^ rotr32(q2 ^ r2)
  q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr32(q3 ^ r3)
  q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr32(q4 ^ r4)
  q[5] = q4 ^ r4 ^ r5 ^ rotr32(q5 ^ r5)
  q[6] = q5 ^ r5 ^ r6 ^ rotr32(q6 ^ r6)
  q[7] = q6 ^ r6 ^ r7 ^ rotr32(q7 ^ r7)
}

///|
/// `inv_mix_columns` from `aes_ct64_dec.c`.
fn inv_mix_columns(q : FixedArray[UInt64]) -> Unit {
  let q0 = q[0]
  let q1 = q[1]
  let q2 = q[2]
  let q3 = q[3]
  let q4 = q[4]
  let q5 = q[5]
  let q6 = q[6]
  let q7 = q[7]
  let r0 = (q0 >> 16) | (q0 << 48)
  let r1 = (q1 >> 16) | (q1 << 48)
  let r2 = (q2 >> 16) | (q2 << 48)
  let r3 = (q3 >> 16) | (q3 << 48)
  let r4 = (q4 >> 16) | (q4 << 48)
  let r5 = (q5 >> 16) | (q5 << 48)
  let r6 = (q6 >> 16) | (q6 << 48)
  let r7 = (q7 >> 16) | (q7 << 48)
  q[0] = q5 ^ q6 ^ q7 ^ r0 ^ r5 ^ r7 ^ rotr32(q0 ^ q5 ^ q6 ^ r0 ^ r5)
  q[1] = q0 ^ q5 ^ r0 ^ r1 ^ r5 ^ r6 ^ r7 ^ rotr32(q1 ^ q5 ^ q7 ^ r1 ^ r5 ^ r6)
  q[2] = q0 ^ q1 ^ q6 ^ r1 ^ r2 ^ r6 ^ r7 ^ rotr32(q0 ^ q2 ^ q6 ^ r2 ^ r6 ^ r7)
  q[3] = q0 ^
    q1 ^
    q2 ^
    q5 ^
    q6 ^
    r0 ^
    r2 ^
    r3 ^
    r5 ^
    rotr32(q0 ^ q1 ^ q3 ^ q5 ^ q6 ^ q7 ^ r0 ^ r3 ^ r5 ^ r7)
  q[4] = q1 ^
    q2 ^
    q3 ^
    q5 ^
    r1 ^
    r3 ^
    r4 ^
    r5 ^
    r6 ^
    r7 ^
    rotr32(q1 ^ q2 ^ q4 ^ q5 ^ q7 ^ r1 ^ r4 ^ r5 ^ r6)
  q[5] = q2 ^
    q3 ^
    q4 ^
    q6 ^
    r2 ^
    r4 ^
    r5 ^
    r6 ^
    r7 ^
    rotr32(q2 ^ q3 ^ q5 ^ q6 ^ r2 ^ r5 ^ r6 ^ r7)
  q[6] = q3 ^
    q4 ^
    q5 ^
    q7 ^
    r3 ^
    r5 ^
    r6 ^
    r7 ^
    rotr32(q3 ^ q4 ^ q6 ^ q7 ^ r3 ^ r6 ^ r7)
  q[7] = q4 ^ q5 ^ q6 ^ r4 ^ r6 ^ r7 ^ rotr32(q4 ^ q5 ^ q7 ^ r4 ^ r7)
}

///|
/// `br_aes_ct64_bitslice_encrypt` from `aes_ct64_enc.c`.
fn encrypt_planes(
  rounds : Int32,
  skey : FixedArray[UInt64],
  q : FixedArray[UInt64],
) -> Unit {
  let r = rounds
  add_round_key(q, skey, 0)
  for u in 1..<r {
    bitslice_sbox(q)
    shift_rows(q)
    mix_columns(q)
    add_round_key(q, skey, u * 8)
  }
  bitslice_sbox(q)
  shift_rows(q)
  add_round_key(q, skey, r * 8)
}

///|
/// `br_aes_ct64_bitslice_decrypt` from `aes_ct64_dec.c`.
fn decrypt_planes(
  rounds : Int32,
  skey : FixedArray[UInt64],
  q : FixedArray[UInt64],
) -> Unit {
  let r = rounds
  add_round_key(q, skey, r * 8)
  let mut u = r - 1
  while u > 0 {
    inv_shift_rows(q)
    bitslice_inv_sbox(q)
    add_round_key(q, skey, u * 8)
    inv_mix_columns(q)
    u = u - 1
  }
  inv_shift_rows(q)
  bitslice_inv_sbox(q)
  add_round_key(q, skey, 0)
}

///|
/// `sub_word` from `aes_ct64.c`: one word through the S-box, used by the key
/// expansion so the schedule has no table lookup either.
fn sub_word(x : UInt64) -> UInt64 {
  let q = FixedArray::make(8, 0UL)
  q[0] = x
  transpose(q)
  bitslice_sbox(q)
  transpose(q)
  q[0] & 0xFFFFFFFFUL
}

///|
/// `br_aes_ct64_keysched` and `br_aes_ct64_skey_expand`: the round keys in the
/// bit-plane layout, (rounds + 1) * 8 words. Every key bit is mixed with XOR,
/// rotation and the same circuit, so the schedule is constant-time too.
fn round_keys(key : BytesView) -> (Int32, FixedArray[UInt64]) {
  let key_len = key.length()
  let rounds = match key_len {
    16 => 10
    24 => 12
    _ => 14
  }
  let nk = key_len / 4
  let nkf = (rounds + 1) * 4
  let skey = FixedArray::make(60, 0UL)
  for i in 0..<nk {
    let at = i * 4
    skey[i] = key[at].to_int().to_uint64() |
      (key[at + 1].to_int().to_uint64() << 8) |
      (key[at + 2].to_int().to_uint64() << 16) |
      (key[at + 3].to_int().to_uint64() << 24)
  }
  let mut tmp = skey[nk - 1]
  let mut j = 0
  let mut k = 0
  for i in nk..<nkf {
    if j == 0 {
      tmp = ((tmp << 24) | (tmp >> 8)) & 0xFFFFFFFFUL
      tmp = sub_word(tmp) ^ round_constant[k].to_uint64()
    } else if nk > 6 && j == 4 {
      tmp = sub_word(tmp)
    }
    tmp = tmp ^ skey[i - nk]
    skey[i] = tmp
    j = j + 1
    if j == nk {
      j = 0
      k = k + 1
    }
  }
  let comp = FixedArray::make((rounds + 1) * 2, 0UL)
  let mut at = 0
  for i in 0..<(nkf / 4) {
    let (q0, q1) = interleave_words(
      skey[i * 4],
      skey[i * 4 + 1],
      skey[i * 4 + 2],
      skey[i * 4 + 3],
    )
    let q = FixedArray::make(8, 0UL)
    q[0] = q0
    q[1] = q0
    q[2] = q0
    q[3] = q0
    q[4] = q1
    q[5] = q1
    q[6] = q1
    q[7] = q1
    transpose(q)
    comp[at] = (q[0] & m1) | (q[1] & m2) | (q[2] & m4) | (q[3] & m8)
    comp[at + 1] = (q[4] & m1) | (q[5] & m2) | (q[6] & m4) | (q[7] & m8)
    at = at + 2
  }
  let enc = FixedArray::make((rounds + 1) * 8, 0UL)
  for u in 0..<((rounds + 1) * 2) {
    let x = comp[u]
    let x0 = x & m1
    let x1 = (x & m2) >> 1
    let x2 = (x & m4) >> 2
    let x3 = (x & m8) >> 3
    enc[u * 4] = (x0 << 4) - x0
    enc[u * 4 + 1] = (x1 << 4) - x1
    enc[u * 4 + 2] = (x2 << 4) - x2
    enc[u * 4 + 3] = (x3 << 4) - x3
  }
  (rounds, enc)
}

///|
/// Run `input` (a whole number of blocks) through four blocks at a time. The
/// last group is zero-padded and only the input's own bytes are returned.
fn run(
  rounds : Int32,
  skey : FixedArray[UInt64],
  input : BytesView,
  decrypt : Bool,
) -> Bytes {
  let n = input.length()
  let out = Array::make(n, b'\x00')
  let mut at = 0
  while at < n {
    let take = if n - at >= 64 { 64 } else { n - at }
    let buf = FixedArray::make(64, b'\x00')
    for i in 0..<take {
      buf[i] = input[at + i]
    }
    let q = FixedArray::make(8, 0UL)
    for i in 0..<4 {
      let (a, b) = interleave_in(buf, i * 16)
      q[i] = a
      q[i + 4] = b
    }
    transpose(q)
    if decrypt {
      decrypt_planes(rounds, skey, q)
    } else {
      encrypt_planes(rounds, skey, q)
    }
    transpose(q)
    for i in 0..<4 {
      interleave_out(q[i], q[i + 4], buf, i * 16)
    }
    for i in 0..<take {
      out[at + i] = buf[i]
    }
    at = at + take
  }
  Bytes::from_array(out)
}
