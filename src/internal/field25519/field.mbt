// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Arithmetic over `GF(2^255 - 19)`: eight 32-bit limbs, Montgomery form, one
// scratch buffer for the wide product. The modulus, `R^2` and the Montgomery
// constant are derived once at start-up rather than transcribed, which is the
// same rule the Weierstrass field follows.

///|
/// A field element in Montgomery form, `a * 2^256 mod p`: eight limbs, least
/// significant first.
pub type Fe = FixedArray[UInt64]

///|
/// The number of limbs.
pub let limbs : Int32 = 8

///|
/// The modulus, `2^255 - 19`.
pub let p : Fe = of_bigint((1N << 255) - 19N)

///|
/// `-p^-1 mod 2^32`, the constant the reduction multiplies by.
let n0 : UInt64 = {
  let mut inv = 1UL
  for _ in 0..<5 {
    inv = (inv * (2UL - ((p[0] * inv) & 0xFFFFFFFFUL))) & 0xFFFFFFFFUL
  }
  (0x100000000UL - inv) & 0xFFFFFFFFUL
}

///|
/// `R^2 mod p`, with `R = 2^256`.
let r2 : Fe = of_bigint((1N << 256) * (1N << 256) % ((1N << 255) - 19N))

///|
/// One, in Montgomery form.
pub let one : Fe = of_bigint((1N << 256) % ((1N << 255) - 19N))

///|
/// `p - 2`, the exponent of the inverse.
let exp_inv : Fe = of_bigint((1N << 255) - 21N)

///|
/// The big-endian limbs of a value below `2^256`.
fn of_bigint(v : BigInt) -> Fe {
  let bytes = v.to_octets(length=32)
  let out = FixedArray::make(8, 0UL)
  for i in 0..<8 {
    let at = 32 - 4 * (i + 1)
    out[i] = (bytes[at].to_int().to_uint64() << 24) |
      (bytes[at + 1].to_int().to_uint64() << 16) |
      (bytes[at + 2].to_int().to_uint64() << 8) |
      bytes[at + 3].to_int().to_uint64()
  }
  out
}

///|
/// The plain integer a field element stands for, reduced.
pub fn to_bigint(a : Fe) -> BigInt {
  let out = FixedArray::make(32, b'\x00')
  for i in 0..<8 {
    let at = 32 - 4 * (i + 1)
    out[at] = ((a[i] >> 24) & 0xFFUL).to_byte()
    out[at + 1] = ((a[i] >> 16) & 0xFFUL).to_byte()
    out[at + 2] = ((a[i] >> 8) & 0xFFUL).to_byte()
    out[at + 3] = (a[i] & 0xFFUL).to_byte()
  }
  BigInt::from_octets(Bytes::from_array(out)[:])
}

///|
/// A plain integer into Montgomery form.
pub fn from_bigint(v : BigInt) -> Fe {
  mul(of_bigint(v), r2)
}

///|
/// A little-endian 32-byte string as a field element — the encoding Ed25519 and
/// X25519 both use, so it lives here rather than in either of them.
pub fn from_le_bytes(b : BytesView) -> Fe {
  let out = FixedArray::make(8, 0UL)
  for i in 0..<8 {
    let at = 4 * i
    out[i] = b[at].to_int().to_uint64() |
      (b[at + 1].to_int().to_uint64() << 8) |
      (b[at + 2].to_int().to_uint64() << 16) |
      (b[at + 3].to_int().to_uint64() << 24)
  }
  mul(out, r2)
}

///|
/// A field element as 32 little-endian bytes.
pub fn to_le_bytes(a : Fe) -> Bytes {
  let plain = mul(a, of_bigint(1N))
  let out = FixedArray::make(32, b'\x00')
  for i in 0..<8 {
    let at = 4 * i
    out[at] = (plain[i] & 0xFFUL).to_byte()
    out[at + 1] = ((plain[i] >> 8) & 0xFFUL).to_byte()
    out[at + 2] = ((plain[i] >> 16) & 0xFFUL).to_byte()
    out[at + 3] = ((plain[i] >> 24) & 0xFFUL).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn make() -> Fe {
  FixedArray::make(8, 0UL)
}

///|
/// `a + b mod p`.
pub fn add(a : Fe, b : Fe) -> Fe {
  let r = make()
  let mut carry = 0UL
  for i in 0..<8 {
    let s = a[i] + b[i] + carry
    r[i] = s & 0xFFFFFFFFUL
    carry = s >> 32
  }
  sub_p(r, carry)
}

///|
/// `a - b mod p`.
pub fn sub(a : Fe, b : Fe) -> Fe {
  let r = make()
  let mut borrow = 0UL
  for i in 0..<8 {
    let d = a[i] - b[i] - borrow
    r[i] = d & 0xFFFFFFFFUL
    borrow = d >> 63
  }
  let m = 0UL - borrow
  let mut carry = 0UL
  for i in 0..<8 {
    let s = r[i] + (p[i] & m) + carry
    r[i] = s & 0xFFFFFFFFUL
    carry = s >> 32
  }
  r
}

///|
/// Undo the last subtraction when the value is still at least `p`; `extra` is
/// the carry out of the top limb. Branch-free: the carry chain decides.
fn sub_p(r : Fe, extra : UInt64) -> Fe {
  let tmp = make()
  let mut borrow = 0UL
  for i in 0..<8 {
    let d = r[i] - p[i] - borrow
    tmp[i] = d & 0xFFFFFFFFUL
    borrow = d >> 63
  }
  let use_tmp = (extra ^ borrow) - 1UL
  let out = make()
  for i in 0..<8 {
    out[i] = (tmp[i] & use_tmp) | (r[i] & (use_tmp ^ 0xFFFFFFFFFFFFFFFFUL))
  }
  out
}

///|
/// The scratch product, one per process: nothing here nests a multiplication
/// inside another, so a single buffer is enough.
let scratch : FixedArray[UInt64] = FixedArray::make(18, 0UL)

///|
/// `a * b * R^-1 mod p`.
pub fn mul(a : Fe, b : Fe) -> Fe {
  let t = scratch
  for i in 0..<18 {
    t[i] = 0UL
  }
  for i in 0..<8 {
    let ai = a[i]
    let mut carry = 0UL
    for j in 0..<8 {
      let uv = t[i + j] + ai * b[j] + carry
      t[i + j] = uv & 0xFFFFFFFFUL
      carry = uv >> 32
    }
    let s = t[i + 8] + carry
    t[i + 8] = s & 0xFFFFFFFFUL
    t[i + 9] = t[i + 9] + (s >> 32)
  }
  for i in 0..<8 {
    let m = (t[i] * n0) & 0xFFFFFFFFUL
    let mut carry = 0UL
    for j in 0..<8 {
      let uv = t[i + j] + m * p[j] + carry
      t[i + j] = uv & 0xFFFFFFFFUL
      carry = uv >> 32
    }
    let s = t[i + 8] + carry
    t[i + 8] = s & 0xFFFFFFFFUL
    t[i + 9] = t[i + 9] + (s >> 32)
  }
  let out = make()
  let mut borrow = 0UL
  for i in 0..<8 {
    let d = t[8 + i] - p[i] - borrow
    out[i] = d & 0xFFFFFFFFUL
    borrow = d >> 63
  }
  let m = 0UL - (borrow ^ t[16])
  let mut carry = 0UL
  for i in 0..<8 {
    let s = out[i] + (p[i] & m) + carry
    out[i] = s & 0xFFFFFFFFUL
    carry = s >> 32
  }
  out
}

///|
/// `a^2`.
pub fn sqr(a : Fe) -> Fe {
  mul(a, a)
}

///|
/// `a^e` by square and multiply over the exponent's limbs. The exponent is a
/// public constant, so the branch on its bits leaks nothing.
fn pow(a : Fe, e : Fe, e_bits : Int32) -> Fe {
  let mut r = one
  let mut i = e_bits - 1
  while i >= 0 {
    r = sqr(r)
    if ((e[i / 32] >> (i % 32)) & 1UL) == 1UL {
      r = mul(r, a)
    }
    i = i - 1
  }
  r
}

///|
/// `a^(p-2)`, which is `a^-1` by Fermat.
pub fn inv(a : Fe) -> Fe {
  pow(a, exp_inv, 255)
}

///|
/// `a^((p+3)/8)`: the exponent a square root starts from, since `p ≡ 5 (mod 8)`.
pub fn pow_8(a : Fe) -> Fe {
  pow(a, of_bigint(((1N << 255) - 16N) / 8N), 252)
}

///|
/// All ones when `a` is zero, zero otherwise.
pub fn is_zero_mask(a : Fe) -> UInt64 {
  let mut acc = 0UL
  for i in 0..<8 {
    acc = acc | a[i]
  }
  ((acc | (0UL - acc)) >> 63) - 1UL
}

///|
/// `a` where `mask` is all ones, `b` where it is zero.
pub fn select(mask : UInt64, a : Fe, b : Fe) -> Fe {
  let out = make()
  for i in 0..<8 {
    out[i] = b[i] ^ (mask & (a[i] ^ b[i]))
  }
  out
}

///|
/// Whether the two elements are the same, by the field's own comparison
/// (constant-time, like every other comparison here).
pub fn eq(a : Fe, b : Fe) -> Bool {
  is_zero_mask(sub(a, b)) != 0UL
}
