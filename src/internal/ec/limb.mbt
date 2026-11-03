// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Fixed-width field arithmetic for the Weierstrass curves, in 32-bit limbs with
// Montgomery multiplication. This is the hot path behind `mul`: the BigInt type
// still carries a point across the API, but the scalar multiplication itself is
// limb arithmetic with a branch-free conditional swap, so it neither allocates a
// bignum per operation nor branches on a scalar bit.
//
// The modulus, `R^2 mod p` and the Montgomery constant are derived once per
// multiplication from the curve's parameters, which are public, so the setup is
// allowed to depend on them.

///|
let limb_mask : UInt64 = 0xFFFFFFFFUL

///|
/// A field element in Montgomery form: `a * R mod p`, with `R = 2^(32k)`.
type Fp = FixedArray[UInt64]

///|
priv struct Field {
  k : Int32
  p : Fp
  n0 : UInt64
  r2 : Fp
  one : Fp
  a : Fp
  exp : Fp
  exp_bits : Int32
  // `fmul` writes the wide product here instead of allocating: no multiplication
  // nests inside another, so one buffer per field is enough and it takes the
  // largest allocation out of the hot loop.
  scratch : FixedArray[UInt64]
}

///|
/// The limbs of a big-endian byte string, least significant first.
fn limbs_from_be(bytes : BytesView, k : Int32) -> Fp {
  let out = FixedArray::make(k, 0UL)
  for i in 0..<k {
    let at = k * 4 - 4 * (i + 1)
    out[i] = (bytes[at].to_int().to_uint64() << 24) |
      (bytes[at + 1].to_int().to_uint64() << 16) |
      (bytes[at + 2].to_int().to_uint64() << 8) |
      bytes[at + 3].to_int().to_uint64()
  }
  out
}

///|
/// The big-endian bytes of a limb string.
fn limbs_to_be(limbs : Fp, k : Int32) -> Bytes {
  let out = FixedArray::make(k * 4, b'\x00')
  for i in 0..<k {
    let at = k * 4 - 4 * (i + 1)
    out[at] = ((limbs[i] >> 24) & 0xFFUL).to_byte()
    out[at + 1] = ((limbs[i] >> 16) & 0xFFUL).to_byte()
    out[at + 2] = ((limbs[i] >> 8) & 0xFFUL).to_byte()
    out[at + 3] = (limbs[i] & 0xFFUL).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn copy_limbs(a : Fp, k : Int32) -> Fp {
  let out = FixedArray::make(k, 0UL)
  for i in 0..<k {
    out[i] = a[i]
  }
  out
}

///|
fn fis_zero(a : Fp, k : Int32) -> Bool {
  let mut acc = 0UL
  for i in 0..<k {
    acc = acc | a[i]
  }
  acc == 0UL
}

///|
fn bit_of_limbs(a : Fp, i : Int32) -> Bool {
  ((a[i / 32] >> (i % 32)) & 1UL) == 1UL
}

///|
/// `a + b mod p`. The conditional subtraction happens in place, so this is one
/// allocation and three passes — it is the most-called function in the point
/// arithmetic and `reduce` was allocating three arrays for it.
fn fadd(a : Fp, b : Fp, f : Field) -> Fp {
  let k = f.k
  let p = f.p
  let out = FixedArray::make(k, 0UL)
  let mut carry = 0UL
  for i in 0..<k {
    let s = a.unsafe_get(i) + b.unsafe_get(i) + carry
    out.unsafe_set(i, s & limb_mask)
    carry = s >> 32
  }
  let mut borrow = 0UL
  for i in 0..<k {
    let d = out.unsafe_get(i) - p.unsafe_get(i) - borrow
    out.unsafe_set(i, d & limb_mask)
    borrow = d >> 63
  }
  // The subtraction stands unless it borrowed with nothing above it; then `p`
  // goes back on. A mask, not a branch: both limbs are secret.
  let restore = 0UL - (borrow & (carry ^ 1UL))
  let mut adding = 0UL
  for i in 0..<k {
    let s = out.unsafe_get(i) + (p.unsafe_get(i) & restore) + adding
    out.unsafe_set(i, s & limb_mask)
    adding = s >> 32
  }
  out
}

///|
/// `a - b mod p`.
fn fsub(a : Fp, b : Fp, f : Field) -> Fp {
  let k = f.k
  let r = FixedArray::make(k, 0UL)
  let mut borrow = 0UL
  for i in 0..<k {
    let d = a.unsafe_get(i) - b.unsafe_get(i) - borrow
    r.unsafe_set(i, d & limb_mask)
    borrow = d >> 63
  }
  let mask = 0UL - borrow
  let mut carry = 0UL
  for i in 0..<k {
    let s = r.unsafe_get(i) + (f.p.unsafe_get(i) & mask) + carry
    r.unsafe_set(i, s & limb_mask)
    carry = s >> 32
  }
  r
}

///|
/// `a * b * R^-1 mod p`, by schoolbook product then Montgomery reduction. The
/// product goes into the field's scratch buffer, the index arithmetic is in
/// range by construction, and the final conditional subtraction is a mask, so
/// the loop allocates once and branches on nothing.
fn fmul(a : Fp, b : Fp, f : Field) -> Fp {
  let k = f.k
  let p = f.p
  let t = f.scratch
  for i in 0..<(2 * k + 2) {
    t.unsafe_set(i, 0UL)
  }
  for i in 0..<k {
    let ai = a.unsafe_get(i)
    let mut carry = 0UL
    for j in 0..<k {
      let uv = t.unsafe_get(i + j) + ai * b.unsafe_get(j) + carry
      t.unsafe_set(i + j, uv & 0xFFFFFFFFUL)
      carry = uv >> 32
    }
    let s = t.unsafe_get(i + k) + carry
    t.unsafe_set(i + k, s & 0xFFFFFFFFUL)
    t.unsafe_set(i + k + 1, t.unsafe_get(i + k + 1) + (s >> 32))
  }
  for i in 0..<k {
    let m = (t.unsafe_get(i) * f.n0) & 0xFFFFFFFFUL
    let mut carry = 0UL
    for j in 0..<k {
      let uv = t.unsafe_get(i + j) + m * p.unsafe_get(j) + carry
      t.unsafe_set(i + j, uv & 0xFFFFFFFFUL)
      carry = uv >> 32
    }
    let s = t.unsafe_get(i + k) + carry
    t.unsafe_set(i + k, s & 0xFFFFFFFFUL)
    t.unsafe_set(i + k + 1, t.unsafe_get(i + k + 1) + (s >> 32))
  }
  let out = FixedArray::make(k, 0UL)
  for i in 0..<k {
    out.unsafe_set(i, t.unsafe_get(k + i))
  }
  let mut borrow = 0UL
  for i in 0..<k {
    let d = out.unsafe_get(i) - p.unsafe_get(i) - borrow
    out.unsafe_set(i, d & 0xFFFFFFFFUL)
    borrow = d >> 63
  }
  // `borrow` is the carry out of `t - p`; when it differs from the top limb of
  // `t` the subtraction should not have happened, so `p` goes back on.
  let mask = 0UL - (borrow ^ t.unsafe_get(2 * k))
  let mut carry = 0UL
  for i in 0..<k {
    let s = out.unsafe_get(i) + (p.unsafe_get(i) & mask) + carry
    out.unsafe_set(i, s & 0xFFFFFFFFUL)
    carry = s >> 32
  }
  out
}

///|
/// `a^2`.
fn fsqr(a : Fp, f : Field) -> Fp {
  fmul(a, a, f)
}

///|
/// Convert a plain integer into Montgomery form.
fn ffrom(value : BigInt, f : Field) -> Fp {
  let plain = limbs_from_be(value.to_octets(length=f.k * 4)[:], f.k)
  fmul(plain, f.r2, f)
}

///|
/// Convert a Montgomery element back to a plain integer.
fn fto(value : Fp, f : Field) -> BigInt {
  let one_plain = FixedArray::make(f.k, 0UL)
  one_plain[0] = 1UL
  BigInt::from_octets(limbs_to_be(fmul(value, one_plain, f), f.k)[:])
}

///|
/// `a^-1`, by Fermat: `a^(p-2)`, a fixed exponent, so the loop shape does not
/// depend on `a`.
fn finv(a : Fp, f : Field) -> Fp {
  let mut r = copy_limbs(f.one, f.k)
  let mut i = f.exp_bits - 1
  while i >= 0 {
    r = fsqr(r, f)
    if bit_of_limbs(f.exp, i) {
      r = fmul(r, a, f)
    }
    i = i - 1
  }
  r
}

///|
/// Build the field for `curve`: the modulus, `R^2`, the Montgomery constant and
/// `p-2` for the inverse.
fn field_of(curve : Curve) -> Field {
  let p_big = params(curve).p
  let k = (bits(p_big) + 31) / 32
  let kk = k * 4
  let p = limbs_from_be(p_big.to_octets(length=kk)[:], k)
  let mut inv = 1UL
  for _ in 0..<5 {
    inv = (inv * (2UL - ((p[0] * inv) & limb_mask))) & limb_mask
  }
  let n0 = (0x100000000UL - inv) & limb_mask
  let r = (1 : BigInt) << (32 * k)
  let r2 = limbs_from_be((r * r % p_big).to_octets(length=kk)[:], k)
  let one = limbs_from_be((r % p_big).to_octets(length=kk)[:], k)
  let exp = p_big - (2 : BigInt)
  let base : Field = {
    k,
    p,
    n0,
    r2,
    one,
    a: FixedArray::make(k, 0UL),
    exp: limbs_from_be(exp.to_octets(length=kk)[:], k),
    exp_bits: bits(exp),
    scratch: FixedArray::make(2 * k + 2, 0UL),
  }
  let a = ffrom(params(curve).a, base)
  {
    k,
    p,
    n0,
    r2,
    one,
    a,
    exp: base.exp,
    exp_bits: base.exp_bits,
    scratch: base.scratch,
  }
}

///|
/// A point in Jacobian coordinates over the limb field.
priv struct Jp {
  x : Fp
  y : Fp
  z : Fp
}

///|
fn jp_infinity(f : Field) -> Jp {
  {
    x: FixedArray::make(f.k, 0UL),
    y: FixedArray::make(f.k, 0UL),
    z: FixedArray::make(f.k, 0UL),
  }
}

///|
/// All ones when every limb is zero, zero otherwise — the mask form of
/// [`fis_zero`], so a caller can select without branching.
fn fzero_mask(a : Fp, k : Int32) -> UInt64 {
  let mut acc = 0UL
  for i in 0..<k {
    acc = acc | a.unsafe_get(i)
  }
  ((acc | (0UL - acc)) >> 63) - 1UL
}

///|
/// `a` where `mask` is all ones, `b` where it is zero.
fn fselect(mask : UInt64, a : Fp, b : Fp, k : Int32) -> Fp {
  let out = FixedArray::make(k, 0UL)
  for i in 0..<k {
    out.unsafe_set(
      i,
      b.unsafe_get(i) ^ (mask & (a.unsafe_get(i) ^ b.unsafe_get(i))),
    )
  }
  out
}

///|
/// The same choice over points.
fn jp_select(mask : UInt64, a : Jp, b : Jp, k : Int32) -> Jp {
  {
    x: fselect(mask, a.x, b.x, k),
    y: fselect(mask, a.y, b.y, k),
    z: fselect(mask, a.z, b.z, k),
  }
}

///|
/// `2P` in Jacobian coordinates, `dbl-2007-bl` (any `a`), evaluated
/// unconditionally: the exceptional inputs are folded in by [`jp_double`], so
/// the arithmetic itself has no branch.
fn jp_double_raw(p : Jp, f : Field) -> Jp {
  let xx = fsqr(p.x, f)
  let yy = fsqr(p.y, f)
  let yyyy = fsqr(yy, f)
  let zz = fsqr(p.z, f)
  let xyy = fadd(p.x, yy, f)
  let inner = fsub(fsub(fsqr(xyy, f), xx, f), yyyy, f)
  let s = fadd(inner, inner, f)
  let azz = fmul(f.a, fsqr(zz, f), f)
  let three_xx = fadd(fadd(xx, xx, f), xx, f)
  let m = fadd(three_xx, azz, f)
  let t = fsub(fsqr(m, f), fadd(s, s, f), f)
  let st = fsub(s, t, f)
  let mst = fmul(m, st, f)
  let two_yyyy = fadd(yyyy, yyyy, f)
  let four_yyyy = fadd(two_yyyy, two_yyyy, f)
  let eight_yyyy = fadd(four_yyyy, four_yyyy, f)
  let y3 = fsub(mst, eight_yyyy, f)
  let yz = fadd(p.y, p.z, f)
  let z3 = fsub(fsub(fsqr(yz, f), yy, f), zz, f)
  { x: t, y: y3, z: z3, }
}

///|
/// `2P`. The doubling is already total on the inputs that occur here: a `z` of
/// zero stays zero through `z3 = (y+z)^2 - y^2 - z^2`, so the point at infinity
/// maps to itself without a mask, and a point of order two — the only other
/// exceptional input — cannot exist on a curve of prime order.
fn jp_double(p : Jp, f : Field) -> Jp {
  jp_double_raw(p, f)
}

///|
/// `P + Q` in Jacobian coordinates, `add-2007-bl`, evaluated unconditionally.
fn jp_add_raw(a : Jp, b : Jp, f : Field) -> Jp {
  let z1z1 = fsqr(a.z, f)
  let z2z2 = fsqr(b.z, f)
  let u1 = fmul(a.x, z2z2, f)
  let u2 = fmul(b.x, z1z1, f)
  let s1 = fmul(fmul(a.y, b.z, f), z2z2, f)
  let s2 = fmul(fmul(b.y, a.z, f), z1z1, f)
  let h = fsub(u2, u1, f)
  let dr = fsub(s2, s1, f)
  let r = fadd(dr, dr, f)
  let hh = fsqr(h, f)
  let i = fadd(hh, hh, f)
  let i = fadd(i, i, f)
  let j = fmul(h, i, f)
  let v = fmul(u1, i, f)
  let x3 = fsub(fsub(fsqr(r, f), j, f), fadd(v, v, f), f)
  let rvx = fmul(r, fsub(v, x3, f), f)
  let s1j = fmul(s1, j, f)
  let y3 = fsub(rvx, fadd(s1j, s1j, f), f)
  let zz = fadd(a.z, b.z, f)
  let z3 = fmul(fsub(fsub(fsqr(zz, f), z1z1, f), z2z2, f), h, f)
  { x: x3, y: y3, z: z3, }
}

///|
/// `P + Q`, complete for every pair the ladder can produce. Its two operands
/// always differ by the base point, so they are never equal and the
/// equal-points case of the formula is unreachable: when `h` is zero the raw
/// sum already has `z = 0`, which is the point at infinity. An infinity on
/// either side is folded in with a mask, so the operation count stays fixed.
fn jp_add(a : Jp, b : Jp, f : Field) -> Jp {
  let raw = jp_add_raw(a, b, f)
  let all = 0xFFFFFFFFFFFFFFFFUL
  let a_gone = fzero_mask(a.z, f.k)
  let b_gone = fzero_mask(b.z, f.k)
  let out = jp_select(a_gone, b, raw, f.k)
  jp_select(b_gone & (a_gone ^ all), a, out, f.k)
}

///|
/// All ones when `i == digit`, zero otherwise: the table scan below must not
/// branch on the digit it is looking for.
fn digit_mask(i : Int32, digit : Int32) -> UInt64 {
  let diff = (i ^ digit).to_uint64()
  ((diff | (0UL - diff)) >> 63) - 1UL
}

///|
/// `digit·P` for a secret `digit < 16`: the whole table is read and the match
/// kept with a mask, so the work does not depend on which multiple was asked
/// for — an indexed read would put the scalar into the cache line pattern.
fn window_lookup(table : FixedArray[Jp], digit : Int32, f : Field) -> Jp {
  let out = jp_infinity(f)
  let k = f.k
  for i in 0..<16 {
    // No `if mask != 0`: the branch would be taken exactly once, in the
    // position of the digit, which is the one thing the scan exists to hide.
    let mask = digit_mask(i, digit)
    let e = table.unsafe_get(i)
    for j in 0..<k {
      out.x.unsafe_set(
        j,
        out.x.unsafe_get(j) ^ (mask & (e.x.unsafe_get(j) ^ out.x.unsafe_get(j))),
      )
      out.y.unsafe_set(
        j,
        out.y.unsafe_get(j) ^ (mask & (e.y.unsafe_get(j) ^ out.y.unsafe_get(j))),
      )
      out.z.unsafe_set(
        j,
        out.z.unsafe_get(j) ^ (mask & (e.z.unsafe_get(j) ^ out.z.unsafe_get(j))),
      )
    }
  }
  out
}

///|
/// `[k]P` over the limb field, four bits at a time: each nibble costs four
/// doublings and one addition against the precomputed small multiples, so a
/// scalar multiplication is 64 additions and 256 doublings instead of 256 of
/// each. The loop covers the scalar's full width and the table is scanned
/// whole, so neither the count nor the sequence of operations follows `k`.
fn mul_limb(c : Curve, k : BigInt, pt : Point) -> Point {
  let f = field_of(c)
  let size = c.size()
  let scalar = k.to_octets(length=size)
  let z_one = copy_limbs(f.one, f.k)
  let base : Jp = { x: ffrom(pt.x, f), y: ffrom(pt.y, f), z: z_one, }
  let table = FixedArray::make(16, jp_infinity(f))
  for i in 0..<16 {
    table.unsafe_set(i, jp_infinity(f))
  }
  table.unsafe_set(1, base)
  // 2P comes from the doubling formula: the addition law leaves the
  // equal-points case to infinity, which is what the ladder wants and not what
  // a table wants. From there (i-1)·P and P differ by P, which they never do.
  if 16 > 2 {
    table.unsafe_set(2, jp_double(base, f))
  }
  for i in 3..<16 {
    table.unsafe_set(i, jp_add(table.unsafe_get(i - 1), base, f))
  }
  let mut acc = jp_infinity(f)
  for i in 0..<(size * 2) {
    if i > 0 {
      for _ in 0..<4 {
        acc = jp_double(acc, f)
      }
    }
    let byte = scalar.unsafe_get(i / 2).to_int()
    let digit = if i % 2 == 0 { (byte >> 4) & 0xF } else { byte & 0xF }
    acc = jp_add(acc, window_lookup(table, digit, f), f)
  }
  if fis_zero(acc.z, f.k) {
    return { x: 0, y: 0, zero: true, }
  }
  let zi = finv(acc.z, f)
  let zi2 = fsqr(zi, f)
  let zi3 = fmul(zi2, zi, f)
  {
    x: fto(fmul(acc.x, zi2, f), f),
    y: fto(fmul(acc.y, zi3, f), f),
    zero: false,
  }
}
