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
  // Which doubling formula applies: `a = -3` and `a = 0` both have a cheaper one
  // than the general `a`, and between them they cover five of the seven curves
  // here. Public, so the branch it drives is not one a secret can steer.
  a_kind : Int32
  // The wide product goes here instead of into a fresh array: no multiplication
  // nests inside another, so one buffer per field is enough and it takes the
  // largest allocation out of the hot loop.
  scratch : FixedArray[UInt64]
  // `fsqr` needs the diagonal terms in a second buffer: it writes the square to
  // `scratch` and reads the diagonals back at the offset they land on.
  scratch2 : FixedArray[UInt64]
  // Field elements handed out to the arithmetic instead of being allocated:
  // a scalar multiplication makes some six thousand of them, and the allocation
  // was a quarter of the time each one took. `used` is a one-element array
  // because the field itself is passed by value everywhere.
  pool : FixedArray[Fp]
  used : FixedArray[Int32]
}

///|
/// How deep the pool goes: the longest expression in the point arithmetic is
/// about twenty live elements, and the rest is margin. Running past it is not an
/// error — `take` falls back to allocating, which is only slower.
let pool_depth : Int32 = 48

///|
/// A field element to write into. The caller owns it until the matching
/// [`release`], and every producer overwrites all `k` limbs.
fn take(f : Field) -> Fp {
  let at = f.used.unsafe_get(0)
  if at < f.pool.length() {
    f.used.unsafe_set(0, at + 1)
    f.pool.unsafe_get(at)
  } else {
    FixedArray::make(f.k, 0UL)
  }
}

///|
fn mark(f : Field) -> Int32 {
  f.used.unsafe_get(0)
}

///|
fn release(f : Field, at : Int32) -> Unit {
  f.used.unsafe_set(0, at)
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
  let out = take(f)
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
  let r = take(f)
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
/// Montgomery reduction of the wide product in `t`, `t * R^-1 mod p`. The
/// index arithmetic is in range by construction and the final conditional
/// subtraction is a mask, so the loop branches on nothing. Shared by `fmul` and
/// `fsqr`, which differ only in how they build `t`.
fn mont_reduce(t : FixedArray[UInt64], f : Field) -> Fp {
  let k = f.k
  let p = f.p
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
  let out = take(f)
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
/// `a * b * R^-1 mod p`, by schoolbook product then Montgomery reduction.
fn fmul(a : Fp, b : Fp, f : Field) -> Fp {
  let k = f.k
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
  mont_reduce(t, f)
}

///|
/// `a^2`, by the symmetric product: `a * a` costs `k^2` limb products, but the
/// off-diagonal half of them is counted twice and can be computed once — so the
/// square is `k(k+1)/2` products and a doubling. Squaring is the most frequent
/// field operation in the point arithmetic (five to eight per doubling, five
/// per addition), so this is where a quarter of the multiplications go.
fn fsqr(a : Fp, f : Field) -> Fp {
  let k = f.k
  let t = f.scratch
  let d = f.scratch2
  for i in 0..<(2 * k + 2) {
    t.unsafe_set(i, 0UL)
  }
  for i in 0..<k {
    let sq = a.unsafe_get(i) * a.unsafe_get(i)
    d.unsafe_set(2 * i, sq & 0xFFFFFFFFUL)
    d.unsafe_set(2 * i + 1, sq >> 32)
  }
  // The upper triangle: for row `i` the columns below the diagonal are left
  // alone, and the carry out of each row lands on a limb no earlier row wrote.
  for i in 0..<k {
    let ai = a.unsafe_get(i)
    let mut carry = 0UL
    for j in (i + 1)..<k {
      let uv = t.unsafe_get(i + j) + ai * a.unsafe_get(j) + carry
      t.unsafe_set(i + j, uv & 0xFFFFFFFFUL)
      carry = uv >> 32
    }
    t.unsafe_set(i + k, carry)
  }
  // Everything above the diagonal is counted twice.
  let mut carry = 0UL
  for i in 0..<(2 * k) {
    let v = (t.unsafe_get(i) << 1) | carry
    t.unsafe_set(i, v & 0xFFFFFFFFUL)
    carry = v >> 32
  }
  let mut j = 2 * k
  t.unsafe_set(j, t.unsafe_get(j) + carry)
  // The diagonal goes on in one pass in limb order, so the carry chain is the
  // same length whatever the value.
  let mut carry = 0UL
  for i in 0..<(2 * k) {
    let s = t.unsafe_get(i) + d.unsafe_get(i) + carry
    t.unsafe_set(i, s & 0xFFFFFFFFUL)
    carry = s >> 32
  }
  while j < 2 * k + 2 {
    let s = t.unsafe_get(j) + carry
    t.unsafe_set(j, s & 0xFFFFFFFFUL)
    carry = s >> 32
    j = j + 1
  }
  mont_reduce(t, f)
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
  let pool = FixedArray::make(pool_depth, FixedArray::make(0, 0UL))
  for i in 0..<pool_depth {
    pool.unsafe_set(i, FixedArray::make(k, 0UL))
  }
  let base : Field = {
    k,
    p,
    n0,
    r2,
    one,
    a: FixedArray::make(k, 0UL),
    exp: limbs_from_be(exp.to_octets(length=kk)[:], k),
    exp_bits: bits(exp),
    a_kind: 2,
    scratch: FixedArray::make(2 * k + 2, 0UL),
    scratch2: FixedArray::make(2 * k + 2, 0UL),
    pool,
    used: FixedArray::make(1, 0),
  }
  // `ffrom` hands back a pool slot, and this one has to outlive the pool: it is
  // the curve's `a`, read on every doubling.
  let a = copy_limbs(ffrom(params(curve).a, base), k)
  release(base, 0)
  let a_kind = if params(curve).a == (0 : BigInt) {
    0
  } else if params(curve).a + (3 : BigInt) == p_big {
    1
  } else {
    2
  }
  {
    k,
    p,
    n0,
    r2,
    one,
    a,
    exp: base.exp,
    exp_bits: base.exp_bits,
    a_kind,
    scratch: base.scratch,
    scratch2: base.scratch2,
    pool: base.pool,
    used: base.used,
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
/// `2P` in Jacobian coordinates, evaluated unconditionally: the exceptional
/// inputs are folded in by [`jp_double`], so the arithmetic itself has no
/// branch. The branch here is on the curve's `a`, which is public.
fn jp_double_raw(p : Jp, f : Field) -> Jp {
  let at = mark(f)
  let zz = fsqr(p.z, f)
  let yy = fsqr(p.y, f)
  let yz = fadd(p.y, p.z, f)
  let z3 = fsub(fsub(fsqr(yz, f), yy, f), zz, f)
  if f.a_kind == 1 {
    // dbl-2001-b, for `a = -3`: `3(X - Z²)(X + Z²)` replaces the `3X² + aZ⁴`
    // of the general formula with a single multiplication, and `X·Y²` is used
    // twice, so the doubling costs three multiplications and five squarings
    // where the general one costs two and eight.
    let beta = fmul(p.x, yy, f)
    let two_beta = fadd(beta, beta, f)
    let four_beta = fadd(two_beta, two_beta, f)
    let eight_beta = fadd(four_beta, four_beta, f)
    let diff = fsub(p.x, zz, f)
    let alpha = fmul(fadd(p.x, zz, f), fadd(fadd(diff, diff, f), diff, f), f)
    let x3 = fsub(fsqr(alpha, f), eight_beta, f)
    let gamma2 = fsqr(yy, f)
    let two_gamma2 = fadd(gamma2, gamma2, f)
    let four_gamma2 = fadd(two_gamma2, two_gamma2, f)
    let eight_gamma2 = fadd(four_gamma2, four_gamma2, f)
    let y3 = fsub(fmul(alpha, fsub(four_beta, x3, f), f), eight_gamma2, f)
    return settled(x3, y3, z3, f, at)
  }
  let xx = fsqr(p.x, f)
  let yyyy = fsqr(yy, f)
  let xyy = fadd(p.x, yy, f)
  let inner = fsub(fsub(fsqr(xyy, f), xx, f), yyyy, f)
  let s = fadd(inner, inner, f)
  let azz = if f.a_kind == 0 {
    FixedArray::make(f.k, 0UL)
  } else {
    fmul(f.a, fsqr(zz, f), f)
  }
  let m = fadd(fadd(fadd(xx, xx, f), xx, f), azz, f)
  let t = fsub(fsqr(m, f), fadd(s, s, f), f)
  let st = fsub(s, t, f)
  let mst = fmul(m, st, f)
  let two_yyyy = fadd(yyyy, yyyy, f)
  let four_yyyy = fadd(two_yyyy, two_yyyy, f)
  let eight_yyyy = fadd(four_yyyy, four_yyyy, f)
  settled(t, fsub(mst, eight_yyyy, f), z3, f, at)
}

///|
/// The result of a point operation, taken out of the pool: a point outlives the
/// expression that built it, so its three coordinates are copied to arrays of
/// their own before the temporaries are handed back.
fn settled(x : Fp, y : Fp, z : Fp, f : Field, at : Int32) -> Jp {
  let out = {
    x: copy_limbs(x, f.k),
    y: copy_limbs(y, f.k),
    z: copy_limbs(z, f.k),
  }
  release(f, at)
  out
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
  let at = mark(f)
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
  settled(x3, y3, z3, f, at)
}

///|
/// `P + Q`, correct for every pair except `Q = P`, which the law sends to
/// infinity instead of `2P`. That case is out of reach in the windowed ladder:
/// both operands are multiples of the one base point, so they are equal only
/// when the scalar prefix happens to satisfy `16A ≡ d (mod n)`, one scalar in
/// `2^252` and never the ones a caller picks. When `h` is zero the raw sum has
/// `z = 0`, the point at infinity. An infinity on either side is folded in with
/// a mask, so the operation count stays fixed.
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
/// The small multiples `P, 2P, … 15P` in Jacobian coordinates.
fn table_of(base : Jp, f : Field) -> FixedArray[Jp] {
  let table = FixedArray::make(16, jp_infinity(f))
  for i in 0..<16 {
    table.unsafe_set(i, jp_infinity(f))
  }
  table.unsafe_set(1, base)
  // 2P comes from the doubling formula: the addition law leaves the
  // equal-points case to infinity, which is what the ladder wants and not what
  // a table wants. From there (i-1)·P and P differ by P, which they never do.
  table.unsafe_set(2, jp_double(base, f))
  for i in 3..<16 {
    table.unsafe_set(i, jp_add(table.unsafe_get(i - 1), base, f))
  }
  table
}

///|
/// Nibble `i` of a scalar held big-endian, counting from the top.
fn digit_at(scalar : BytesView, i : Int32) -> Int32 {
  let byte = scalar.unsafe_get(i / 2).to_int()
  if i % 2 == 0 {
    (byte >> 4) & 0xF
  } else {
    byte & 0xF
  }
}

///|
/// A Jacobian point as an affine one: 0 and the point at infinity are the same
/// thing here, and the inverse is the one place a scalar multiplication can
/// still come out empty-handed.
fn jp_affine(acc : Jp, f : Field) -> Point {
  if fis_zero(acc.z, f.k) {
    return { x: 0, y: 0, zero: true, }
  }
  let at = mark(f)
  let zi = finv(acc.z, f)
  let zi2 = fsqr(zi, f)
  let zi3 = fmul(zi2, zi, f)
  let out = {
    x: fto(fmul(acc.x, zi2, f), f),
    y: fto(fmul(acc.y, zi3, f), f),
    zero: false,
  }
  release(f, at)
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
  let table = table_of({ x: ffrom(pt.x, f), y: ffrom(pt.y, f), z: z_one, }, f)
  let mut acc = jp_infinity(f)
  for i in 0..<(size * 2) {
    if i > 0 {
      for _ in 0..<4 {
        acc = jp_double(acc, f)
      }
    }
    acc = jp_add(acc, window_lookup(table, digit_at(scalar, i), f), f)
  }
  jp_affine(acc, f)
}

///|
/// `[k1]G + [k2]P`, in one loop: the doublings are shared, and the half against
/// the fixed base comes from the comb table instead of a second window. That is
/// the shape of every signature verification here.
///
/// The two halves want different numbers of doublings — the comb needs `d - 1`,
/// the window one per scalar bit — so the comb rows are spent in the last `d`
/// steps, where a row is worth `2^j` with `j` the number of doublings still to
/// come. Doubling a partial sum that is still zero costs nothing but the
/// doublings it was going to make anyway.
fn mul2_g_limb(c : Curve, k1 : BigInt, k2 : BigInt, pt : Point) -> Point {
  let table = fixed_base_of(c)
  let f = field_of(c)
  let kk = f.k
  let w = fixed_window
  let size = c.size()
  let bit_count = size * 8
  let d = (bits(params(c).n) + w - 1) / w
  let len = (w * d + 7) / 8
  let s1 = k1.to_octets(length=len)
  let s2 = k2.to_octets(length=size)
  let z_one = copy_limbs(f.one, f.k)
  let win = table_of({ x: ffrom(pt.x, f), y: ffrom(pt.y, f), z: z_one, }, f)
  let ex = FixedArray::make(kk, 0UL)
  let ey = FixedArray::make(kk, 0UL)
  let mut acc = jp_infinity(f)
  for i in 0..<bit_count {
    if i > 0 {
      acc = jp_double(acc, f)
    }
    if (i + 1) % 4 == 0 {
      acc = jp_add(acc, window_lookup(win, digit_at(s2, i / 4), f), f)
    }
    if i >= bit_count - d {
      let j = bit_count - 1 - i
      let row = comb_row(s1, j, w, d, len)
      for n in 0..<kk {
        ex.unsafe_set(n, 0UL)
        ey.unsafe_set(n, 0UL)
      }
      for e in 0..<(1 << w) {
        let mask = digit_mask(e, row)
        let at = e * 2 * kk
        for n in 0..<kk {
          ex.unsafe_set(
            n,
            ex.unsafe_get(n) ^
            (mask & (table.unsafe_get(at + n) ^ ex.unsafe_get(n))),
          )
          ey.unsafe_set(
            n,
            ey.unsafe_get(n) ^
            (mask & (table.unsafe_get(at + kk + n) ^ ey.unsafe_get(n))),
          )
        }
      }
      acc = jp_madd(acc, ex, ey, f)
    }
  }
  jp_affine(acc, f)
}

///|
/// The comb table for `curve`. Exhaustive on purpose: a curve without a table
/// does not compile, so adding one means running the generator rather than
/// quietly falling back to the slow path.
fn fixed_base_of(c : Curve) -> FixedArray[UInt64] {
  match c {
    P256 => p256_fixed
    P384 => p384_fixed
    P521 => p521_fixed
    Secp256k1 => secp256k1_fixed
    BrainpoolP256r1 => brainpool_p256_fixed
    BrainpoolP384r1 => brainpool_p384_fixed
    BrainpoolP512r1 => brainpool_p512_fixed
  }
}

///|
/// Row `j` of the scalar's bit matrix: bit `i` is scalar bit `i·d + j`, counted
/// from the least significant end of a `len`-byte big-endian scalar.
fn comb_row(
  scalar : BytesView,
  j : Int32,
  w : Int32,
  d : Int32,
  len : Int32,
) -> Int32 {
  let mut row = 0
  for i in 0..<w {
    let t = i * d + j
    let byte = scalar.unsafe_get(len - 1 - t / 8).to_int()
    row = row | (((byte >> (t % 8)) & 1) << i)
  }
  row
}

///|
/// `P + Q` where `Q` is affine and comes from the comb table, so `Z2 = 1`:
/// seven multiplications instead of ten. `madd-2007-bl`.
fn jp_madd_raw(a : Jp, x : Fp, y : Fp, f : Field) -> Jp {
  let at = mark(f)
  let z1z1 = fsqr(a.z, f)
  let u2 = fmul(x, z1z1, f)
  let s2 = fmul(fmul(y, a.z, f), z1z1, f)
  let h = fsub(u2, a.x, f)
  let hh = fsqr(h, f)
  let i = fadd(fadd(hh, hh, f), fadd(hh, hh, f), f)
  let j = fmul(h, i, f)
  let dy = fsub(s2, a.y, f)
  let r = fadd(dy, dy, f)
  let v = fmul(a.x, i, f)
  let x3 = fsub(fsub(fsqr(r, f), j, f), fadd(v, v, f), f)
  let y1j = fmul(a.y, j, f)
  let y3 = fsub(fmul(r, fsub(v, x3, f), f), fadd(y1j, y1j, f), f)
  let zh = fadd(a.z, h, f)
  let z3 = fsub(fsub(fsqr(zh, f), z1z1, f), hh, f)
  settled(x3, y3, z3, f, at)
}

///|
/// The same, with the two infinities folded in. A table entry of `(0, 0)` is the
/// point at infinity — that is `T[0]`, which a zero row reaches — and is given a
/// `z` of zero so the selection lands on the accumulator rather than on a false
/// affine point.
fn jp_madd(a : Jp, x : Fp, y : Fp, f : Field) -> Jp {
  let raw = jp_madd_raw(a, x, y, f)
  let all = 0xFFFFFFFFFFFFFFFFUL
  let a_gone = fzero_mask(a.z, f.k)
  let e_gone = fzero_mask(x, f.k) & fzero_mask(y, f.k)
  let z = fselect(e_gone, FixedArray::make(f.k, 0UL), f.one, f.k)
  let b : Jp = { x, y, z, }
  let out = jp_select(a_gone, b, raw, f.k)
  jp_select(e_gone & (a_gone ^ all), a, out, f.k)
}

///|
/// `[k]G` through the comb table: `d - 1` doublings and `d` mixed additions,
/// against one doubling per scalar bit for the general path. The table is read
/// whole — one entry per row, chosen by a mask — so the pattern of reads does
/// not follow `k`.
fn mul_g_limb(c : Curve, k : BigInt) -> Point {
  let table = fixed_base_of(c)
  let f = field_of(c)
  let kk = f.k
  let w = fixed_window
  let d = (bits(params(c).n) + w - 1) / w
  let len = (w * d + 7) / 8
  let scalar = k.to_octets(length=len)
  let ex = FixedArray::make(kk, 0UL)
  let ey = FixedArray::make(kk, 0UL)
  let mut acc = jp_infinity(f)
  let mut j = d - 1
  while j >= 0 {
    if j < d - 1 {
      acc = jp_double(acc, f)
    }
    let row = comb_row(scalar, j, w, d, len)
    // The whole table, every row: an index would put the scalar into the cache
    // line pattern, which is the one thing this table must not leak.
    for i in 0..<kk {
      ex.unsafe_set(i, 0UL)
      ey.unsafe_set(i, 0UL)
    }
    for e in 0..<(1 << w) {
      let mask = digit_mask(e, row)
      let at = e * 2 * kk
      for i in 0..<kk {
        ex.unsafe_set(
          i,
          ex.unsafe_get(i) ^
          (mask & (table.unsafe_get(at + i) ^ ex.unsafe_get(i))),
        )
        ey.unsafe_set(
          i,
          ey.unsafe_get(i) ^
          (mask & (table.unsafe_get(at + kk + i) ^ ey.unsafe_get(i))),
        )
      }
    }
    acc = jp_madd(acc, ex, ey, f)
    j = j - 1
  }
  jp_affine(acc, f)
}

// ------------------------------------------------------------ secp256k1 GLV

///|
/// `secp256k1` has `p ≡ 1 (mod 3)`, so the curve carries an endomorphism
/// `φ(x, y) = (βx, y)` with `β³ = 1 (mod p)`, and `φ` is multiplication by `λ`
/// with `λ³ = 1 (mod n)`. A scalar can therefore be split in two halves of half
/// the width — the lattice below is the one the GLV paper gives for this curve —
/// and `[k]P` becomes `[k₁]P + [k₂]φ(P)` with both halves under `2^128`. That
/// halves the doublings, which is where most of the work is.
let glv_beta : BigInt = big(
  "7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE",
)

///|
let glv_a1 : BigInt = big("3086D221A7D46BCDE86C90E49284EB15")

///|
let glv_b1 : BigInt = big("0E4437ED6010E88286F547FA90ABFE4C3")

///|
let glv_a2 : BigInt = big("114CA50F7A8E2F3F657C1108D9D44CFD8")

///|
let glv_b2 : BigInt = glv_a1

///|
/// `k = k₁ + k₂·λ` with `|k₁|, |k₂| < 2^128`, by rounding `k` onto the lattice
/// spanned by `(a₁, b₁)` and `(a₂, b₂)`. Both halves can come out negative, and
/// the caller turns that into a negation of the point rather than a reduction
/// back to full width.
fn glv_split(k : BigInt, n : BigInt) -> (BigInt, BigInt) {
  let half = n / (2 : BigInt)
  let c1 = (glv_b2 * k + half) / n
  let c2 = (glv_b1 * k + half) / n
  let k1 = k - c1 * glv_a1 - c2 * glv_a2
  let k2 = c1 * glv_b1 - c2 * glv_b2
  (k1, k2)
}

///|
/// `[k]P` for `secp256k1`, over the two halves. The tables are built for `P` and
/// `φ(P)` — negated where the half is negative — and the two run through one
/// windowed loop, so the multiplication is 124 doublings rather than 256.
fn mul_glv_limb(c : Curve, k : BigInt, pt : Point) -> Point {
  let n = params(c).n
  let (s1, s2) = glv_split(k, n)
  let half1 = if s1 < (0 : BigInt) { (0 : BigInt) - s1 } else { s1 }
  let half2 = if s2 < (0 : BigInt) { (0 : BigInt) - s2 } else { s2 }
  let f = field_of(c)
  let negate = fn(y : BigInt) { mod_p(c, (0 : BigInt) - y) }
  let first : Point = if s1 < (0 : BigInt) {
    { x: pt.x, y: negate(pt.y), zero: false, }
  } else {
    pt
  }
  let second : Point = {
    x: mod_p(c, glv_beta * pt.x),
    y: if s2 < (0 : BigInt) {
      negate(pt.y)
    } else {
      pt.y
    },
    zero: false,
  }
  let z_one = copy_limbs(f.one, f.k)
  let t1 = table_of(
    { x: ffrom(first.x, f), y: ffrom(first.y, f), z: z_one, },
    f,
  )
  let t2 = table_of(
    { x: ffrom(second.x, f), y: ffrom(second.y, f), z: copy_limbs(f.one, f.k), },
    f,
  )
  // Both halves are under `2^128`, so sixteen bytes carry them.
  let width = 16
  let s1b = half1.to_octets(length=width)
  let s2b = half2.to_octets(length=width)
  let mut acc = jp_infinity(f)
  for i in 0..<(width * 2) {
    if i > 0 {
      for _ in 0..<4 {
        acc = jp_double(acc, f)
      }
    }
    acc = jp_add(acc, window_lookup(t1, digit_at(s1b, i), f), f)
    acc = jp_add(acc, window_lookup(t2, digit_at(s2b, i), f), f)
  }
  jp_affine(acc, f)
}
