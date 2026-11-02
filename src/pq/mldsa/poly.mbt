// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The modulus (FIPS 204 Table 1): 8380417 = 2^23 - 2^13 + 1.
///
/// It is one more than a multiple of 512, so `Z_q[X]/(X^256 + 1)` splits
/// completely and the transform has eight layers with no leftover pair to
/// multiply separately, which is the difference from ML-KEM's ring.
let q : Int32 = 8380417

///|
/// The degree, in coefficients.
let degree : Int32 = 256

///|
/// The bit width of the dropped half in `Power2Round` (FIPS 204 §7.4).
let dropped : Int32 = 13

///|
/// The 256 coefficients of a ring element, unreduced between steps: the
/// butterflies here add at most `q` per layer, so eight layers stay inside
/// `Int32` and the reduction costs one pass at the end instead of one per
/// coefficient per layer.
type Poly = FixedArray[Int32]

///|
fn poly() -> Poly {
  FixedArray::make(degree, 0)
}

///|
fn polys(n : Int32) -> Array[Poly] {
  let out : Array[Poly] = []
  for _ in 0..<n {
    out.push(poly())
  }
  out
}

///|
/// `a * 2^-32 mod q`.
///
/// The low word of the product by `q^-1` is exactly the multiple of `q` to
/// subtract, so the intermediate is computed in 32 bits and only the
/// subtraction needs 64. `a` must be below `q * 2^31` in magnitude, which a
/// product of two reduced coefficients always is.
fn montgomery_reduce(a : Int64) -> Int32 {
  let t = a.to_int() * q_inv
  ((a - t.to_int64() * q.to_int64()) >> 32).to_int()
}

///|
/// `q^-1 mod 2^32`, the multiplier that cancels the low word.
let q_inv : Int32 = 58728449

///|
/// `2^32 mod q`: the representable one in Montgomery form.
let mont : Int32 = 4193792

///|
fn fqmul(a : Int32, b : Int32) -> Int32 {
  montgomery_reduce(a.to_int64() * b.to_int64())
}

///|
/// `(2^32)^2 / 256 mod q`: what the inverse transform multiplies by to undo
/// both the Montgomery factor of each butterfly and the factor of 256.
let inv_ntt_factor : Int32 = 41978

///|
/// The residues the transform multiplies by, in bit-reversed order: entry `i`
/// is `1753^bitrev8(i)`, the powers of a 512th root of unity that is congruent
/// to 1753.
///
/// Computed rather than transcribed: 256 hand-copied entries are 256 chances
/// to mistype a digit, and the loop that produces them is three lines.
let zetas : FixedArray[Int32] = {
  let out = FixedArray::make(256, 0)
  for i in 1..<256 {
    // In Montgomery form, because the butterflies multiply through
    // montgomery_reduce: a plain root would leave a factor of 2^32 behind.
    out[i] = (pow(1753, bitrev8(i)).to_int64() * mont.to_int64() % q.to_int64()).to_int()
  }
  out
}

///|
fn pow(base : Int32, e : Int32) -> Int32 {
  let mut result = 1L
  let mut b = base.to_int64()
  let mut n = e
  while n > 0 {
    if (n & 1) == 1 {
      result = result * b % q.to_int64()
    }
    b = b * b % q.to_int64()
    n = n >> 1
  }
  result.to_int()
}

///|
/// Eight bits, least significant first.
fn bitrev8(i : Int32) -> Int32 {
  let mut out = 0
  let mut n = i
  for _ in 0..<8 {
    out = (out << 1) | (n & 1)
    n = n >> 1
  }
  out
}

///|
/// The forward transform (FIPS 204 Algorithm 41), in place.
fn ntt(r : Poly) -> Unit {
  let z = zetas
  let mut k = 0
  let mut len = 128
  while len > 0 {
    let mut start = 0
    while start < degree {
      k += 1
      let zeta = z[k]
      for j in start..<(start + len) {
        let t = fqmul(zeta, r[j + len])
        r[j + len] = r[j] - t
        r[j] = r[j] + t
      }
      start = start + 2 * len
    }
    len = len >> 1
  }
}

///|
/// The inverse transform multiplied by the Montgomery factor (FIPS 204
/// Algorithm 42), in place.
fn inv_ntt(r : Poly) -> Unit {
  let z = zetas
  let mut k = 256
  let mut len = 1
  while len < degree {
    let mut start = 0
    while start < degree {
      k -= 1
      let zeta = -z[k]
      for j in start..<(start + len) {
        let t = r[j]
        r[j] = t + r[j + len]
        r[j + len] = fqmul(zeta, t - r[j + len])
      }
      start = start + 2 * len
    }
    len = len << 1
  }
  for j in 0..<degree {
    r[j] = fqmul(inv_ntt_factor, r[j])
  }
}

///|
/// The exact residue in `[0, q)`.
///
/// A division by a constant, so the compiler turns it into a multiply and a
/// shift; the negative case takes one masked addition of `q` rather than a
/// branch on a coefficient.
fn freeze(x : Int32) -> Int32 {
  let r = x % q
  r + ((r >> 31) & q)
}

///|
/// The representative `m` with `|m| <= (q-1)/2` and `m ≡ x (mod q)`.
fn centered(x : Int32) -> Int32 {
  let r = freeze(x)
  if r > (q - 1) / 2 {
    r - q
  } else {
    r
  }
}

///|
fn add_assign(a : Poly, b : Poly) -> Unit {
  for i in 0..<degree {
    a[i] = a[i] + b[i]
  }
}

///|
fn sub_assign(a : Poly, b : Poly) -> Unit {
  for i in 0..<degree {
    a[i] = a[i] - b[i]
  }
}

///|
/// `out += a * b` in the transform domain, one coefficient pair at a time.
fn pointwise_add(out : Poly, a : Poly, b : Poly) -> Unit {
  for i in 0..<degree {
    out[i] = out[i] + fqmul(a[i], b[i])
  }
}

///|
fn pointwise(a : Poly, b : Poly) -> Poly {
  let out = poly()
  for i in 0..<degree {
    out[i] = fqmul(a[i], b[i])
  }
  out
}

// ---------------------------------------------------------------- rounding

///|
/// `Power2Round` (FIPS 204 Algorithm 35): split `a` into the high half, which
/// is published, and the low half, which is kept and must stay small.
fn power2round(a : Int32) -> (Int32, Int32) {
  let a1 = (a + (1 << (dropped - 1)) - 1) >> dropped
  (a1, a - (a1 << dropped))
}

///|
/// `Decompose` (FIPS 204 Algorithm 36): the high and low halves at `gamma2`.
///
/// Both constants are `(q - 1) / 32` or `(q - 1) / 88`, and the multiply and
/// shift that follow are the exact division by those, chosen so that the low
/// half lands in `(-gamma2, gamma2]` instead of a half-open interval.
fn decompose(a : Int32, gamma2 : Int32) -> (Int32, Int32) {
  let mut a1 = (a + 127) >> 7
  if gamma2 == (q - 1) / 32 {
    a1 = ((a1 * 1025 + (1 << 21)) >> 22) & 15
  } else {
    a1 = (a1 * 11275 + (1 << 23)) >> 24
    a1 = a1 ^ (((43 - a1) >> 31) & a1)
  }
  let mut a0 = a - a1 * 2 * gamma2
  a0 = a0 - ((((q - 1) / 2 - a0) >> 31) & q)
  (a1, a0)
}

///|
/// `HighBits` of every coefficient.
fn high_bits(r : Poly, gamma2 : Int32) -> Poly {
  let out = poly()
  for i in 0..<degree {
    out[i] = decompose(freeze(r[i]), gamma2).0
  }
  out
}

///|
/// `LowBits` of every coefficient.
fn low_bits(r : Poly, gamma2 : Int32) -> Poly {
  let out = poly()
  for i in 0..<degree {
    out[i] = decompose(freeze(r[i]), gamma2).1
  }
  out
}

///|
/// `MakeHint` (FIPS 204 Algorithm 39): whether adding `z` to `r` moves the high
/// half. Both halves are computed and compared rather than derived from an
/// inequality, which is the definition and not much more work.
fn make_hint(z : Poly, r : Poly, gamma2 : Int32) -> Poly {
  let out = poly()
  for i in 0..<degree {
    let before = decompose(freeze(r[i]), gamma2).0
    let after = decompose(freeze(r[i] + z[i]), gamma2).0
    out[i] = if before == after { 0 } else { 1 }
  }
  out
}

///|
/// `UseHint` (FIPS 204 Algorithm 40), with the wrap that the number of high
/// bits implies.
fn use_hint(a : Int32, hint : Int32, gamma2 : Int32) -> Int32 {
  let (a1, a0) = decompose(freeze(a), gamma2)
  if hint == 0 {
    return a1
  }
  if gamma2 == (q - 1) / 32 {
    if a0 > 0 {
      (a1 + 1) & 15
    } else {
      (a1 - 1) & 15
    }
  } else if a0 > 0 {
    if a1 == 43 {
      0
    } else {
      a1 + 1
    }
  } else if a1 == 0 {
    43
  } else {
    a1 - 1
  }
}

///|
/// The largest absolute value over the coefficients, which is what the norm
/// bounds are stated in.
fn max_abs(r : Poly) -> Int32 {
  let mut m = 0
  for i in 0..<degree {
    let v = centered(r[i])
    let a = if v < 0 { -v } else { v }
    if a > m {
      m = a
    }
  }
  m
}

///|
/// The number of non-zero coefficients, which a hint must not exceed `omega`.
fn count_nonzero(r : Poly) -> Int32 {
  let mut n = 0
  for i in 0..<degree {
    if r[i] != 0 {
      n += 1
    }
  }
  n
}

// ------------------------------------------------------------------ packing

///|
/// Write coefficients as `d` bits each, low coefficient first.
///
/// The values must already be in `[0, 2^d)`; every packed polynomial here goes
/// through a shift-and-reduce that puts them there.
fn pack(r : Poly, d : Int32) -> Bytes {
  let out = Array::make(degree * d / 8, b'\x00')
  let mut acc = 0L
  let mut bits = 0
  let mut at = 0
  for i in 0..<degree {
    acc = acc | (r[i].to_int64() << bits)
    bits += d
    while bits >= 8 {
      out[at] = (acc & 0xFF).to_int().to_byte()
      at += 1
      acc = acc >> 8
      bits -= 8
    }
  }
  Bytes::from_array(out)
}

///|
fn unpack(b : BytesView, d : Int32) -> Poly {
  let r = poly()
  let mut acc = 0L
  let mut bits = 0
  let mut at = 0
  let mask = (1L << d) - 1
  for i in 0..<degree {
    while bits < d {
      acc = acc | (b[at].to_int64() << bits)
      at += 1
      bits += 8
    }
    r[i] = (acc & mask).to_int()
    acc = acc >> d
    bits -= d
  }
  r
}
