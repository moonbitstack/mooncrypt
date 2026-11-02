// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The modulus (FIPS 203 §8, Table 2). Small enough that every intermediate in
/// the NTT fits an `Int32` with room to spare, which is why the limbs are
/// `Int32` and not reduced after every butterfly.
let q : Int32 = 3329

///|
/// `q` as the ring's degree, in coefficients.
let degree : Int32 = 256

///|
/// All 256 coefficients of one element of `Z_q[X]/(X^256 + 1)`, in the order
/// FIPS 203 uses them: coefficient `i` multiplies `X^i`.
///
/// Coefficients are held as `Int32` and are *not* kept in `[0, q)` between
/// steps. The NTT's butterflies leave them in `(-2q, 2q)`, and reducing there
/// would cost a multiply and a mask per coefficient per layer for nothing —
/// [`reduce`] puts them back in range once, where the value is read out.
type Poly = FixedArray[Int32]

///|
fn poly() -> Poly {
  FixedArray::make(degree, 0)
}

///|
/// Multiply and shift back by 16 bits: `a * 2^-16 mod q`, the step the
/// Montgomery form of the NTT products is built from.
///
/// The middle term is the 16-bit word `a * q^-1 mod 2^16` read as a signed
/// integer. Writing it as a product by the *signed* `q^-1` keeps it inside
/// `Int32`; masking to 16 bits then sign-extending gives the same word back
/// without a branch.
fn montgomery_reduce(a : Int32) -> Int32 {
  let t = ((a & 0xFFFF) * q_inv) & 0xFFFF
  let signed = t << 16 >> 16
  (a - signed * q) >> 16
}

///|
/// `q^-1 mod 2^16`, as the negative residue so the product above stays small.
let q_inv : Int32 = -3327

///|
/// `2^16 mod q`: the representable one in Montgomery form.
let mont : Int32 = 2285

///|
/// `(2^16)^2 / 128 mod q`, which the inverse NTT multiplies by to undo both
/// the Montgomery factor of every butterfly and the factor of 128 that the
/// inverse transform introduces.
let inv_ntt_factor : Int32 = 1441

///|
fn fqmul(a : Int32, b : Int32) -> Int32 {
  montgomery_reduce(a * b)
}

///|
/// Barrett reduction of a value in about `(-2^14, 2^14)` back to `(-q, q)`.
fn barrett_reduce(a : Int32) -> Int32 {
  // `floor(2^26 / q)` rounded, as the reference implementation computes it.
  let t = ((20159 * a + (1 << 25)) >> 26) * q
  a - t
}

///|
/// The exact residue in `[0, q)`, whatever the input.
///
/// This is a division by a constant, so the compiler turns it into a multiply
/// and a shift: constant time, and the one place coefficients are brought into
/// range. A negative remainder takes one conditional addition of `q`, written
/// as a mask so it is not a branch on secret data.
fn reduce(x : Int32) -> Int32 {
  let r = x % q
  r + ((r >> 31) & q)
}

///|
/// The powers of the primitive root that the NTT multiplies by, in Montgomery
/// form and in the bit-reversed order the butterflies consume.
///
/// Computed rather than written out: a hand-copied table of 128 entries is 128
/// chances to mistype a digit, and the arithmetic that proves each entry is two
/// lines.
let zetas : FixedArray[Int32] = {
  let out = FixedArray::make(128, 0)
  for i in 0..<128 {
    // zeta_i = 17^bitrev7(i) * 2^16 mod q; 17 generates Z_q^*.
    let e = bitrev7(i)
    out[i] = pow(17, e) * mont % q
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
/// Seven bits, least significant first.
fn bitrev7(i : Int32) -> Int32 {
  let mut out = 0
  let mut n = i
  for _ in 0..<7 {
    out = (out << 1) | (n & 1)
    n = n >> 1
  }
  out
}

///|
/// The in-place forward transform (FIPS 203 Algorithm 9).
///
/// Every layer halves the block length and doubles the stride into [`zetas`],
/// which is seven layers for 256 coefficients: an in-place Cooley–Tukey over
/// the negacyclic ring, so the result is the 128 quadratic residues of the
/// polynomial and the 128 pairs its products live in.
fn ntt(r : Poly) -> Unit {
  let z = zetas
  let mut k = 1
  let mut len = 128
  while len >= 2 {
    let mut start = 0
    while start < degree {
      let zeta = z[k]
      k += 1
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
/// The in-place inverse transform multiplied by the Montgomery factor, so a
/// product of two transformed polynomials comes back out in the normal domain.
fn inv_ntt(r : Poly) -> Unit {
  let z = zetas
  let mut k = 127
  let mut len = 2
  while len <= 128 {
    let mut start = 0
    while start < degree {
      let zeta = z[k]
      k -= 1
      for j in start..<(start + len) {
        let t = r[j]
        r[j] = barrett_reduce(t + r[j + len])
        r[j + len] = r[j + len] - t
        r[j + len] = fqmul(zeta, r[j + len])
      }
      start = start + 2 * len
    }
    len = len << 1
  }
  for j in 0..<degree {
    r[j] = fqmul(r[j], inv_ntt_factor)
  }
}

///|
/// One product of two degree-one factors modulo `X^2 - zeta`, the unit the
/// transform leaves the polynomial in.
fn basemul(r : Poly, a : Poly, b : Poly) -> Unit {
  let z = zetas
  for i in 0..<64 {
    let zeta = z[64 + i]
    let t0 = fqmul(fqmul(a[4 * i + 1], b[4 * i + 1]), zeta)
    r[4 * i] = fqmul(a[4 * i], b[4 * i]) + t0
    r[4 * i + 1] = fqmul(a[4 * i], b[4 * i + 1]) + fqmul(a[4 * i + 1], b[4 * i])
    let t1 = fqmul(fqmul(a[4 * i + 3], b[4 * i + 3]), -zeta)
    r[4 * i + 2] = fqmul(a[4 * i + 2], b[4 * i + 2]) + t1
    r[4 * i + 3] = fqmul(a[4 * i + 2], b[4 * i + 3]) +
      fqmul(a[4 * i + 3], b[4 * i + 2])
  }
}

///|
/// `out += a * b` in the transform domain, one product of the matrix and
/// vector product at a time.
fn basemul_add(out : Poly, a : Poly, b : Poly) -> Unit {
  let tmp = poly()
  basemul(tmp, a, b)
  for i in 0..<degree {
    out[i] = out[i] + tmp[i]
  }
}

///|
/// Multiply by `2^16`, taking a polynomial out of the Montgomery domain.
fn to_mont(r : Poly) -> Unit {
  for i in 0..<degree {
    r[i] = fqmul(r[i], 1353)
  }
}

///|
fn add_assign(a : Poly, b : Poly) -> Unit {
  for i in 0..<degree {
    a[i] = a[i] + b[i]
  }
}

///|
fn sub(a : Poly, b : Poly) -> Poly {
  let out = poly()
  for i in 0..<degree {
    out[i] = a[i] - b[i]
  }
  out
}

///|
fn reduce_poly(r : Poly) -> Unit {
  for i in 0..<degree {
    r[i] = reduce(r[i])
  }
}

// ------------------------------------------------------------------ encoding

///|
/// Write a polynomial as `d` bits per coefficient, low coefficient first and
/// each field starting at the next free bit.
///
/// Coefficients must already be in `[0, m)` for the `d` in use — the
/// compression step is what puts them there.
fn pack(r : Poly, d : Int32) -> Bytes {
  let out = Array::make(degree * d / 8, b'\x00')
  let mut acc = 0
  let mut bits = 0
  let mut at = 0
  for i in 0..<degree {
    acc = acc | (r[i] << bits)
    bits += d
    while bits >= 8 {
      out[at] = (acc & 0xFF).to_byte()
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
  let mask = (1 << d) - 1
  let mut acc = 0
  let mut bits = 0
  let mut at = 0
  for i in 0..<degree {
    while bits < d {
      acc = acc | (b[at].to_int() << bits)
      at += 1
      bits += 8
    }
    r[i] = acc & mask
    acc = acc >> d
    bits -= d
  }
  r
}

///|
/// `Compress_d` (FIPS 203 §4.2.1): `x` scaled from `[0, q)` to `[0, 2^d)` and
/// rounded to nearest, by adding half a step before the division.
fn compress(x : Int32, d : Int32) -> Int32 {
  (((x << d) + (q >> 1)) / q) & ((1 << d) - 1)
}

///|
fn decompress(y : Int32, d : Int32) -> Int32 {
  (y * q + (1 << (d - 1))) >> d
}

///|
/// The lossless twelve-bit encoding of a polynomial, which a key's components
/// are written in. Coefficients come out of the transform in `(-q, q)`, so they
/// are brought into range first: twelve bits hold `q` but not `-q`.
fn encode12(r : Poly) -> Bytes {
  reduce_poly(r)
  pack(r, 12)
}

///|
fn compress_poly(r : Poly, d : Int32) -> Bytes {
  for i in 0..<degree {
    r[i] = compress(reduce(r[i]), d)
  }
  pack(r, d)
}

///|
fn decompress_poly(b : BytesView, d : Int32) -> Poly {
  let r = unpack(b, d)
  for i in 0..<degree {
    r[i] = decompress(r[i], d)
  }
  r
}

// ------------------------------------------------------------------- sampling

///|
/// `SampleNTT` (FIPS 203 Algorithm 7): rejection sampling from a SHAKE128
/// stream, three bytes at a time, keeping the 12-bit halves that are below `q`.
///
/// The stream is read three bytes at a time rather than in bulk because a
/// rejected half must not advance the stream by a whole extra triple; SHAKE's
/// squeeze is a stream, so taking three bytes at a time is the cheap way to say
/// exactly that.
fn sample_ntt(seed : BytesView) -> Poly {
  let r = poly()
  let x = @sha3.Xof::new(kind=@sha3.Shake128)
  x.absorb(seed)
  let mut i = 0
  while i < degree {
    let b = x.squeeze(3)
    let a0 = b[0].to_int() | ((b[1].to_int() & 0x0F) << 8)
    let a1 = (b[1].to_int() >> 4) | (b[2].to_int() << 4)
    if a0 < q {
      r[i] = a0
      i += 1
    }
    if a1 < q && i < degree {
      r[i] = a1
      i += 1
    }
  }
  r
}

///|
/// The sum of the `eta` bits at bit offset `at`, least significant bit first.
///
/// A sum, not the value the bits spell out: the binomial distribution counts
/// how many of the bits are set, so their weights are all one.
fn sum_bits(b : BytesView, at : Int32, eta : Int32) -> Int32 {
  let mut acc = 0
  for i in 0..<eta {
    let bit = at + i
    acc = acc + ((b[bit >> 3].to_int() >> (bit & 7)) & 1)
  }
  acc
}

///|
/// `SamplePolyCBD_eta` (FIPS 203 Algorithm 8): the difference of the two
/// `eta`-bit sums in each half of a `2 * eta`-bit window.
fn sample_cbd(seed : BytesView, eta : Int32) -> Poly {
  let stream = @sha3.shake256(seed, 64 * eta)
  let r = poly()
  for i in 0..<degree {
    let at = 2 * eta * i
    r[i] = sum_bits(stream, at, eta) - sum_bits(stream, at + eta, eta)
  }
  r
}
