// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Fixed-width, constant-time modular exponentiation over a modulus of any byte
// width, for the RSA private exponentiation.
//
// The limbs are 32-bit values carried in 64-bit lanes, the same shape the
// Curve25519 field uses: a 64-bit lane holds a 32-bit limb and the carry out of
// it, so multiplying two limbs needs only the word the platform already has.
// Every operation that touches a secret runs over the same number of limbs on
// every call. The loop bound is the key's width, which is public and fixed;
// nothing here iterates over the value's significant bits, branches on an
// exponent bit, or stops early on a zero. That is the "fixed width" the timing
// claim rests on.

///|
/// How many 32-bit limbs a value of `bits` bits occupies.
fn width(bits : Int32) -> Int32 {
  (bits + 31) / 32
}

///|
/// How many bits `v` takes. Used on public values only: the modulus and the
/// public exponent.
fn bit_length(v : BigInt) -> Int32 {
  let mut bits = 0
  let mut rest = v
  while rest > 0N {
    bits += 1
    rest = rest >> 1
  }
  bits
}

///|
/// A Montgomery engine over one modulus: the modulus in 32-bit limbs (least
/// significant first), the reduction constant `n0`, `R^2 mod n` and `R mod n`
/// to convert in and out, and the scratch one product needs. Built per
/// exponentiation, so it holds nothing secret between operations.
priv struct Mont {
  size : Int32
  mod : FixedArray[UInt64]
  n0 : UInt64
  r2 : FixedArray[UInt64]
  one : FixedArray[UInt64]
  // The running sum of one product, and its trial subtraction of the modulus.
  t : FixedArray[UInt64]
  u : FixedArray[UInt64]
  // A square's full-width product, and the two halves it is reduced in.
  sq : FixedArray[UInt64]
  lo : FixedArray[UInt64]
  hi : FixedArray[UInt64]
}

///|
/// The lane width, `2^32`, as a BigInt.
let lane : BigInt = 1N << 32

///|
/// `v mod 2^32`, as a non-negative BigInt.
fn lo32(v : BigInt) -> BigInt {
  let m = v % lane
  if m < 0N {
    m + lane
  } else {
    m
  }
}

///|
/// The 32-bit limbs of `v`, least significant first, in `size` lanes.
fn limbs(v : BigInt, size : Int32) -> FixedArray[UInt64] {
  let bytes = v.to_octets(length=size * 4)
  let out = FixedArray::make(size, 0UL)
  for i in 0..<size {
    let at = size * 4 - 4 * (i + 1)
    out[i] = (bytes[at].to_int().to_uint64() << 24) |
      (bytes[at + 1].to_int().to_uint64() << 16) |
      (bytes[at + 2].to_int().to_uint64() << 8) |
      bytes[at + 3].to_int().to_uint64()
  }
  out
}

///|
/// A value in 32-bit lanes back to the integer it stands for.
fn from_limbs(a : FixedArray[UInt64]) -> BigInt {
  let bytes = FixedArray::make(a.length() * 4, b'\x00')
  for i in 0..<a.length() {
    let at = a.length() * 4 - 4 * (i + 1)
    bytes[at] = ((a[i] >> 24) & 0xFFUL).to_byte()
    bytes[at + 1] = ((a[i] >> 16) & 0xFFUL).to_byte()
    bytes[at + 2] = ((a[i] >> 8) & 0xFFUL).to_byte()
    bytes[at + 3] = (a[i] & 0xFFUL).to_byte()
  }
  BigInt::from_octets(bytes.unsafe_reinterpret_as_bytes()[:])
}

///|
/// Build the engine over `n`, which must be odd.
fn Mont::new(n : BigInt) -> Mont {
  let size = width(bit_length(n))
  let mod = limbs(n, size)
  // `n0 = -n^-1 mod 2^32`, by Newton iteration: each round doubles the correct
  // bits, five rounds from one cover the lane. Only the modulus's low limb
  // matters, and the modulus is public.
  let nlo = lo32(n)
  let mut inv = 1N
  for _ in 0..<5 {
    inv = lo32(inv * (2N - lo32(nlo * inv)))
  }
  let n0 = lo32(lane - inv).to_uint64()
  // `R = 2^32*size`; `R^2 mod n` and `R mod n` convert a plain value in and out.
  let r = 1N << (32 * size)
  {
    size,
    mod,
    n0,
    r2: limbs(r * r % n, size),
    one: limbs(r % n, size),
    t: FixedArray::make(size + 2, 0UL),
    u: FixedArray::make(size, 0UL),
    sq: FixedArray::make(2 * size + 1, 0UL),
    lo: FixedArray::make(size, 0UL),
    hi: FixedArray::make(size, 0UL),
  }
}

///|
/// `out = a * b * R^-1 mod n`, by CIOS: each limb of `b` is multiplied in and
/// one limb reduced away in the same pass, so the running sum stays `size + 2`
/// lanes. `out` may be `a` or `b`: both are read before `out` is written.
fn Mont::mul(
  self : Mont,
  out : FixedArray[UInt64],
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> Unit {
  let size = self.size
  let t = self.t
  let u = self.u
  let n = self.mod
  for i in 0..<(size + 2) {
    t[i] = 0UL
  }
  for i in 0..<size {
    let bi = b[i]
    let mut carry = 0UL
    for j in 0..<size {
      let s = t[j] + a[j] * bi + carry
      t[j] = s & 0xFFFFFFFFUL
      carry = s >> 32
    }
    let s = t[size] + carry
    t[size] = s & 0xFFFFFFFFUL
    t[size + 1] = s >> 32
    // `m` makes the low lane cancel; the sum then shifts down one lane.
    let m = (t[0] * self.n0) & 0xFFFFFFFFUL
    let mut c = (t[0] + m * n[0]) >> 32
    for j in 1..<size {
      let s = t[j] + m * n[j] + c
      t[j - 1] = s & 0xFFFFFFFFUL
      c = s >> 32
    }
    let s = t[size] + c
    t[size - 1] = s & 0xFFFFFFFFUL
    t[size] = t[size + 1] + (s >> 32)
  }
  // The sum is below `2n`. It is `n` or more exactly when the overflow lane is
  // set or subtracting `n` does not borrow; the choice is a mask, not a branch.
  let mut borrow = 0UL
  for i in 0..<size {
    let d = t[i] - n[i] - borrow
    u[i] = d & 0xFFFFFFFFUL
    borrow = d >> 63
  }
  let take = 0UL - ((t[size] | (borrow ^ 1UL)) & 1UL)
  for i in 0..<size {
    out[i] = t[i] ^ (take & (t[i] ^ u[i]))
  }
}

///|
/// `out = a^2 * R^-1 mod n`, by squaring instead of multiplying.
///
/// A product takes two multiplies for every pair of limbs; a square takes one per
/// pair, because `a[i]*a[j]` and `a[j]*a[i]` are the same number — it is twice the
/// upper triangle plus the diagonal. That is where the saving is, and it is why
/// the four squarings of a window are worth writing out rather than calling
/// [`Mont::mul`].
///
/// The square is formed at full width and then reduced in place, `n` rows of
/// `m*n` subtracted from the low lanes. The carry out of a row lands in the lane
/// above it and is walked from there to the top of the product; the walk's length
/// is set by the row's index, not by any value, so the work is the same on every
/// call. The result is below `2n` and takes the same masked subtraction `mul`
/// ends with.
fn Mont::sqr(
  self : Mont,
  out : FixedArray[UInt64],
  a : FixedArray[UInt64],
) -> Unit {
  let size = self.size
  let sq = self.sq
  for i in 0..<(2 * size + 1) {
    sq[i] = 0UL
  }
  // The upper triangle, row by row. Row `i` writes lanes `2i+1` to `i+size-1`
  // and leaves its carry in lane `i+size`, which no earlier row reaches: earlier
  // rows stop one lane short of it. So the carry is stored, never added.
  for i in 0..<size {
    let ai = a[i]
    let mut carry = 0UL
    for j in (i + 1)..<size {
      let s = sq[i + j] + ai * a[j] + carry
      sq[i + j] = s & 0xFFFFFFFFUL
      carry = s >> 32
    }
    sq[i + size] = carry
  }
  // Twice the cross terms. The product of two 32-bit limbs is below `2^64`, so
  // the doubling runs a lane at a time with one bit of carry.
  let mut carry = 0UL
  for k in 0..<(2 * size) {
    let v = (sq[k] << 1) | carry
    sq[k] = v & 0xFFFFFFFFUL
    carry = v >> 32
  }
  // Plus the diagonal, `a[i]^2` at lane `2i`, held as its low and high halves so
  // that the pass below stays over 32-bit lanes with a single carry.
  let lo = self.lo
  let hi = self.hi
  for i in 0..<size {
    let d = a[i] * a[i]
    lo[i] = d & 0xFFFFFFFFUL
    hi[i] = d >> 32
  }
  let mut carry = 0UL
  for k in 0..<(2 * size) {
    let add = if k % 2 == 0 { lo[k / 2] } else { hi[(k - 1) / 2] }
    let s = sq[k] + add + carry
    sq[k] = s & 0xFFFFFFFFUL
    carry = s >> 32
  }
  // The reduction. Lane `i` takes the multiple of the modulus that cancels it,
  // the row's carry goes into lane `i+size`, and the walk above it carries what
  // is left; the last lane yields the one bit by which the result can exceed the
  // width, since it is below `2n`.
  let n = self.mod
  for i in 0..<size {
    let m = (sq[i] * self.n0) & 0xFFFFFFFFUL
    let mut c = (sq[i] + m * n[0]) >> 32
    for j in 1..<size {
      let s = sq[i + j] + m * n[j] + c
      sq[i + j] = s & 0xFFFFFFFFUL
      c = s >> 32
    }
    let mut k = i + size
    while k <= 2 * size {
      let s = sq[k] + c
      sq[k] = s & 0xFFFFFFFFUL
      c = s >> 32
      k = k + 1
    }
  }
  let t = self.t
  let mut borrow = 0UL
  for i in 0..<size {
    let d = sq[size + i] - n[i] - borrow
    t[i] = d & 0xFFFFFFFFUL
    borrow = d >> 63
  }
  let take = 0UL - ((sq[2 * size] | (borrow ^ 1UL)) & 1UL)
  for i in 0..<size {
    let v = sq[size + i]
    out[i] = v ^ (take & (v ^ t[i]))
  }
}

///|
/// A copy of `a`.
fn copied(a : FixedArray[UInt64]) -> FixedArray[UInt64] {
  let out = FixedArray::make(a.length(), 0UL)
  for i in 0..<a.length() {
    out[i] = a[i]
  }
  out
}

///|
/// `base^exp mod n`, in the engine's form, for a secret exponent.
///
/// A fixed four-bit window: every window squares four times and multiplies once
/// by a table entry, and the entry is read by scanning all sixteen under masks,
/// so neither the work nor the memory touched follows the exponent's bits. The
/// windows cover the full width of the modulus; leading zeros in the exponent
/// are harmless, and the width is public.
fn Mont::pow(
  self : Mont,
  base : FixedArray[UInt64],
  exp : BigInt,
) -> FixedArray[UInt64] {
  let size = self.size
  let table = FixedArray::make(16 * size, 0UL)
  let entry = copied(base)
  for i in 0..<size {
    table[i] = self.one[i]
    table[size + i] = base[i]
  }
  for k in 2..<16 {
    self.mul(entry, entry, base)
    for i in 0..<size {
      table[k * size + i] = entry[i]
    }
  }
  let e = limbs(exp, size)
  let r = copied(self.one)
  let mut w = 8 * size - 1
  while w >= 0 {
    for _ in 0..<4 {
      self.sqr(r, r)
    }
    let nibble = (e[w / 8] >> (4 * (w % 8))) & 0xFUL
    for i in 0..<size {
      entry[i] = 0UL
    }
    for k in 0..<16 {
      // All ones when `k` is the nibble: `x - 1` borrows into the top bit only
      // for `x == 0`.
      let mask = 0UL - (((k.to_uint64() ^ nibble) - 1UL) >> 63)
      for i in 0..<size {
        entry[i] = entry[i] | (table[k * size + i] & mask)
      }
    }
    self.mul(r, r, entry)
    w = w - 1
  }
  r
}

///|
/// `base^e mod n` for a public exponent: square-and-multiply from the
/// exponent's top bit, branching on its bits, which leak nothing. The blinder's
/// `r^e` takes this route, at seventeen bits for `e = 65537`.
fn Mont::pow_public(
  self : Mont,
  base : FixedArray[UInt64],
  exp : BigInt,
) -> FixedArray[UInt64] {
  let bits = bit_length(exp)
  let e = limbs(exp, width(bits))
  let r = copied(self.one)
  let mut i = bits - 1
  while i >= 0 {
    self.sqr(r, r)
    if ((e[i / 32] >> (i % 32)) & 1UL) == 1UL {
      self.mul(r, r, base)
    }
    i = i - 1
  }
  r
}

///|
/// A plain integer below the modulus into the engine's form.
fn Mont::from(self : Mont, v : BigInt) -> FixedArray[UInt64] {
  let out = limbs(v, self.size)
  self.mul(out, out, self.r2)
  out
}

///|
/// A value in the engine's form back to the plain integer it stands for.
fn Mont::to(self : Mont, a : FixedArray[UInt64]) -> BigInt {
  let unit = FixedArray::make(self.size, 0UL)
  unit[0] = 1UL
  let out = FixedArray::make(self.size, 0UL)
  self.mul(out, a, unit)
  from_limbs(out)
}

///|
/// The Chinese-remainder half of a private key: the two primes, the exponents
/// reduced against the factors' own group orders, and `q^-1 mod p` to
/// recombine. Each half runs over the full width of its own prime, so both are
/// fixed width. The Montgomery engines are built from these on the fly; only the
/// key material is carried, so nothing secret is held between operations.
priv struct Crt {
  p_big : BigInt
  q_big : BigInt
  d_p : BigInt
  d_q : BigInt
  q_inv : BigInt
}

///|
/// Build the CRT half from two primes the caller handed in: `d_p` and `d_q` are
/// `d` reduced against the factors' own group orders, so each half exponentiates
/// to a width half the modulus. `e * d_p ≡ 1 (mod p-1)`, and likewise for `q`,
/// holds for a genuine factor pair; a pair that fails it is `Weak`, refused here
/// rather than at a signature.
fn Crt::new(
  p : BigInt,
  q : BigInt,
  d : BigInt,
  e : BigInt,
) -> Crt raise @spec.Broken {
  let crt = Crt::fitted(p, q, d)
  guard e * crt.d_p % (p - 1N) == 1N && e * crt.d_q % (q - 1N) == 1N else {
    raise @spec.Weak
  }
  crt
}

///|
/// The CRT half of factors already known to fit `d`, as a key just generated
/// from them does. `q_inv` is `q^-1 mod p`.
fn Crt::fitted(p : BigInt, q : BigInt, d : BigInt) -> Crt {
  {
    p_big: p,
    q_big: q,
    d_p: d % (p - 1N),
    d_q: d % (q - 1N),
    q_inv: modinv(q, p),
  }
}

///|
/// The CRT private exponentiation of a value already below the modulus: the two
/// fixed-width halves, recombined with `q_inv`. Returns the value below `n`.
fn Crt::dp(self : Crt, c : BigInt) -> BigInt {
  let mp = pow_mod(c % self.p_big, self.d_p, self.p_big)
  let mq = pow_mod(c % self.q_big, self.d_q, self.q_big)
  let h = ((mp - mq) % self.p_big + self.p_big) % self.p_big
  let hb = h * self.q_inv % self.p_big
  (mq + hb * self.q_big) % (self.p_big * self.q_big)
}

///|
/// `base^exp mod modulus` in fixed width, for a secret exponent and a base below
/// the modulus.
fn pow_mod(base : BigInt, exp : BigInt, modulus : BigInt) -> BigInt {
  let m = Mont::new(modulus)
  m.to(m.pow(m.from(base), exp))
}

///|
/// `base^exp mod modulus` for a public exponent and a base below the modulus.
fn pow_public_mod(base : BigInt, exp : BigInt, modulus : BigInt) -> BigInt {
  let m = Mont::new(modulus)
  m.to(m.pow_public(m.from(base), exp))
}
