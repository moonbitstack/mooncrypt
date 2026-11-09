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
/// How many 32-bit limbs a value occupies, from its own length.
fn width_of(v : BigInt) -> Int32 {
  let mut bits = 0
  let mut rest = v
  while rest > 0N {
    bits += 1
    rest = rest >> 1
  }
  width(bits)
}

///|
/// A Montgomery engine over one modulus: the modulus in 32-bit limbs (least
/// significant first), the reduction constant `n0`, and the value one already
/// in the engine's form. Built once per key and reused by every private
/// operation under it.
priv struct Mont {
  size : Int32
  mod : Array[UInt64]
  n0 : UInt64
  r2 : Array[UInt64]
  one : Array[UInt64]
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
fn limbs(v : BigInt, size : Int32) -> Array[UInt64] {
  let bytes = v.to_octets(length=size * 4)
  let out = Array::make(size, 0UL)
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
fn from_limbs(a : Array[UInt64]) -> BigInt {
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
/// Build the engine over `n`, which must be odd and at least 512 bits.
fn Mont::new(n : BigInt) -> Mont {
  let size = width_of(n)
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
  let r2 = limbs(r * r % n, size)
  let one = limbs(r % n, size)
  { size, mod, n0, r2, one, }
}

///|
/// `a * b * R^-1 mod n`. `t` is scratch, `2*size + 2` lanes wide, reused by the
/// caller so an exponentiation allocates it once.
fn Mont::mul(
  self : Mont,
  a : Array[UInt64],
  b : Array[UInt64],
  t : Array[UInt64],
) -> Array[UInt64] {
  let size = self.size
  for i in 0..<(2 * size + 2) {
    t[i] = 0UL
  }
  // The wide product `t = a * b`, in the low `2*size + 1` lanes.
  for i in 0..<size {
    let ai = a[i]
    let mut carry = 0UL
    for j in 0..<size {
      let uv = t[i + j] + ai * b[j] + carry
      t[i + j] = uv & 0xFFFFFFFFUL
      carry = uv >> 32
    }
    let s = t[i + size] + carry
    t[i + size] = s & 0xFFFFFFFFUL
    t[i + size + 1] = t[i + size + 1] + (s >> 32)
  }
  // CIOS reduction: for each limb, `m = t[i] * n0`, add `m * n` shifted, and
  // the lane cancels to zero while the overflow drains upward.
  for i in 0..<size {
    let m = (t[i] * self.n0) & 0xFFFFFFFFUL
    let mut carry = 0UL
    for j in 0..<size {
      let uv = t[i + j] + m * self.mod[j] + carry
      t[i + j] = uv & 0xFFFFFFFFUL
      carry = uv >> 32
    }
    let s = t[i + size] + carry
    t[i + size] = s & 0xFFFFFFFFUL
    t[i + size + 1] = t[i + size + 1] + (s >> 32)
  }
  // The answer is the upper half; if it is still `n` or more, subtract it back.
  let out = Array::make(size, 0UL)
  let mut borrow = 0UL
  for i in 0..<size {
    let d = t[size + i] - self.mod[i] - borrow
    out[i] = d & 0xFFFFFFFFUL
    borrow = d >> 63
  }
  // The overflow lane or a borrow says the answer did not wrap: the choice is
  // a mask, not a branch.
  let keep = 0UL - (borrow ^ t[2 * size])
  let mut carry = 0UL
  for i in 0..<size {
    let s = out[i] + (self.mod[i] & keep) + carry
    out[i] = s & 0xFFFFFFFFUL
    carry = s >> 32
  }
  out
}

///|
/// `a` times itself.
fn Mont::square(
  self : Mont,
  a : Array[UInt64],
  t : Array[UInt64],
) -> Array[UInt64] {
  self.mul(a, a, t)
}

///|
/// `a` where `mask` is all ones, `b` where it is zero: the branch-free select.
fn select(mask : UInt64, a : Array[UInt64], b : Array[UInt64]) -> Array[UInt64] {
  let out = Array::make(a.length(), 0UL)
  for i in 0..<a.length() {
    out[i] = b[i] ^ (mask & (a[i] ^ b[i]))
  }
  out
}

///|
/// `base^exp mod n`, in the engine's form.
///
/// The exponent is secret, so the loop does not branch on its bits: every one
/// squares, and the multiply is done for every bit and then selected in — the
/// masked square-and-multiply a constant-time exponentiation needs. The loop
/// runs over the full width of the modulus; leading zeros in the exponent are
/// harmless, and the width is public.
fn Mont::pow(self : Mont, base : Array[UInt64], exp : BigInt) -> Array[UInt64] {
  let t = Array::make(2 * self.size + 2, 0UL)
  let e = limbs(exp, self.size)
  let mut r = self.one
  let mut i = 32 * self.size - 1
  while i >= 0 {
    r = self.square(r, t)
    let bit = (e[i / 32] >> (i % 32)) & 1UL
    let mask = 0UL - bit
    let rr = self.mul(r, base, t)
    r = select(mask, rr, r)
    i = i - 1
  }
  r
}

///|
/// `base^e mod n` for a public exponent: the branch-on-bit square-and-multiply
/// the public-key paths (and the blinder's `r^e`) can use, because the bits of a
/// public exponent leak nothing.
fn Mont::pow_public(
  self : Mont,
  base : Array[UInt64],
  exp : BigInt,
) -> Array[UInt64] {
  let t = Array::make(2 * self.size + 2, 0UL)
  let e = limbs(exp, self.size)
  let mut r = self.one
  let mut i = 32 * self.size - 1
  while i >= 0 {
    r = self.square(r, t)
    if ((e[i / 32] >> (i % 32)) & 1UL) == 1UL {
      r = self.mul(r, base, t)
    }
    i = i - 1
  }
  r
}

///|
/// A plain integer into the engine's form.
fn Mont::from(self : Mont, v : BigInt, t : Array[UInt64]) -> Array[UInt64] {
  self.mul(limbs(v, self.size), self.r2, t)
}

///|
/// A value in the engine's form back to the plain integer it stands for.
fn Mont::to(self : Mont, a : Array[UInt64], t : Array[UInt64]) -> BigInt {
  from_limbs(self.mul(a, limbs(1N, self.size), t))
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
/// `base^exp mod modulus` in fixed width: build the engine over the modulus and
/// run the masked exponentiation. The engine is a few limbs and one Newton
/// loop, cheap against the exponentiation it serves.
fn pow_mod(base : BigInt, exp : BigInt, modulus : BigInt) -> BigInt {
  let m = Mont::new(modulus)
  let t = Array::make(2 * m.size + 2, 0UL)
  m.to(m.pow(m.from(base, t), exp), t)
}
