// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// `base^exp mod modulus` for a public exponent and a base below the modulus,
/// through the fixed-width engine.
///
/// Compiled where a 64-bit word is a hardware word: the engine's lanes are
/// 32-bit limbs carried in one. This is where the whole library's public
/// operation runs on `native`, `wasm` and `wasm-gc`, and it is the only route
/// there — the engine's Montgomery multiplication and its fixed four-bit window
/// are what a squaring costs, which is less than core's general multiplication
/// of the same width.
///
/// The `js` backend has no 64-bit word: every lane becomes a heap object and the
/// same exponentiation runs about thirty times slower than core's. That target
/// takes the other file. The two agree, and neither touches a secret — a public
/// exponent is public by definition, which is why this one may branch on its
/// bits where the private path in `ct.mbt` may not.

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
fn pow_public_mod(base : BigInt, exp : BigInt, modulus : BigInt) -> BigInt {
  let m = Mont::new(modulus)
  m.to(m.pow_public(m.from(base), exp))
}
