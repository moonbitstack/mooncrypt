// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// `base^exp mod modulus` for a public exponent and a base below the modulus,
/// through core's big-integer power.
///
/// This file is compiled for `js` only. The engine the other backends use
/// carries a 32-bit limb in a 64-bit lane, and JavaScript has no 64-bit word to
/// carry it in: every lane becomes a heap object and the same exponentiation
/// runs about thirty times slower than core's. Both give the same number, and
/// neither touches a secret — the exponent is public by definition.
fn pow_public_mod(base : BigInt, exp : BigInt, modulus : BigInt) -> BigInt {
  base.pow(exp, modulus~)
}
