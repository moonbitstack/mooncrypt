// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The limb field has to agree with the `BigInt` arithmetic the rest of the
// package already uses, so these tests hold the two side by side: field
// operations against `BigInt` ones, and `mul` against repeated `add`.

///|
fn to_big(a : Fp, k : Int32) -> BigInt {
  BigInt::from_octets(limbs_to_be(a, k)[:])
}

///|
fn all_curves() -> Array[Curve] {
  [
    @curve.P256,
    @curve.P384,
    @curve.P521,
    @curve.Secp256k1,
    @curve.BrainpoolP256r1,
    @curve.BrainpoolP384r1,
    @curve.BrainpoolP512r1,
  ]
}

///|
test "the field's constants match R, R^2 and the Montgomery identity" {
  for c in all_curves() {
    let f = field_of(c)
    let p = params(c).p
    let r = (1 : BigInt) << (32 * f.k)
    assert_eq(to_big(f.one, f.k), r % p)
    assert_eq(to_big(f.r2, f.k), r * r % p)
    // n0 is the negative inverse of the low limb, which is what the reduction
    // multiplies by.
    assert_eq((f.p[0] * f.n0) & 0xFFFFFFFFUL, 0xFFFFFFFFUL)
  }
}

///|
test "a byte string survives the limb round trip" {
  for c in all_curves() {
    let f = field_of(c)
    for v in [(0 : BigInt), (1 : BigInt), (255 : BigInt), (65537 : BigInt)] {
      let bytes = (v : BigInt).to_octets(length=f.k * 4)
      assert_eq(to_big(limbs_from_be(bytes[:], f.k), f.k), (v : BigInt))
    }
  }
}

///|
test "field arithmetic agrees with BigInt arithmetic" {
  for c in all_curves() {
    let f = field_of(c)
    let p = params(c).p
    // Values near both ends of the range, so the reduction is exercised where
    // it has to borrow and where it does not.
    let values : Array[BigInt] = [
      0,
      1,
      2,
      3,
      5,
      7,
      p - (1 : BigInt),
      p - (2 : BigInt),
      p - (3 : BigInt),
      p / (2 : BigInt),
      (1 : BigInt) << 128,
    ]
    let limbs = values.map(fn(v) { ffrom(v, f) })
    for i in 0..<values.length() {
      for j in 0..<values.length() {
        let a = values[i]
        let b = values[j]
        assert_eq(fto(fmul(limbs[i], limbs[j], f), f), mod_p(c, a * b))
        assert_eq(fto(fadd(limbs[i], limbs[j], f), f), mod_p(c, a + b))
        assert_eq(fto(fsub(limbs[i], limbs[j], f), f), mod_p(c, a - b))
      }
    }
    for v in values {
      // The symmetric square has to agree with the general product it
      // replaces, so it is checked against `BigInt` on the same values.
      assert_eq(fto(fsqr(ffrom(v, f), f), f), mod_p(c, v * v))
      if v != (0 : BigInt) {
        let back = fto(finv(ffrom(v, f), f), f)
        assert_eq(back * v % p, (1 : BigInt))
      }
    }
  }
}

///|
test "mul agrees with repeated addition on every curve" {
  for c in all_curves() {
    let g = generator(c)
    let mut acc = g
    // 1P through 12P, plus the two ends of the scalar range.
    let mut scalar = (1 : BigInt)
    for _ in 2..<13 {
      acc = add(c, acc, g)
      scalar = scalar + (1 : BigInt)
      let got = mul(c, scalar, g)
      assert_eq(got.x, acc.x)
      assert_eq(got.y, acc.y)
    }
    let n = params(c).n
    let one = mul(c, (1 : BigInt), g)
    assert_eq(one.x, g.x)
    assert_eq(one.y, g.y)
    let top = mul(c, n - (1 : BigInt), g)
    assert_eq(top.x, g.x)
    assert_eq(top.y, mod_p(c, -g.y))
  }
}

///|
test "the two-scalar product is the sum of the two products" {
  for c in all_curves() {
    let g = generator(c)
    let n = params(c).n
    let h = mul(c, (7 : BigInt), g)
    let pairs : Array[(BigInt, BigInt)] = [
      (0, 1),
      (1, 0),
      (1, 1),
      (5, 9),
      (n - (1 : BigInt), 3),
      (65537, n - (2 : BigInt)),
    ]
    for pair in pairs {
      let (a, b) = pair
      let want = add(c, mul(c, a, g), mul(c, b, h))
      let got = mul2(c, a, g, b, h)
      assert_eq(got.zero, want.zero)
      if !want.zero {
        assert_eq(got.x, want.x)
        assert_eq(got.y, want.y)
      }
    }
  }
}

///|
test "zero and the point at infinity come out right" {
  for c in all_curves() {
    let g = generator(c)
    let zero = mul(c, (0 : BigInt), g)
    assert_true(zero.zero)
    let n = params(c).n
    assert_true(mul(c, n, g).zero)
    // Doubling and adding the same point still produce a real point, which is
    // where a Jacobian formula that forgot its own exception case would break.
    let two = double(c, g)
    let sum = add(c, g, g)
    assert_eq(sum.x, two.x)
    assert_eq(sum.y, two.y)
    let cancelled = add(c, g, { x: g.x, y: mod_p(c, -g.y), zero: false, })
    assert_true(cancelled.zero)
    assert_true(double(c, { x: 0, y: 0, zero: true, }).zero)
    let inf = { x: 0, y: 0, zero: true, }
    let back = add(c, inf, g)
    assert_eq(back.x, g.x)
    assert_eq(back.y, g.y)
  }
}
