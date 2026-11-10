///|
/// Odd moduli of one, two and many limbs, the last two a 1024-bit prime pair's
/// width and a 2048-bit modulus's, each with the bases at its edges.
fn moduli() -> Array[BigInt] {
  [
    0xFFFFFFFBN,
    0x1_0000_0001N,
    0xC5D3_1A7F_92B4_E601_7D3C_1155_8A2F_0B6DN,
    (1N << 1023) + 1155N,
    (1N << 2047) - (1N << 1100) + 0xABCDEFN,
  ]
}

///|
fn bases(n : BigInt) -> Array[BigInt] {
  [0N, 1N, 2N, n - 1N, n / 3N, (n >> 7) + 12345N]
}

///|
test "the fixed-width power agrees with BigInt's, on every width" {
  for n in moduli() {
    let exps = [0N, 1N, 2N, 15N, 16N, 0x10001N, n - 2N, n >> 3]
    for b in bases(n) {
      for e in exps {
        assert_eq(pow_mod(b, e, n), b.pow(e, modulus=n))
      }
    }
  }
}

///|
test "the public route agrees with BigInt's, from the exponent's top bit" {
  for n in moduli() {
    for b in bases(n) {
      for e in [1N, 3N, 0x10001N, (1N << 40) + 7N] {
        assert_eq(pow_public_mod(b, e, n), b.pow(e, modulus=n))
      }
    }
  }
}

///|
/// A product that lands on `n` or above before the final subtraction, and one
/// that lands below: both sides of the mask.
test "the final subtraction is taken exactly when the sum reaches the modulus" {
  let n = 0xFFFFFFFBN
  let m = Mont::new(n)
  for (a, b) in [(n - 1N, n - 1N), (n - 1N, 1N), (2N, 3N), (n - 2N, n - 3N)] {
    let out = FixedArray::make(m.size, 0UL)
    m.mul(out, m.from(a), m.from(b))
    assert_eq(m.to(out), a * b % n)
  }
}

///|
/// The square has to agree with the product and with `BigInt` at every width the
/// engine runs at, and at the values where the carry chains inside it are
/// longest: all ones, a single high limb, and one below the modulus.
test "the square agrees with the product and with BigInt's, at every width" {
  for n in moduli() {
    let m = Mont::new(n)
    let ones = (1N << (32 * m.size)) - 1N
    let edges : Array[BigInt] = [
      n >> 1,
      ones % n,
      (ones - 1N) % n,
      0xFFFF_FFFFN % n,
      (1N << 32) % n,
    ]
    for b in bases(n) {
      check_square(m, n, b)
    }
    for b in edges {
      check_square(m, n, b)
    }
  }
}

///|
fn check_square(m : Mont, n : BigInt, b : BigInt) -> Unit raise {
  let want = b * b % n
  let squared = FixedArray::make(m.size, 0UL)
  let product = FixedArray::make(m.size, 0UL)
  let in_form = m.from(b)
  m.sqr(squared, in_form)
  m.mul(product, in_form, in_form)
  assert_eq(m.to(product), want)
  assert_eq(m.to(squared), want)
}
