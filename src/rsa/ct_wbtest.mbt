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

///|
/// A small key, so the blind can be held still cheaply: `2^32 - 5` and
/// `2^32 - 11` are primes, and the exponents follow from them.
fn blind_key() -> PrivateKey raise {
  let p = 4294967291N
  let q = 4294967279N
  let n = p * q
  let e = 65537N
  let d = modinv(e, (p - 1N) * (q - 1N))
  PrivateKey::new(n.to_octets(), e.to_octets(), d.to_octets())
}

///|
/// What the blinder exists for, read off the seam rather than the clock: hold
/// the random still and the value the secret exponentiation is handed is
/// `value * r^e mod n`, which is not the value. Without the blind that value is
/// the caller's own, and its running time follows its Hamming weight.
test "the blinder hands the exponentiation a blinded value, not the value" {
  let key = blind_key()
  let n = key.n
  let d = key.d
  for value in [1N, 1234567N, (1N << 31) + 12345N, n - 1N] {
    let r = 987654321N
    let handed = blinder_apply(key, value, r)
    assert_true(handed != value)
    assert_eq(handed, value * pow_public_mod(r, key.e, n) % n)
    // Two randoms, one answer: the blind divides out exactly.
    let a = blind_with(key, value, r.to_octets()[:])
    let b = blind_with(key, value, (r + 1N).to_octets()[:])
    assert_eq(a, b)
    assert_eq(a, value.pow(d, modulus=n))
  }
}

///|
/// A host with no entropy draws nothing, and the operation still answers: the
/// same fixed-width exponentiation, on the value itself.
test "an empty draw falls back to the value, and still gets the answer" {
  let key = blind_key()
  assert_eq(blind_with(key, 12345N, b""[:]), 12345N.pow(key.d, modulus=key.n))
}
