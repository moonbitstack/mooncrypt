// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The first primes, for trial division before Miller-Rabin. A composite that a
/// small prime divides costs a division to reject instead of an exponentiation,
/// and most candidates fall here.
let small_primes : FixedArray[Int32] = [
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
  83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
  173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
  263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
  359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
  457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
]

///|
/// `a^{-1} mod m` by the extended Euclidean algorithm. `m` need not be prime,
/// which is what rules out the Fermat inverse — RSA's `phi` is even and so never
/// prime.
fn modinv(a : BigInt, m : BigInt) -> BigInt {
  let mut old_r = a
  let mut r = m
  let mut old_s = (1 : BigInt)
  let mut s = (0 : BigInt)
  while r != (0 : BigInt) {
    let q = old_r / r
    let nr = old_r - q * r
    old_r = r
    r = nr
    let ns = old_s - q * s
    old_s = s
    s = ns
  }
  if old_r != (1 : BigInt) {
    abort(
      "rsa: the exponent is not invertible modulo phi, which means a bad prime",
    )
  }
  let d = old_s % m
  if d < (0 : BigInt) {
    d + m
  } else {
    d
  }
}

///|
/// The Miller-Rabin test (FIPS 186-5 B.3.1), with the bases drawn uniformly from
/// the source. Forty rounds make the error below 4^-40, and the small-prime pass
/// rejects the common composites before the first exponentiation.
fn[S : @moonseed.Source] is_probable_prime(
  n : BigInt,
  source : S,
) -> Bool raise @moonseed.Unavailable {
  for p in small_primes {
    let bp = BigInt::from_int(p)
    if n % bp == (0 : BigInt) {
      return n == bp
    }
  }
  let n1 = n - (1 : BigInt)
  let mut d = n1
  let mut s = 0
  while d % (2 : BigInt) == (0 : BigInt) {
    d = d >> 1
    s = s + 1
  }
  // A base in [2, n - 2]: `below` draws [0, n - 3), so adding two shifts up.
  let span = n - (3 : BigInt)
  for _ in 0..<40 {
    let a = BigInt::from_octets(@moonseed.below(span.to_octets()[:], source)) +
      (2 : BigInt)
    let mut x = a.pow(d, modulus=n)
    let mut pass = x == (1 : BigInt) || x == n1
    if !pass {
      for _ in 1..<s {
        x = x * x % n
        if x == n1 {
          pass = true
          break
        }
      }
    }
    if !pass {
      return false
    }
  }
  true
}

///|
/// A random prime of exactly `bits` bits: the two top bits are set so the
/// product of two such primes keeps the modulus width, and the low bit so the
/// candidate is odd (FIPS 186-5 A.1.3).
fn[S : @moonseed.Source] random_prime(
  bits : Int32,
  source : S,
) -> BigInt raise @moonseed.Unavailable {
  let nbytes = (bits + 7) / 8
  let excess = nbytes * 8 - bits
  while true {
    let buf = FixedArray::make(nbytes, b'\x00')
    source.fill(buf)
    buf[0] = (buf[0].to_int() | 0xC0).to_byte()
    if excess > 0 {
      buf[0] = (buf[0].to_int() & (0xFF >> excess)).to_byte()
    }
    buf[nbytes - 1] = (buf[nbytes - 1].to_int() | 1).to_byte()
    let candidate = BigInt::from_octets(buf.unsafe_reinterpret_as_bytes()[:])
    if is_probable_prime(candidate, source) {
      return candidate
    }
  }
  abort("rsa: unreachable")
}

///|
/// Generate a fresh RSA signing key (FIPS 186-5 A.1.1): two random primes `p` and
/// `q`, the modulus `n = p·q`, the public exponent 65537, and the private
/// exponent `d = e^{-1} mod phi(n)`.
///
/// The primes are drawn from `source`, so a seeded [`@moonseed.Source`] makes the
/// key reproducible and the platform's entropy makes it secret. `bits` is the
/// modulus width, at least 512 and a multiple of 8; 2048 is the default every
/// certificate and TLS stack accepts.
pub fn[S : @moonseed.Source] PrivateKey::generate(
  source : S,
  bits~ : Int32 = 2048,
  digest~ : Digest = Sha256,
  scheme~ : Scheme = Pkcs1,
) -> PrivateKey raise @moonseed.Unavailable {
  guard bits >= 512 && bits % 8 == 0 else {
    abort("rsa: a modulus of \{bits} bits is not a multiple of 8 at least 512")
  }
  let e = BigInt::from_int(65537)
  while true {
    let p = random_prime(bits / 2, source)
    let q = random_prime(bits / 2, source)
    if p == q {
      continue
    }
    let n = p * q
    if octets(n) != bits / 8 {
      continue
    }
    let phi = (p - 1) * (q - 1)
    // 65537 is prime, so it divides `phi` only when it divides a factor.
    if phi % e == (0 : BigInt) {
      continue
    }
    let d = modinv(e, phi)
    return { n, e, d, size: octets(n), digest, scheme, }
  }
  abort("rsa: unreachable")
}
