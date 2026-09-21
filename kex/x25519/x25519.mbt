// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The length of a scalar, a u-coordinate and a shared secret, in bytes. All
/// three are 32; X25519 has no other size.
pub let size : Int = 32

///|
/// The field prime, `2^255 - 19` (RFC 7748 §4.1).
let prime : BigInt = (1N << 255) - 19N

///|
/// The ladder constant `(A - 2) / 4`, which is 121665 for Curve25519.
let a24 : BigInt = 121665N

///|
/// The base point, `u = 9`, little-endian (RFC 7748 §4.1).
pub let base : Bytes = {
  let out = Array::make(32, b'\x00')
  out[0] = b'\x09'
  Bytes::from_array(out)
}

///|
/// Little-endian bytes as a field integer.
fn decode(b : FixedArray[Int]) -> BigInt {
  let mut acc = 0N
  for i = b.length() - 1; i >= 0; i = i - 1 {
    acc = acc * 256N + BigInt::from_int(b[i])
  }
  acc
}

///|
/// A field integer as 32 little-endian bytes.
fn encode(v : BigInt) -> Bytes {
  let out = Array::make(32, b'\x00')
  let mut acc = v % prime
  for i in 0..<32 {
    out[i] = (acc % 256N).to_int().to_byte()
    acc = acc / 256N
  }
  Bytes::from_array(out)
}

///|
/// The Montgomery ladder (RFC 7748 §5).
///
/// Subtractions add the prime first rather than assume a Euclidean remainder,
/// and the conditional swap is driven by the scalar's clamped bits, so no
/// bignum bit operations are needed.
fn ladder(scalar : FixedArray[Int], u : BigInt) -> BigInt {
  let p = prime
  let x1 = u
  let mut x2 = 1N
  let mut z2 = 0N
  let mut x3 = x1
  let mut z3 = 1N
  let mut swap = 0
  for t = 254; t >= 0; t = t - 1 {
    let bit = (scalar[t / 8] >> (t % 8)) & 1
    swap = swap ^ bit
    if swap == 1 {
      let tx = x2
      x2 = x3
      x3 = tx
      let tz = z2
      z2 = z3
      z3 = tz
    }
    swap = bit
    let a = (x2 + z2) % p
    let aa = a * a % p
    let b = (x2 + p - z2) % p
    let bb = b * b % p
    let e = (aa + p - bb) % p
    let c = (x3 + z3) % p
    let d = (x3 + p - z3) % p
    let da = d * a % p
    let cb = c * b % p
    let sum = (da + cb) % p
    x3 = sum * sum % p
    let diff = (da + p - cb) % p
    z3 = x1 * (diff * diff % p) % p
    x2 = aa * bb % p
    z2 = e * ((aa + a24 * e) % p) % p
  }
  if swap == 1 {
    let tx = x2
    x2 = x3
    x3 = tx
    let tz = z2
    z2 = z3
    z3 = tz
  }
  // x2 / z2 is x2 * z2^(p-2) by Fermat's little theorem.
  x2 * BigInt::pow(z2, p - 2N, modulus=p) % p
}

///|
/// Apply a scalar to a u-coordinate, which is the whole of X25519 (RFC 7748 §5).
///
/// Both inputs and the answer are 32 little-endian bytes. The scalar is clamped
/// and the u-coordinate's high bit is masked, as §5 requires: a caller may hand
/// in whatever 32 bytes it has, and the ones that are not part of the value are
/// ignored rather than rejected, because that is what makes a random 32 bytes a
/// valid private key.
///
/// An all-zero shared secret is refused. It is what a low-order point produces,
/// and it means the peer chose the answer rather than contributing to it — the
/// check is a MAY in RFC 7748 §6.1 and a MUST in TLS 1.3 (RFC 8446 §7.4.2), and
/// every implementation in use makes it. There is no knob to turn it off: no
/// protocol served here wants the unchecked primitive, and offering it would only
/// make the dangerous call the short one.
pub fn shared(
  scalar : BytesView,
  point : BytesView,
) -> Bytes raise @spec.Broken {
  guard scalar.length() == size else {
    raise @spec.Size(want=size, got=scalar.length())
  }
  guard point.length() == size else {
    raise @spec.Size(want=size, got=point.length())
  }
  let k = FixedArray::make(32, 0)
  for i in 0..<32 {
    k[i] = scalar[i].to_int()
  }
  k[0] = k[0] & 248
  k[31] = k[31] & 127
  k[31] = k[31] | 64
  let u = FixedArray::make(32, 0)
  for i in 0..<32 {
    u[i] = point[i].to_int()
  }
  u[31] = u[31] & 127
  let out = encode(ladder(k, decode(u) % prime))
  let mut any = 0
  for i in 0..<32 {
    any = any | out[i].to_int()
  }
  for i in 0..<32 {
    k[i] = 0
  }
  guard any != 0 else { raise @spec.Weak }
  out
}

///|
/// The public key for a private one: the scalar applied to the base point.
pub fn public(scalar : BytesView) -> Bytes raise @spec.Broken {
  shared(scalar, base[:])
}
