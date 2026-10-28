// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The length of a scalar, a u-coordinate and a shared secret, in bytes. All
/// three are 56; X448 has no other size.
pub let size : Int32 = 56

///|
/// The field prime, `2^448 - 2^224 - 1` (RFC 7748 §4.2).
let prime : BigInt = (1N << 448) - (1N << 224) - 1N

///|
/// The ladder constant `(A - 2) / 4`, which is 39081 for Curve448.
let a24 : BigInt = 39081N

///|
/// The base point, `u = 5`, little-endian (RFC 7748 §4.2).
pub let base : Bytes = {
  let out = Array::make(size, b'\x00')
  out[0] = b'\x05'
  Bytes::from_array(out)
}

///|
/// Little-endian bytes as a field integer.
fn decode(b : FixedArray[Int32]) -> BigInt {
  let mut acc = 0N
  for i = b.length() - 1; i >= 0; i = i - 1 {
    acc = acc * 256N + BigInt::from_int(b[i])
  }
  acc
}

///|
/// A field integer as 56 little-endian bytes.
fn encode(v : BigInt) -> Bytes {
  let out = Array::make(size, b'\x00')
  let mut acc = v % prime
  for i in 0..<size {
    out[i] = (acc % 256N).to_int().to_byte()
    acc = acc / 256N
  }
  Bytes::from_array(out)
}

///|
/// The Montgomery ladder (RFC 7748 §5) over the 448-bit field.
///
/// The structure is identical to Curve25519's ladder and only the constants and
/// the bit count differ: 447 down to 0 rather than 254 down to 0, because the
/// scalar is 56 bytes rather than 32.
fn ladder(scalar : FixedArray[Int32], u : BigInt) -> BigInt {
  let p = prime
  let x1 = u
  let mut x2 = 1N
  let mut z2 = 0N
  let mut x3 = x1
  let mut z3 = 1N
  let mut swap = 0
  for t = 447; t >= 0; t = t - 1 {
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
/// Apply a scalar to a u-coordinate, which is the whole of X448 (RFC 7748 §5).
///
/// Both inputs and the answer are 56 little-endian bytes. The scalar is clamped
/// — and, unlike X25519, nothing is masked off the u-coordinate, because 56
/// bytes is exactly the width of the field.
///
/// An all-zero shared secret is refused, as in [`@x25519`]: it is what a
/// low-order point produces, and it means the peer chose the answer rather than
/// contributing to it.
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
  let k = FixedArray::make(size, 0)
  for i in 0..<size {
    k[i] = scalar[i].to_int()
  }
  // RFC 7748 §5: clear the low two bits to kill the cofactor, and set the top
  // bit so every scalar has the same width.
  k[0] = k[0] & 252
  k[55] = k[55] | 128
  let u = FixedArray::make(size, 0)
  for i in 0..<size {
    u[i] = point[i].to_int()
  }
  let out = encode(ladder(k, decode(u) % prime))
  let mut any = 0
  for i in 0..<size {
    any = any | out[i].to_int()
  }
  for i in 0..<size {
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
