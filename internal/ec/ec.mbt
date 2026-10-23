// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
using @curve {type Curve}

///|
pub(all) struct Params {
  p : BigInt
  a : BigInt
  b : BigInt
  n : BigInt
  gx : BigInt
  gy : BigInt
}

///|
pub(all) struct Point {
  x : BigInt
  y : BigInt
  zero : Bool
}

///|
pub fn big(s : String) -> BigInt {
  BigInt::from_string(s, radix=16)
}

///|
/// FIPS 186-4 §D.1.2 for the three NIST primes, SEC 2 §2.4.1 for secp256k1.
/// `a = p - 3` for all three NIST curves; secp256k1 is `y² = x³ + 7`.
let p256 : Params = {
  p: big("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
  a: big("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
  b: big("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
  n: big("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
  gx: big("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
  gy: big("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
}

///|
let p384 : Params = {
  p: big(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
  ),
  a: big(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
  ),
  b: big(
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
  ),
  n: big(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
  ),
  gx: big(
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
  ),
  gy: big(
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
  ),
}

///|
let p521 : Params = {
  p: big(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
  ),
  a: big(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
  ),
  b: big(
    "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
  ),
  n: big(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
  ),
  gx: big(
    "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
  ),
  gy: big(
    "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
  ),
}

///|
let secp256k1 : Params = {
  p: big("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
  a: 0,
  b: 7,
  n: big("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
  gx: big("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
  gy: big("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
}

///|
pub fn params(c : Curve) -> Params {
  match c {
    P256 => p256
    P384 => p384
    P521 => p521
    Secp256k1 => secp256k1
  }
}

///|
pub fn generator(c : Curve) -> Point {
  let q = params(c)
  { x: q.gx, y: q.gy, zero: false, }
}

///|
pub fn mod_p(c : Curve, a : BigInt) -> BigInt {
  let p = params(c).p
  let m = a % p
  if m < (0 : BigInt) {
    m + p
  } else {
    m
  }
}

///|
pub fn mod_n(c : Curve, a : BigInt) -> BigInt {
  let n = params(c).n
  let m = a % n
  if m < (0 : BigInt) {
    m + n
  } else {
    m
  }
}

///|
/// The inverse by Fermat's little theorem, which needs a prime modulus — both
/// the field prime and the group order are prime, so it serves for each.
pub fn inv(a : BigInt, modulus : BigInt) -> BigInt {
  let m = a % modulus
  let norm = if m < (0 : BigInt) { m + modulus } else { m }
  norm.pow(modulus - 2, modulus~)
}

///|
pub fn on_curve(c : Curve, x : BigInt, y : BigInt) -> Bool {
  let q = params(c)
  mod_p(c, y * y) == mod_p(c, x * x * x + q.a * x + q.b)
}

///|
/// Recover `Y` from `X` for a compressed point. Every curve here has
/// `p ≡ 3 (mod 4)`, so the square root is one exponentiation.
pub fn y_of(c : Curve, x : BigInt, odd : Bool) -> BigInt {
  let q = params(c)
  let yy = mod_p(c, x * x * x + q.a * x + q.b)
  let y = yy.pow((q.p + 1) / 4, modulus=q.p)
  if (y % 2 == (1 : BigInt)) == odd {
    y
  } else {
    q.p - y
  }
}

///|
pub fn double(c : Curve, pt : Point) -> Point {
  if pt.zero || pt.y == (0 : BigInt) {
    return { x: 0, y: 0, zero: true, }
  }
  let lam = mod_p(
    c,
    (3 * pt.x * pt.x + params(c).a) * inv(2 * pt.y, params(c).p),
  )
  let x = mod_p(c, lam * lam - 2 * pt.x)
  { x, y: mod_p(c, lam * (pt.x - x) - pt.y), zero: false, }
}

///|
pub fn add(c : Curve, a : Point, b : Point) -> Point {
  if a.zero {
    return b
  }
  if b.zero {
    return a
  }
  if a.x == b.x {
    return if a.y == b.y { double(c, a) } else { { x: 0, y: 0, zero: true, } }
  }
  let lam = mod_p(c, (b.y - a.y) * inv(b.x - a.x, params(c).p))
  let x = mod_p(c, lam * lam - a.x - b.x)
  { x, y: mod_p(c, lam * (a.x - x) - a.y), zero: false, }
}

///|
/// A point in Jacobian coordinates, `x = X/Z²` and `y = Y/Z³`; `Z = 0` is the
/// point at infinity. A scalar multiplication pays one inversion at the end
/// instead of one per step.
priv struct Jacobian {
  x : BigInt
  y : BigInt
  z : BigInt
}

///|
/// `dbl-2007-bl` from the Explicit-Formulas Database, valid for any `a`.
fn jdouble(c : Curve, p : Jacobian) -> Jacobian {
  if p.z == (0 : BigInt) || p.y == (0 : BigInt) {
    return { x: 1, y: 1, z: 0, }
  }
  let q = params(c)
  let xx = mod_p(c, p.x * p.x)
  let yy = mod_p(c, p.y * p.y)
  let yyyy = mod_p(c, yy * yy)
  let zz = mod_p(c, p.z * p.z)
  let s = mod_p(c, 2 * ((p.x + yy) * (p.x + yy) - xx - yyyy))
  let m = mod_p(c, 3 * xx + q.a * zz * zz)
  let t = mod_p(c, m * m - 2 * s)
  {
    x: t,
    y: mod_p(c, m * (s - t) - 8 * yyyy),
    z: mod_p(c, (p.y + p.z) * (p.y + p.z) - yy - zz),
  }
}

///|
/// `add-2007-bl` from the Explicit-Formulas Database.
fn jadd(c : Curve, a : Jacobian, b : Jacobian) -> Jacobian {
  if a.z == (0 : BigInt) {
    return b
  }
  if b.z == (0 : BigInt) {
    return a
  }
  let z1z1 = mod_p(c, a.z * a.z)
  let z2z2 = mod_p(c, b.z * b.z)
  let u1 = mod_p(c, a.x * z2z2)
  let u2 = mod_p(c, b.x * z1z1)
  let s1 = mod_p(c, a.y * b.z * z2z2)
  let s2 = mod_p(c, b.y * a.z * z1z1)
  let h = mod_p(c, u2 - u1)
  let r = mod_p(c, 2 * (s2 - s1))
  if h == (0 : BigInt) {
    return if r == (0 : BigInt) { jdouble(c, a) } else { { x: 1, y: 1, z: 0, } }
  }
  let i = mod_p(c, 4 * h * h)
  let j = mod_p(c, h * i)
  let v = mod_p(c, u1 * i)
  let x = mod_p(c, r * r - j - 2 * v)
  {
    x,
    y: mod_p(c, r * (v - x) - 2 * s1 * j),
    z: mod_p(c, ((a.z + b.z) * (a.z + b.z) - z1z1 - z2z2) * h),
  }
}

///|
/// `[k]P`. A Montgomery ladder: every bit costs one addition and one doubling,
/// whatever its value, so the sequence of operations does not spell out `k`.
pub fn mul(c : Curve, k : BigInt, pt : Point) -> Point {
  if pt.zero {
    return pt
  }
  let mut r0 : Jacobian = { x: 1, y: 1, z: 0, }
  let mut r1 : Jacobian = { x: pt.x, y: pt.y, z: 1, }
  for i = bits(k) - 1; i >= 0; i = i - 1 {
    if (k >> i) % 2 == (1 : BigInt) {
      r0 = jadd(c, r0, r1)
      r1 = jdouble(c, r1)
    } else {
      r1 = jadd(c, r0, r1)
      r0 = jdouble(c, r0)
    }
  }
  if r0.z == (0 : BigInt) {
    return { x: 0, y: 0, zero: true, }
  }
  let p = params(c).p
  let zi = inv(r0.z, p)
  let zi2 = mod_p(c, zi * zi)
  { x: mod_p(c, r0.x * zi2), y: mod_p(c, r0.y * zi2 * zi), zero: false, }
}

///|
pub fn bits(n : BigInt) -> Int32 {
  let mut count = 0
  let mut rest = n
  while rest > (0 : BigInt) {
    count += 1
    rest = rest >> 1
  }
  count
}

///|
/// A point read from SEC 1 §2.3.3: `04 ∥ X ∥ Y` uncompressed, or `02`/`03 ∥ X`
/// compressed with the prefix giving the parity of `Y`. Refused unless it lies on
/// the curve.
pub fn decode(c : Curve, point : BytesView) -> Point raise @spec.Broken {
  let size = c.size()
  let (x, y) = if point.length() == 1 + 2 * size && point[0] == b'\x04' {
    (
      BigInt::from_octets(point[1:1 + size]),
      BigInt::from_octets(point[1 + size:]),
    )
  } else if point.length() == 1 + size &&
    (point[0] == b'\x02' || point[0] == b'\x03') {
    let x = BigInt::from_octets(point[1:])
    (x, y_of(c, x, point[0] == b'\x03'))
  } else {
    raise @spec.Size(want=1 + 2 * size, got=point.length())
  }
  guard x < params(c).p && y < params(c).p && on_curve(c, x, y) else {
    raise @spec.Tag
  }
  { x, y, zero: false, }
}

///|
/// A point as an uncompressed SEC 1 point, `04 ∥ X ∥ Y`.
pub fn encode(c : Curve, pt : Point) -> Bytes {
  let size = c.size()
  let out : Array[Byte] = [b'\x04']
  for b in pt.x.to_octets(length=size) {
    out.push(b)
  }
  for b in pt.y.to_octets(length=size) {
    out.push(b)
  }
  Bytes::from_array(out)
}

///|
/// A scalar read big-endian and fixed-width, refused unless it is in `[1, n)`.
pub fn scalar(c : Curve, bytes : BytesView) -> BigInt raise @spec.Broken {
  let size = c.size()
  guard bytes.length() == size else {
    raise @spec.Size(want=size, got=bytes.length())
  }
  let d = BigInt::from_octets(bytes)
  guard d >= (1 : BigInt) && d < params(c).n else { raise @spec.Tag }
  d
}
