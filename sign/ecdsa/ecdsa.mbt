// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which curve a key lives on.
///
/// The four short-Weierstrass curves that protocols in use actually name: the
/// three NIST primes, which TLS and JOSE speak, and secp256k1, which Bitcoin and
/// Ethereum speak. They differ only in their parameters, so the arithmetic below
/// is written once and each curve is a row in a table.
pub(all) enum Curve {
  P256
  P384
  P521
  Secp256k1
} derive(Eq, Debug)

///|
pub extend Curve with Eq::{equal, not_equal}

///|
pub extend Curve with Debug::{to_repr}

///|
/// The width in bytes of a coordinate, a scalar, and each half of a signature.
pub fn Curve::size(self : Curve) -> Int {
  match self {
    P256 | Secp256k1 => 32
    P384 => 48
    P521 => 66
  }
}

///|
/// An ECDSA verification key: a point on the curve.
struct PublicKey {
  curve : Curve
  hash : () -> &@spec.Hash
  x : BigInt
  y : BigInt
}

///|
/// An ECDSA signing key: a scalar less than the group order.
struct PrivateKey {
  curve : Curve
  hash : () -> &@spec.Hash
  d : BigInt
}

///|
/// Read a public key from a SEC 1 §2.3.3 encoded point.
///
/// Both forms are accepted: `04 ∥ X ∥ Y` uncompressed, and `02`/`03 ∥ X`
/// compressed, where the prefix gives the parity of `Y` and the rest is
/// recovered from the curve equation.
///
/// The digest is the one the curve is standardly paired with — SHA-256 for the
/// 256-bit curves, SHA-384 for P-384, SHA-512 for P-521 — which is what ES256,
/// ES384 and ES512 mean. Use [`PublicKey::with_hash`] for any other pairing.
pub fn PublicKey::new(
  point : BytesView,
  curve? : Curve = P256,
) -> PublicKey raise @spec.Broken {
  PublicKey::with_hash(point, paired(curve), curve~)
}

///|
/// A public key read against a digest of the caller's choosing.
pub fn PublicKey::with_hash(
  point : BytesView,
  hash : () -> &@spec.Hash,
  curve? : Curve = P256,
) -> PublicKey raise @spec.Broken {
  let size = curve.size()
  let (x, y) = if point.length() == 1 + 2 * size && point[0] == b'\x04' {
    (
      BigInt::from_octets(point[1:1 + size]),
      BigInt::from_octets(point[1 + size:]),
    )
  } else if point.length() == 1 + size &&
    (point[0] == b'\x02' || point[0] == b'\x03') {
    let x = BigInt::from_octets(point[1:])
    (x, y_of(curve, x, point[0] == b'\x03'))
  } else {
    raise @spec.Size(want=1 + 2 * size, got=point.length())
  }
  guard on_curve(curve, x, y) else { raise @spec.Tag }
  { curve, hash, x, y, }
}

///|
/// Read a public key from its two affine coordinates — the shape a JWK carries.
pub fn PublicKey::of_xy(
  x : BytesView,
  y : BytesView,
  curve? : Curve = P256,
) -> PublicKey raise @spec.Broken {
  let size = curve.size()
  guard x.length() == size && y.length() == size else {
    raise @spec.Size(want=size, got=x.length())
  }
  let px = BigInt::from_octets(x)
  let py = BigInt::from_octets(y)
  guard on_curve(curve, px, py) else { raise @spec.Tag }
  { curve, hash: paired(curve), x: px, y: py, }
}

///|
/// The key as an uncompressed SEC 1 point, `04 ∥ X ∥ Y`.
pub fn PublicKey::bytes(self : PublicKey) -> Bytes {
  let size = self.curve.size()
  let out : Array[Byte] = [b'\x04']
  for b in self.x.to_octets(length=size) {
    out.push(b)
  }
  for b in self.y.to_octets(length=size) {
    out.push(b)
  }
  Bytes::from_array(out)
}

///|
/// The two affine coordinates, each fixed-width — the shape a JWK wants.
pub fn PublicKey::xy(self : PublicKey) -> (Bytes, Bytes) {
  let size = self.curve.size()
  (self.x.to_octets(length=size), self.y.to_octets(length=size))
}

///|
/// Which curve this key is on.
pub fn PublicKey::curve(self : PublicKey) -> Curve {
  self.curve
}

///|
/// Read a signing key from its scalar, big-endian and fixed-width.
pub fn PrivateKey::new(
  scalar : BytesView,
  curve? : Curve = P256,
) -> PrivateKey raise @spec.Broken {
  PrivateKey::with_hash(scalar, paired(curve), curve~)
}

///|
/// A signing key read against a digest of the caller's choosing.
pub fn PrivateKey::with_hash(
  scalar : BytesView,
  hash : () -> &@spec.Hash,
  curve? : Curve = P256,
) -> PrivateKey raise @spec.Broken {
  let size = curve.size()
  guard scalar.length() == size else {
    raise @spec.Size(want=size, got=scalar.length())
  }
  let d = BigInt::from_octets(scalar)
  let order = params(curve).n
  guard d >= (1 : BigInt) && d < order else { raise @spec.Tag }
  { curve, hash, d, }
}

///|
/// The scalar this key is written as, big-endian and fixed-width.
pub fn PrivateKey::bytes(self : PrivateKey) -> Bytes {
  self.d.to_octets(length=self.curve.size())
}

///|
/// The verification key that matches this signing key: `Q = [d]G`.
pub fn PrivateKey::public(self : PrivateKey) -> PublicKey {
  let q = mul(self.curve, self.d, generator(self.curve))
  { curve: self.curve, hash: self.hash, x: q.x, y: q.y, }
}

///|
/// Which curve this key is on.
pub fn PrivateKey::curve(self : PrivateKey) -> Curve {
  self.curve
}

///|
pub extend PrivateKey with @spec.Signer::{sign}

///|
/// Sign a message (FIPS 186-4 §6.4.1), returning `r ∥ s` — two fixed-width
/// big-endian integers, which is the encoding JOSE and most wire protocols use.
/// The ASN.1 DER wrapper that OpenSSL writes is a separate concern and belongs
/// with the other DER.
///
/// The nonce is derived from the key and the message by RFC 6979, not drawn from
/// an entropy source. A repeated or guessable nonce hands over the private key
/// outright — it is how the PlayStation 3 and several Bitcoin wallets were
/// emptied — so removing the entropy source removes the failure.
pub impl @spec.Signer for PrivateKey with fn sign(
  self : PrivateKey,
  msg : BytesView,
) -> Bytes {
  let size = self.curve.size()
  let order = params(self.curve).n
  let h1 = @spec.digest((self.hash)(), msg)
  let e = truncate(h1[:], order)
  let mut k = nonce(self, h1)
  // A zero `r` or `s` is vanishingly unlikely and would be a signature that
  // verifies for anything, so it is re-derived rather than emitted.
  for _ in 0..<64 {
    let pt = mul(self.curve, k, generator(self.curve))
    let r = mod_n(self.curve, pt.x)
    let s = mod_n(self.curve, inv(k, order) * (e + r * self.d))
    if r != (0 : BigInt) && s != (0 : BigInt) {
      let out : Array[Byte] = []
      for b in r.to_octets(length=size) {
        out.push(b)
      }
      for b in s.to_octets(length=size) {
        out.push(b)
      }
      return Bytes::from_array(out)
    }
    k = mod_n(self.curve, k + 1)
  }
  abort("ecdsa: no usable nonce after 64 attempts, which cannot happen")
}

///|
pub extend PublicKey with @spec.Verifier::{verify}

///|
/// Check an `r ∥ s` signature (FIPS 186-4 §6.4.2).
pub impl @spec.Verifier for PublicKey with fn verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  let size = self.curve.size()
  if sig.length() != 2 * size {
    return false
  }
  let order = params(self.curve).n
  let r = BigInt::from_octets(sig[0:size])
  let s = BigInt::from_octets(sig[size:])
  if r < (1 : BigInt) || r >= order || s < (1 : BigInt) || s >= order {
    return false
  }
  let e = truncate(@spec.digest((self.hash)(), msg)[:], order)
  let w = inv(s, order)
  let pt = add(
    self.curve,
    mul(self.curve, mod_n(self.curve, e * w), generator(self.curve)),
    mul(self.curve, mod_n(self.curve, r * w), {
      x: self.x,
      y: self.y,
      zero: false,
    }),
  )
  if pt.zero {
    return false
  }
  mod_n(self.curve, pt.x) == r
}

// ----------------------------------------------------------------- the curves

///|
priv struct Params {
  p : BigInt
  a : BigInt
  b : BigInt
  n : BigInt
  gx : BigInt
  gy : BigInt
}

///|
priv struct Point {
  x : BigInt
  y : BigInt
  zero : Bool
}

///|
fn big(s : String) -> BigInt {
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
fn params(c : Curve) -> Params {
  match c {
    P256 => p256
    P384 => p384
    P521 => p521
    Secp256k1 => secp256k1
  }
}

///|
/// The digest each curve is standardly paired with, which is what ES256, ES384
/// and ES512 name.
fn paired(c : Curve) -> () -> &@spec.Hash {
  match c {
    P256 | Secp256k1 => fn() { @sha2.Hasher::new() }
    P384 => fn() { @sha2.Hasher::new(kind=Sha384) }
    P521 => fn() { @sha2.Hasher::new(kind=Sha512) }
  }
}

///|
fn generator(c : Curve) -> Point {
  let q = params(c)
  { x: q.gx, y: q.gy, zero: false, }
}

///|
fn mod_p(c : Curve, a : BigInt) -> BigInt {
  let p = params(c).p
  let m = a % p
  if m < (0 : BigInt) {
    m + p
  } else {
    m
  }
}

///|
fn mod_n(c : Curve, a : BigInt) -> BigInt {
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
fn inv(a : BigInt, modulus : BigInt) -> BigInt {
  let m = a % modulus
  let norm = if m < (0 : BigInt) { m + modulus } else { m }
  norm.pow(modulus - 2, modulus~)
}

///|
fn on_curve(c : Curve, x : BigInt, y : BigInt) -> Bool {
  let q = params(c)
  mod_p(c, y * y) == mod_p(c, x * x * x + q.a * x + q.b)
}

///|
/// Recover `Y` from `X` for a compressed point. Every curve here has
/// `p ≡ 3 (mod 4)`, so the square root is one exponentiation.
fn y_of(c : Curve, x : BigInt, odd : Bool) -> BigInt {
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
fn double(c : Curve, pt : Point) -> Point {
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
fn add(c : Curve, a : Point, b : Point) -> Point {
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
fn mul(c : Curve, k : BigInt, pt : Point) -> Point {
  let mut acc : Point = { x: 0, y: 0, zero: true, }
  let mut addend = pt
  let mut rest = k
  while rest > (0 : BigInt) {
    if rest % 2 == (1 : BigInt) {
      acc = add(c, acc, addend)
    }
    addend = double(c, addend)
    rest = rest / 2
  }
  acc
}

///|
/// A digest as an integer, keeping only as many leading bits as the group order
/// has (FIPS 186-4 §6.4). A digest wider than the order must be cut, or a
/// SHA-512 signature over P-256 would silently reduce instead of truncate.
fn truncate(h : BytesView, order : BigInt) -> BigInt {
  let e = BigInt::from_octets(h)
  let extra = h.length() * 8 - bits(order)
  if extra > 0 {
    e >> extra
  } else {
    e
  }
}

///|
fn bits(n : BigInt) -> Int {
  let mut count = 0
  let mut rest = n
  while rest > (0 : BigInt) {
    count += 1
    rest = rest >> 1
  }
  count
}

///|
/// The deterministic nonce of RFC 6979 §3.2: an HMAC-DRBG seeded with the
/// private key and the message digest, drained until it yields a scalar in
/// range.
fn nonce(key : PrivateKey, h1 : Bytes) -> BigInt {
  let order = params(key.curve).n
  let size = key.curve.size()
  let hlen = (key.hash)().size()
  let x = key.d.to_octets(length=size)
  let e = mod_n(key.curve, truncate(h1[:], order)).to_octets(length=size)
  let mut v = Bytes::make(hlen, b'\x01')
  let mut k = Bytes::make(hlen, b'\x00')
  k = @hmac.mac(k[:], join([v[:], b"\x00"[:], x[:], e[:]]), key.hash)
  v = @hmac.mac(k[:], v[:], key.hash)
  k = @hmac.mac(k[:], join([v[:], b"\x01"[:], x[:], e[:]]), key.hash)
  v = @hmac.mac(k[:], v[:], key.hash)
  for _ in 0..<1000 {
    // The order can be wider than one digest — P-521 needs two — so the
    // candidate is filled a digest at a time before it is read as an integer.
    let t : Array[Byte] = []
    while t.length() < size {
      v = @hmac.mac(k[:], v[:], key.hash)
      for b in v {
        t.push(b)
      }
    }
    let candidate = truncate(Bytes::from_array(t)[0:size], order)
    if candidate >= (1 : BigInt) && candidate < order {
      return candidate
    }
    k = @hmac.mac(k[:], join([v[:], b"\x00"[:]]), key.hash)
    v = @hmac.mac(k[:], v[:], key.hash)
  }
  abort("ecdsa: the RFC 6979 generator did not produce a scalar in range")
}

///|
fn join(parts : Array[BytesView]) -> BytesView {
  let out : Array[Byte] = []
  for part in parts {
    for b in part {
      out.push(b)
    }
  }
  Bytes::from_array(out)[:]
}
