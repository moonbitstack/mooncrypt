// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
using @bigint {type BigInt}

///|
/// The recommended curve of GB/T 32918.5-2017 §A.2.
priv struct Curve {
  p : BigInt
  a : BigInt
  b : BigInt
  n : BigInt
  gx : BigInt
  gy : BigInt
}

///|
let curve : Curve = {
  p: @ec.big("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
  a: @ec.big("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"),
  b: @ec.big("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
  n: @ec.big("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
  gx: @ec.big(
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
  ),
  gy: @ec.big(
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
  ),
}

///|
/// The coordinate width in bytes, and the width of each half of a signature.
pub let size : Int32 = 32

///|
/// The default identity a signature is bound to (GB/T 32918.2-2016 §5.5). It is
/// not a secret and not a key; it separates one application's signatures from
/// another's, the way a domain separator does.
pub let default_id : Bytes = b"1234567812345678"

///|
fn field(v : BigInt) -> BigInt {
  let m = v % curve.p
  if m < (0 : BigInt) {
    m + curve.p
  } else {
    m
  }
}

///|
fn order(v : BigInt) -> BigInt {
  let m = v % curve.n
  if m < (0 : BigInt) {
    m + curve.n
  } else {
    m
  }
}

///|
/// A point in Jacobian coordinates, so a scalar multiplication pays one
/// inversion at the end instead of one at every step.
priv struct Jac {
  x : BigInt
  y : BigInt
  z : BigInt
}

///|
let infinity : Jac = { x: 1, y: 1, z: 0, }

///|
fn jdouble(q : Jac) -> Jac {
  if q.z == (0 : BigInt) || q.y == (0 : BigInt) {
    return infinity
  }
  let xx = field(q.x * q.x)
  let yy = field(q.y * q.y)
  let yyyy = field(yy * yy)
  let zz = field(q.z * q.z)
  let s = field(2 * ((q.x + yy) * (q.x + yy) - xx - yyyy))
  let m = field(3 * xx + curve.a * zz * zz)
  let t = field(m * m - 2 * s)
  {
    x: t,
    y: field(m * (s - t) - 8 * yyyy),
    z: field((q.y + q.z) * (q.y + q.z) - yy - zz),
  }
}

///|
fn jadd(a : Jac, b : Jac) -> Jac {
  if a.z == (0 : BigInt) {
    return b
  }
  if b.z == (0 : BigInt) {
    return a
  }
  let z1z1 = field(a.z * a.z)
  let z2z2 = field(b.z * b.z)
  let u1 = field(a.x * z2z2)
  let u2 = field(b.x * z1z1)
  let s1 = field(a.y * b.z * z2z2)
  let s2 = field(b.y * a.z * z1z1)
  let h = field(u2 - u1)
  let r = field(2 * (s2 - s1))
  if h == (0 : BigInt) {
    return if r == (0 : BigInt) { jdouble(a) } else { infinity }
  }
  let i = field(4 * h * h)
  let j = field(h * i)
  let v = field(u1 * i)
  let x = field(r * r - j - 2 * v)
  {
    x,
    y: field(r * (v - x) - 2 * s1 * j),
    z: field(((a.z + b.z) * (a.z + b.z) - z1z1 - z2z2) * h),
  }
}

///|
/// `[k]P`, ladder-shaped: every bit costs one addition and one doubling
/// whatever its value.
fn jmul(k : BigInt, pt : Jac) -> Jac {
  if pt.z == (0 : BigInt) || k == (0 : BigInt) {
    return infinity
  }
  let mut r0 = infinity
  let mut r1 = pt
  for i = @ec.bits(k) - 1; i >= 0; i = i - 1 {
    if (k >> i) % 2 == (1 : BigInt) {
      r0 = jadd(r0, r1)
      r1 = jdouble(r1)
    } else {
      r1 = jadd(r0, r1)
      r0 = jdouble(r0)
    }
  }
  r0
}

///|
fn affine(q : Jac) -> (BigInt, BigInt, Bool) {
  if q.z == (0 : BigInt) {
    return (0, 0, true)
  }
  let zi = @ec.inv(q.z, curve.p)
  let zi2 = field(zi * zi)
  (field(q.x * zi2), field(q.y * zi2 * zi), false)
}

///|
fn generator() -> Jac {
  { x: curve.gx, y: curve.gy, z: 1, }
}

///|
/// A verification key: the public point.
pub(all) struct PublicKey {
  x : BigInt
  y : BigInt
}

///|
/// A signing key: a scalar in `[1, n-1]`.
pub struct PrivateKey {
  d : BigInt
}

///|
/// A private key from its 32-byte big-endian encoding.
pub fn PrivateKey::new(bytes : BytesView) -> PrivateKey raise @spec.Broken {
  guard bytes.length() == 32 else {
    raise @spec.Broken::Size(want=32, got=bytes.length())
  }
  PrivateKey::from_big(BigInt::from_octets(bytes))
}

///|
/// A private key from a scalar, refused unless it is in range.
pub fn PrivateKey::from_big(d : BigInt) -> PrivateKey raise @spec.Broken {
  guard d > (0 : BigInt) && d < curve.n - 1 else { raise @spec.Broken::Weak }
  PrivateKey::{ d, }
}

///|
/// A fresh private key, drawn from `source` uniformly in [1, n - 2] as GB/T
/// 32918.1 §6.1 asks, so that 1 + d is invertible when signing.
pub fn[S : @moonseed.Source] PrivateKey::generate(
  source : S,
) -> PrivateKey raise @moonseed.Unavailable {
  let bound = (curve.n - 1).to_octets(length=32)
  PrivateKey::{ d: BigInt::from_octets(@moonseed.scalar(bound, source)), }
}

///|
/// The 32-byte big-endian encoding of the scalar.
pub fn PrivateKey::encode(self : PrivateKey) -> Bytes {
  self.d.to_octets(length=32)
}

///|
/// The public point this key signs under.
pub fn PrivateKey::public(self : PrivateKey) -> PublicKey {
  let (x, y, _) = affine(jmul(self.d, generator()))
  { x, y, }
}

///|
/// A public key from a SEC 1 §2.3.3 point: `04 ∥ X ∥ Y` uncompressed, or
/// `02`/`03 ∥ X` compressed. A point off the curve is refused.
pub fn PublicKey::new(point : BytesView) -> PublicKey raise @spec.Broken {
  let (x, y) = if point.length() == 65 && point[0] == b'\x04' {
    (BigInt::from_octets(point[1:33]), BigInt::from_octets(point[33:]))
  } else if point.length() == 33 && (point[0] == b'\x02' || point[0] == b'\x03') {
    let x = BigInt::from_octets(point[1:])
    let yy = field(x * x * x + curve.a * x + curve.b)
    // p ≡ 3 (mod 4), so one exponentiation takes the square root.
    let mut y = yy.pow((curve.p + 1) / 4, modulus=curve.p)
    if (y % 2 == (1 : BigInt)) != (point[0] == b'\x03') {
      y = curve.p - y
    }
    (x, y)
  } else {
    raise @spec.Broken::Size(want=65, got=point.length())
  }
  guard on_curve(x, y) else { raise @spec.Broken::Weak }
  { x, y, }
}

///|
fn on_curve(x : BigInt, y : BigInt) -> Bool {
  field(y * y) == field(x * x * x + curve.a * x + curve.b)
}

///|
/// The uncompressed encoding, `04 ∥ X ∥ Y`.
pub fn PublicKey::encode(self : PublicKey) -> Bytes {
  let out : Array[Byte] = [b'\x04']
  for b in self.x.to_octets(length=32) {
    out.push(b)
  }
  for b in self.y.to_octets(length=32) {
    out.push(b)
  }
  Bytes::from_array(out)
}

///|
/// The hash a signature commits to: `SM3(ZA ∥ M)`, where `ZA` binds the
/// identity string, the curve and the public key (GB/T 32918.2 §5.5).
fn digest(key : PublicKey, msg : BytesView, id : BytesView) -> Bytes {
  let h = @sm3.Hasher::new()
  let bits = id.length() * 8
  let entl : Array[Byte] = [(bits >> 8).to_byte(), (bits & 0xFF).to_byte()]
  h.write(Bytes::from_array(entl)[:])
  h.write(id)
  h.write(curve.a.to_octets(length=32)[:])
  h.write(curve.b.to_octets(length=32)[:])
  h.write(curve.gx.to_octets(length=32)[:])
  h.write(curve.gy.to_octets(length=32)[:])
  h.write(key.x.to_octets(length=32)[:])
  h.write(key.y.to_octets(length=32)[:])
  let z = h.finish()
  h.reset()
  h.write(z[:])
  h.write(msg)
  h.finish()
}

///|
/// The deterministic nonce of RFC 6979 §3.2, over SM3: an HMAC-DRBG seeded with
/// the private scalar and the digest.
///
/// SM2 itself asks for a random `k`. Deriving it instead removes the one place
/// where a bad random number hands over the key, which is the same trade ECDSA
/// makes here.
priv struct Nonce {
  mut k : Bytes
  mut v : Bytes
}

///|
fn Nonce::new(secret : BytesView, digest : BytesView) -> Nonce {
  let mut k : Bytes = Bytes::from_array(Array::make(32, b'\x00'))
  let mut v : Bytes = Bytes::from_array(Array::make(32, b'\x01'))
  k = @hmac.mac(
    k[:],
    join(join(v[:], b"\x00"[:])[:], join(secret, digest)[:]),
    fn() { @sm3.Hasher::new() },
  )
  v = @hmac.mac(k[:], v[:], fn() { @sm3.Hasher::new() })
  k = @hmac.mac(
    k[:],
    join(join(v[:], b"\x01"[:])[:], join(secret, digest)[:]),
    fn() { @sm3.Hasher::new() },
  )
  v = @hmac.mac(k[:], v[:], fn() { @sm3.Hasher::new() })
  { k, v, }
}

///|
fn Nonce::next(self : Nonce) -> BigInt {
  let v = @hmac.mac(self.k[:], self.v[:], fn() { @sm3.Hasher::new() })
  let candidate = BigInt::from_octets(v[:])
  self.v = v
  candidate
}

///|
fn Nonce::retry(self : Nonce) -> Unit {
  self.k = @hmac.mac(self.k[:], join(self.v[:], b"\x00"[:]), fn() {
    @sm3.Hasher::new()
  })
  self.v = @hmac.mac(self.k[:], self.v[:], fn() { @sm3.Hasher::new() })
}

///|
fn join(a : BytesView, b : BytesView) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<a.length() {
    out.push(a[i])
  }
  for i in 0..<b.length() {
    out.push(b[i])
  }
  Bytes::from_array(out)
}

///|
/// Sign `msg`, bound to `id`. The signature is `r ∥ s`, thirty-two bytes each.
///
/// The identity is part of what is signed, so a signature made under one `id`
/// does not verify under another — which is what stops a signature from being
/// lifted from one protocol into a different one.
pub fn PrivateKey::sign_with(
  self : PrivateKey,
  msg : BytesView,
  id~ : BytesView = default_id[:],
) -> Bytes {
  let key = self.public()
  let e = BigInt::from_octets(digest(key, msg, id)[:])
  let drbg = Nonce::new(
    self.d.to_octets(length=32)[:],
    e.to_octets(length=32)[:],
  )
  let one : BigInt = 1
  let inverse = @ec.inv(one + self.d, curve.n)
  for _ in 0..<64 {
    let k = drbg.next()
    if k <= (0 : BigInt) || k >= curve.n {
      drbg.retry()
      continue
    }
    let (x1, _, zero) = affine(jmul(k, generator()))
    if zero {
      drbg.retry()
      continue
    }
    let r = order(e + x1)
    if r == (0 : BigInt) || r + k == curve.n {
      drbg.retry()
      continue
    }
    let s = order(inverse * (k - r * self.d))
    if s == (0 : BigInt) {
      drbg.retry()
      continue
    }
    let out : Array[Byte] = []
    for b in r.to_octets(length=32) {
      out.push(b)
    }
    for b in s.to_octets(length=32) {
      out.push(b)
    }
    return Bytes::from_array(out)
  }
  abort("sm2: no usable nonce after 64 attempts, which cannot happen")
}

///|
/// Check `sig` against `msg` and `id`. A malformed signature is a `false`
/// answer, not an error: it is an expected thing for the peer to send.
pub fn PublicKey::verify_with(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
  id~ : BytesView = default_id[:],
) -> Bool {
  guard sig.length() == 64 else { return false }
  let r = BigInt::from_octets(sig[0:32])
  let s = BigInt::from_octets(sig[32:])
  if r <= (0 : BigInt) || r >= curve.n {
    return false
  }
  if s <= (0 : BigInt) || s >= curve.n {
    return false
  }
  let t = order(r + s)
  if t == (0 : BigInt) {
    return false
  }
  let e = BigInt::from_octets(digest(self, msg, id)[:])
  let (x1, _, zero) = affine(
    jadd(jmul(s, generator()), jmul(t, { x: self.x, y: self.y, z: 1, })),
  )
  if zero {
    return false
  }
  order(e + x1) == r
}

///|

///|
pub extend PrivateKey with @spec.Signer::{sign}

///|
/// The default identity, so a signer can be used wherever a `Signer` is
/// expected without naming one.
pub impl @spec.Signer for PrivateKey with fn sign(
  self : PrivateKey,
  msg : BytesView,
) -> Bytes {
  self.sign_with(msg)
}

///|

///|
pub extend PublicKey with @spec.Verifier::{verify}

///|
pub impl @spec.Verifier for PublicKey with fn verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  self.verify_with(msg, sig)
}
