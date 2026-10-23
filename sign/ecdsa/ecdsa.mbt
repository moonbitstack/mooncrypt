// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which curve a key lives on: the three NIST primes TLS and JOSE speak, and
/// secp256k1, which Bitcoin and Ethereum speak.
pub using @ec {type Curve}

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
  curve~ : Curve = P256,
) -> PublicKey raise @spec.Broken {
  PublicKey::with_hash(point, paired(curve), curve~)
}

///|
/// A public key read against a digest of the caller's choosing.
pub fn PublicKey::with_hash(
  point : BytesView,
  hash : () -> &@spec.Hash,
  curve~ : Curve = P256,
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
    (x, @ec.y_of(curve, x, point[0] == b'\x03'))
  } else {
    raise @spec.Size(want=1 + 2 * size, got=point.length())
  }
  guard @ec.on_curve(curve, x, y) else { raise @spec.Tag }
  { curve, hash, x, y, }
}

///|
/// Read a public key from its two affine coordinates — the shape a JWK carries.
pub fn PublicKey::of_xy(
  x : BytesView,
  y : BytesView,
  curve~ : Curve = P256,
) -> PublicKey raise @spec.Broken {
  let size = curve.size()
  guard x.length() == size && y.length() == size else {
    raise @spec.Size(want=size, got=x.length())
  }
  let px = BigInt::from_octets(x)
  let py = BigInt::from_octets(y)
  guard @ec.on_curve(curve, px, py) else { raise @spec.Tag }
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
  curve~ : Curve = P256,
) -> PrivateKey raise @spec.Broken {
  PrivateKey::with_hash(scalar, paired(curve), curve~)
}

///|
/// A signing key read against a digest of the caller's choosing.
pub fn PrivateKey::with_hash(
  scalar : BytesView,
  hash : () -> &@spec.Hash,
  curve~ : Curve = P256,
) -> PrivateKey raise @spec.Broken {
  let size = curve.size()
  guard scalar.length() == size else {
    raise @spec.Size(want=size, got=scalar.length())
  }
  let d = BigInt::from_octets(scalar)
  let order = @ec.params(curve).n
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
  let q = @ec.mul(self.curve, self.d, @ec.generator(self.curve))
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
  let order = @ec.params(self.curve).n
  let h1 = @spec.digest((self.hash)(), msg)
  let e = truncate(h1[:], order)
  let mut k = nonce(self, h1)
  // A zero `r` or `s` is vanishingly unlikely and would be a signature that
  // verifies for anything, so it is re-derived rather than emitted.
  for _ in 0..<64 {
    let pt = @ec.mul(self.curve, k, @ec.generator(self.curve))
    let r = @ec.mod_n(self.curve, pt.x)
    let s = @ec.mod_n(self.curve, @ec.inv(k, order) * (e + r * self.d))
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
    k = @ec.mod_n(self.curve, k + 1)
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
  let order = @ec.params(self.curve).n
  let r = BigInt::from_octets(sig[0:size])
  let s = BigInt::from_octets(sig[size:])
  if r < (1 : BigInt) || r >= order || s < (1 : BigInt) || s >= order {
    return false
  }
  let e = truncate(@spec.digest((self.hash)(), msg)[:], order)
  let w = @ec.inv(s, order)
  let pt = @ec.add(
    self.curve,
    @ec.mul(self.curve, @ec.mod_n(self.curve, e * w), @ec.generator(self.curve)),
    @ec.mul(self.curve, @ec.mod_n(self.curve, r * w), {
      x: self.x,
      y: self.y,
      zero: false,
    }),
  )
  if pt.zero {
    return false
  }
  @ec.mod_n(self.curve, pt.x) == r
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
/// A digest as an integer, keeping only as many leading bits as the group order
/// has (FIPS 186-4 §6.4). A digest wider than the order must be cut, or a
/// SHA-512 signature over P-256 would silently reduce instead of truncate.
fn truncate(h : BytesView, order : BigInt) -> BigInt {
  let e = BigInt::from_octets(h)
  let extra = h.length() * 8 - @ec.bits(order)
  if extra > 0 {
    e >> extra
  } else {
    e
  }
}

///|
/// The deterministic nonce of RFC 6979 §3.2: an HMAC-DRBG seeded with the
/// private key and the message digest, drained until it yields a scalar in
/// range.
fn nonce(key : PrivateKey, h1 : Bytes) -> BigInt {
  let order = @ec.params(key.curve).n
  let size = key.curve.size()
  let hlen = (key.hash)().size()
  let x = key.d.to_octets(length=size)
  let e = @ec.mod_n(key.curve, truncate(h1[:], order)).to_octets(length=size)
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
