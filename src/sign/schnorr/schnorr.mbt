// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The curve BIP 340 is defined over, and the only one it has.
let curve : @curve.Curve = Secp256k1

///|
/// The length of a secret key, a public key and half a signature.
///
/// A public key is 32 bytes and not 33, because BIP 340 drops the parity byte
/// that SEC1 keeps: the scheme only ever uses the even-y point for a given x.
pub let key_size : Int32 = 32

///|
/// The length of a signature: `R.x ∥ s`, sixty-four bytes.
pub let sig_size : Int32 = 64

///|
/// A signing key.
pub struct PrivateKey {
  scalar : BigInt
  point : @ec.Point
}

///|
/// A verification key: the even-y point whose x coordinate is the key.
pub struct PublicKey {
  point : @ec.Point
}

///|
/// A fresh signing key, its scalar drawn from `source` uniformly in [1, n - 1].
pub fn[S : @moonrand.Source] PrivateKey::generate(
  source : S,
) -> PrivateKey raise @moonrand.Unavailable {
  let order = @ec.params(curve).n.to_octets(length=key_size)
  let scalar = BigInt::from_octets(@moonrand.scalar(order, source))
  { scalar, point: @ec.mul(curve, scalar, @ec.generator(curve)), }
}

///|
/// Read a signing key from its 32 bytes.
///
/// The scalar has to lie in `[1, n-1]`. Zero is not a key, and a value at or above
/// the group order is a different scalar — the same number modulo `n` — which
/// would give a signature that verifies against a different key than the one the
/// caller thought they were using.
pub fn PrivateKey::new(secret : BytesView) -> PrivateKey raise @spec.Broken {
  guard secret.length() == key_size else {
    raise @spec.Size(want=key_size, got=secret.length())
  }
  let scalar = BigInt::from_octets(secret)
  let order = @ec.params(curve).n
  guard scalar > (0 : BigInt) && scalar < order else { raise @spec.Weak }
  let point = @ec.mul(curve, scalar, @ec.generator(curve))
  { scalar, point, }
}

///|
/// The 32 bytes this key is written as.
pub fn PrivateKey::bytes(self : PrivateKey) -> Bytes {
  self.scalar.to_octets(length=key_size)
}

///|
/// The verification key that matches this signing key.
///
/// The x coordinate is taken from `d·G` and the parity is thrown away; signing
/// then works with whichever of `d` and `n-d` lands on the even-y point.
pub fn PrivateKey::public(self : PrivateKey) -> PublicKey {
  { point: even(self.point), }
}

///|
/// Read a verification key from its 32 bytes.
///
/// The bytes are an x coordinate, and not every 32-byte string is one: it has to
/// be below the field prime, and `x³+7` has to be a square. Either failing is a
/// key that cannot exist, so both are refused here rather than at verification
/// time, where the answer would be a silent `false`.
pub fn PublicKey::new(raw : BytesView) -> PublicKey raise @spec.Broken {
  guard raw.length() == key_size else {
    raise @spec.Size(want=key_size, got=raw.length())
  }
  { point: lift_x(BigInt::from_octets(raw)), }
}

///|
/// The 32 bytes this key is written as: the x coordinate.
pub fn PublicKey::bytes(self : PublicKey) -> Bytes {
  self.point.x.to_octets(length=key_size)
}

///|
/// Sign a message with fresh auxiliary randomness mixed into the nonce.
///
/// `aux` is 32 bytes that do not have to be secret and do not have to be random
/// to be correct — but they are what protects the key if the entropy source ever
/// repeats itself, which is why BIP 340 asks for them. Deterministic signing is
/// `sign` with none.
pub fn PrivateKey::sign_with(
  self : PrivateKey,
  msg : BytesView,
  aux~ : BytesView = zeroes(),
) -> Bytes raise @spec.Broken {
  guard aux.length() == key_size else {
    raise @spec.Size(want=key_size, got=aux.length())
  }
  self.sign_checked(msg, aux)
}

///|
/// The signature itself, once the auxiliary input is known to be the right
/// length.
///
/// Kept apart from [`sign_with`](#sign_with) so that the trait form, which cannot
/// raise, has something to call: the only thing left that can go wrong here is a
/// nonce of zero, which needs the hash to produce 256 zero bits.
fn PrivateKey::sign_checked(
  self : PrivateKey,
  msg : BytesView,
  aux : BytesView,
) -> Bytes {
  let order = @ec.params(curve).n
  let point = even(self.point)
  // Negate the scalar along with the point, so that the key used for signing is
  // the one whose point has the even y the verifier will lift to.
  let scalar = if self.point.y % (2 : BigInt) == (0 : BigInt) {
    self.scalar
  } else {
    order - self.scalar
  }
  let mask = xor(scalar.to_octets(length=key_size), tagged("BIP0340/aux", aux))
  let nonce = tagged(
    "BIP0340/nonce",
    join([mask, point.x.to_octets(length=key_size), msg.to_owned()]),
  )
  let k0 = BigInt::from_octets(nonce) % order
  guard k0 != (0 : BigInt) else {
    // The probability is about 2^-256, and it means the hash is broken rather
    // than the key. There is no correct signature to return, so this stops.
    abort("schnorr: the derived nonce is zero")
  }
  let r_point = @ec.mul(curve, k0, @ec.generator(curve))
  let k = if r_point.y % (2 : BigInt) == (0 : BigInt) { k0 } else { order - k0 }
  let e = challenge(r_point.x.to_octets(length=key_size), point, msg)
  join([
    r_point.x.to_octets(length=key_size),
    ((k + e * scalar) % order).to_octets(length=key_size),
  ])
}

///|
/// Check a 64-byte signature.
///
/// `R = s·G - e·P` is computed and compared to the `r` in the signature. Both
/// halves are range-checked first: `r` below the field prime, `s` below the group
/// order, because either being out of range admits a second encoding of a valid
/// signature, which is the malleability this scheme exists to avoid.
///
/// A public key that is not a point, a signature of the wrong length, and a
/// point at infinity are all `false` rather than errors: a signature that does
/// not verify is an expected answer.
pub impl @spec.Verifier for PublicKey with fn verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  if sig.length() != sig_size {
    return false
  }
  let r = BigInt::from_octets(sig[0:32])
  let s = BigInt::from_octets(sig[32:64])
  let prime = @ec.params(curve).p
  let order = @ec.params(curve).n
  if r >= prime || s >= order {
    return false
  }
  let e = challenge(sig[0:32].to_owned(), self.point, msg)
  // s·G - e·P, with the subtraction done as an addition of the negation.
  let left = @ec.mul(curve, s, @ec.generator(curve))
  let right = @ec.mul(curve, e, self.point)
  let sum = @ec.add(curve, left, negate(right))
  if sum.zero {
    return false
  }
  // An odd y is not the point the verifier lifted to, and the x alone would not
  // tell the two apart — which is exactly how a signature could be replayed onto
  // a different key if this check were left out.
  if sum.y % (2 : BigInt) != (0 : BigInt) {
    return false
  }
  sum.x == r
}

///|
pub extend PrivateKey with @spec.Signer::{sign}

///|
/// Sign deterministically: the same key, message and auxiliary randomness always
/// give the same signature.
pub impl @spec.Signer for PrivateKey with fn sign(
  self : PrivateKey,
  msg : BytesView,
) -> Bytes {
  self.sign_checked(msg, zeroes())
}

///|
pub extend PublicKey with @spec.Verifier::{verify}

// ------------------------------------------------------------------ internals

///|
/// `H(tag) ‖ H(tag) ‖ msg`, so that no two uses of SHA-256 can collide.
fn tagged(tag : String, msg : BytesView) -> Bytes {
  let prefix = @sha2.hash(@utf8.encode(tag)[:])
  @sha2.hash(join([prefix, prefix, msg.to_owned()])[:])
}

///|
/// `e = H(R ‖ P ‖ m) mod n`, the challenge.
fn challenge(r : Bytes, point : @ec.Point, msg : BytesView) -> BigInt {
  let order = @ec.params(curve).n
  BigInt::from_octets(
    tagged(
      "BIP0340/challenge",
      join([r, point.x.to_octets(length=key_size), msg.to_owned()]),
    ),
  ) %
  order
}

///|
/// The even-y point with the same x, which is the point a key is.
fn even(point : @ec.Point) -> @ec.Point {
  if point.y % (2 : BigInt) == (0 : BigInt) {
    point
  } else {
    negate(point)
  }
}

///|
fn negate(point : @ec.Point) -> @ec.Point {
  if point.zero {
    point
  } else {
    { x: point.x, y: @ec.params(curve).p - point.y, zero: false, }
  }
}

///|
/// The even-y point at `x`, or a refusal if there is none.
fn lift_x(x : BigInt) -> @ec.Point raise @spec.Broken {
  let prime = @ec.params(curve).p
  guard x < prime else { raise @spec.Weak }
  let y = @ec.y_of(curve, x, false)
  guard @ec.on_curve(curve, x, y) else {
    // `x³+7` was not a square, so no point has this x.
    raise @spec.Weak
  }
  { x, y, zero: false, }
}

///|
fn xor(a : Bytes, b : Bytes) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<a.length() {
    out.push((a[i].to_int() ^ b[i].to_int()).to_byte())
  }
  Bytes::from_array(out)
}

///|
fn join(parts : Array[Bytes]) -> Bytes {
  let out : Array[Byte] = []
  for part in parts {
    for i in 0..<part.length() {
      out.push(part[i])
    }
  }
  Bytes::from_array(out)
}

///|
/// Thirty-two zero bytes, the auxiliary input a deterministic signature uses.
fn zeroes() -> Bytes {
  let out : Array[Byte] = []
  for _ in 0..<key_size {
    out.push(b'\x00')
  }
  Bytes::from_array(out)
}
