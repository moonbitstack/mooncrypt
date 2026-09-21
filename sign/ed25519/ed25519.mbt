// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An Ed25519 verification key: a point on Edwards25519 in its 32-byte
/// compressed form.
struct PublicKey {
  raw : Bytes
  point : Point
}

///|
/// An Ed25519 signing key: the 32-byte secret seed, not the expanded scalar.
///
/// RFC 8032 calls the seed the private key and derives everything else from it,
/// which is why a key file holds 32 bytes and not 64.
struct PrivateKey {
  seed : Bytes
  scalar : BigInt
  prefix : Bytes
}

///|
/// The length of a seed, a public key and half a signature.
pub let key_size : Int = 32

///|
/// The length of a signature: `R ∥ S`.
pub let sig_size : Int = 64

///|
/// Read a public key from its 32 compressed bytes.
pub fn PublicKey::new(raw : BytesView) -> PublicKey raise @spec.Broken {
  guard raw.length() == key_size else {
    raise @spec.Size(want=key_size, got=raw.length())
  }
  { raw: raw.to_owned(), point: decode(raw), }
}

///|
/// The 32 bytes this key is written as.
pub fn PublicKey::bytes(self : PublicKey) -> Bytes {
  self.raw
}

///|
/// Read a signing key from its 32-byte seed.
pub fn PrivateKey::new(seed : BytesView) -> PrivateKey raise @spec.Broken {
  guard seed.length() == key_size else {
    raise @spec.Size(want=key_size, got=seed.length())
  }
  expand(seed)
}

///|
/// A signing key from a secret of any length.
///
/// [`PrivateKey::new`] takes the 32-byte seed the key format stores. The
/// expansion itself — SHA-512 over the secret, then clamping — is defined for
/// an input of any length; RFC 8032 fixes the seed at 32 octets so that keys
/// have one written form, not because the arithmetic needs it. MariaDB's
/// `client_ed25519` keys a connection with the password directly, which is the
/// protocol this entry point exists for.
///
/// Anything that holds a real seed wants `new`: it is the one that refuses a
/// secret of the wrong length, and a length check is worth having.
pub fn PrivateKey::of_secret(secret : BytesView) -> PrivateKey {
  expand(secret)
}

///|
/// RFC 8032 §5.1.5: the secret's digest splits in two — the low half is clamped
/// into the scalar, the high half is the prefix that makes signing
/// deterministic. Clamping clears the three low bits to kill the cofactor and
/// pins bit 254 so every scalar has the same length.
fn expand(secret : BytesView) -> PrivateKey {
  let h = @sha2.hash(secret, kind=Sha512)
  let clamped : Array[Byte] = []
  clamped.push((h[0].to_int() & 0xF8).to_byte())
  for i in 1..<31 {
    clamped.push(h[i])
  }
  clamped.push(((h[31].to_int() & 0x7F) | 0x40).to_byte())
  {
    seed: secret.to_owned(),
    scalar: le_int(Bytes::from_array(clamped)[:]),
    prefix: h[32:64].to_owned(),
  }
}

///|
/// The secret this key was built from — the 32-byte seed for a key from
/// [`PrivateKey::new`], and whatever was handed to [`PrivateKey::of_secret`]
/// otherwise.
pub fn PrivateKey::bytes(self : PrivateKey) -> Bytes {
  self.seed
}

///|
/// The verification key that matches this signing key: `A = [s]B`.
pub fn PrivateKey::public(self : PrivateKey) -> PublicKey {
  let raw = encode(mul(self.scalar, base))
  { raw, point: decode(raw[:]), }
}

///|
pub extend PrivateKey with @spec.Signer::{sign}

///|
/// Sign a message (RFC 8032 §5.1.6).
///
/// The same key and message always give the same signature: the nonce is
/// `SHA-512(prefix ∥ message)` rather than a random number, which is what makes
/// the scheme immune to the entropy failures that have leaked ECDSA keys.
pub impl @spec.Signer for PrivateKey with fn sign(
  self : PrivateKey,
  msg : BytesView,
) -> Bytes {
  let a = encode(mul(self.scalar, base))
  let r = mod_l(
    le_int(@sha2.hash(join([self.prefix[:], msg])[:], kind=Sha512)[:]),
  )
  let big_r = encode(mul(r, base))
  let k = mod_l(
    le_int(@sha2.hash(join([big_r[:], a[:], msg])[:], kind=Sha512)[:]),
  )
  join([big_r[:], le_bytes(mod_l(r + k * self.scalar), key_size)[:]])
}

///|
pub extend PublicKey with @spec.Verifier::{verify}

///|
/// Check a 64-byte signature (RFC 8032 §5.1.7): `[S]B = R + [k]A`.
///
/// `S` at or above the group order is rejected, which is what stops a valid
/// signature being rewritten into a second, different, also-valid one.
pub impl @spec.Verifier for PublicKey with fn verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  if sig.length() != sig_size {
    return false
  }
  let s = le_int(sig[32:64])
  if s >= l {
    return false
  }
  let r_pt = decode(sig[0:32])
  let k = mod_l(
    le_int(@sha2.hash(join([sig[0:32], self.raw[:], msg])[:], kind=Sha512)[:]),
  )
  let lhs = mul(s, base)
  let rhs = add(r_pt, mul(k, self.point))
  lhs.x == rhs.x && lhs.y == rhs.y
}

// ------------------------------------------------------------------ the curve

///|
/// `p = 2^255 - 19`, the field prime.
let p : BigInt = BigInt::from_string(
  "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
  radix=16,
)

///|
/// The curve coefficient `d = -121665/121666`.
let d : BigInt = BigInt::from_string(
  "52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3",
  radix=16,
)

///|
/// The order of the base point's subgroup.
let l : BigInt = BigInt::from_string(
  "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
  radix=16,
)

///|
/// A square root of -1, which decompression needs because `p ≡ 5 (mod 8)`.
let sqrt_m1 : BigInt = BigInt::from_string(
  "2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0",
  radix=16,
)

///|
/// 2^255, for masking a compressed point's sign bit away.
let two_255 : BigInt = BigInt::from_string(
  "8000000000000000000000000000000000000000000000000000000000000000",
  radix=16,
)

///|
/// A point in affine coordinates. The twisted-Edwards addition law is complete —
/// identity `(0, 1)`, no exceptional cases — so there is no infinity to carry.
priv struct Point {
  x : BigInt
  y : BigInt
}

///|
let base : Point = {
  x: BigInt::from_string(
    "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
    radix=16,
  ),
  y: BigInt::from_string(
    "6666666666666666666666666666666666666666666666666666666666666658",
    radix=16,
  ),
}

///|
fn mod_p(a : BigInt) -> BigInt {
  let m = a % p
  if m < (0 : BigInt) {
    m + p
  } else {
    m
  }
}

///|
fn mod_l(a : BigInt) -> BigInt {
  let m = a % l
  if m < (0 : BigInt) {
    m + l
  } else {
    m
  }
}

///|
fn inv(a : BigInt) -> BigInt {
  mod_p(a).pow(p - 2, modulus=p)
}

///|
/// Recover `x` from `y`: `x² = (y² - 1)/(d·y² + 1)`, taking the even root.
fn x_of(y : BigInt) -> BigInt {
  let yy = mod_p(y * y)
  let xx = mod_p((yy - 1) * inv(mod_p(d * yy + 1)))
  let mut x = xx.pow((p + 3) / 8, modulus=p)
  if mod_p(x * x - xx) != (0 : BigInt) {
    x = mod_p(x * sqrt_m1)
  }
  if x % 2 != (0 : BigInt) {
    x = p - x
  }
  x
}

///|
fn add(a : Point, b : Point) -> Point {
  let dxy = mod_p(d * a.x * b.x * a.y * b.y)
  {
    x: mod_p((a.x * b.y + b.x * a.y) * inv(mod_p(1 + dxy))),
    y: mod_p((a.y * b.y + a.x * b.x) * inv(mod_p(1 - dxy))),
  }
}

///|
fn mul(e : BigInt, pt : Point) -> Point {
  let mut acc : Point = { x: 0, y: 1, }
  let mut addend = pt
  let mut k = e
  while k > (0 : BigInt) {
    if k % 2 == (1 : BigInt) {
      acc = add(acc, addend)
    }
    addend = add(addend, addend)
    k = k / 2
  }
  acc
}

///|
/// Ed25519 reads and writes integers little-endian, where every other scheme
/// here is big-endian; these two helpers are the whole of that difference.
fn le_int(b : BytesView) -> BigInt {
  let be : Array[Byte] = []
  for i = b.length() - 1; i >= 0; i = i - 1 {
    be.push(b[i])
  }
  BigInt::from_octets(Bytes::from_array(be)[:])
}

///|
fn le_bytes(n : BigInt, length : Int) -> Bytes {
  let be = n.to_octets(length~)
  let le : Array[Byte] = []
  for i = length - 1; i >= 0; i = i - 1 {
    le.push(be[i])
  }
  Bytes::from_array(le)
}

///|
fn encode(pt : Point) -> Bytes {
  let be = mod_p(pt.y).to_octets(length=32)
  let out : Array[Byte] = []
  for i = 31; i >= 1; i = i - 1 {
    out.push(be[i])
  }
  let sign = if mod_p(pt.x) % 2 == (1 : BigInt) { 0x80 } else { 0 }
  out.push((be[0].to_int() | sign).to_byte())
  Bytes::from_array(out)
}

///|
fn decode(s : BytesView) -> Point {
  let y = le_int(s) % two_255
  let mut x = x_of(y)
  let sign = (s[31].to_int() >> 7) & 1
  let parity = if x % 2 == (1 : BigInt) { 1 } else { 0 }
  if parity != sign {
    x = p - x
  }
  { x, y, }
}

///|
fn join(parts : Array[BytesView]) -> Bytes {
  let out : Array[Byte] = []
  for part in parts {
    for b in part {
      out.push(b)
    }
  }
  Bytes::from_array(out)
}
