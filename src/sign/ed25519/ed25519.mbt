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
pub let key_size : Int32 = 32

///|
/// The length of a signature: `R ∥ S`.
pub let sig_size : Int32 = 64

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
/// A fresh signing key from 32 bytes of `source`, as Go's
/// `ed25519.GenerateKey` makes one and RFC 8032 §5.1.5 describes.
pub fn[S : @moonseed.Source] PrivateKey::generate(
  source : S,
) -> PrivateKey raise @moonseed.Unavailable {
  expand(@moonseed.bytes(key_size, source))
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
/// The curve coefficient `d = -121665/121666`.
let d : @field25519.Fe = @field25519.from_bigint(
  BigInt::from_string(
    "52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3",
    radix=16,
  ),
)

///|
/// `2d`, the constant the extended addition law wants.
let two_d : @field25519.Fe = @field25519.add(d, d)

///|
/// The order of the base point's subgroup. Scalar arithmetic stays in `BigInt`:
/// it is a handful of operations per signature, not the inner loop.
let l : BigInt = BigInt::from_string(
  "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
  radix=16,
)

///|
/// A square root of -1, which decompression needs because `p ≡ 5 (mod 8)`.
let sqrt_m1 : @field25519.Fe = @field25519.from_bigint(
  BigInt::from_string(
    "2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0",
    radix=16,
  ),
)

///|
/// The field's zero.
let zero : @field25519.Fe = @field25519.from_bigint(0N)

///|
/// A point in affine coordinates: the form a key is encoded in and returned in.
/// The twisted-Edwards addition law is complete — identity `(0, 1)`, no
/// exceptional cases — so there is no infinity to carry.
priv struct Point {
  x : @field25519.Fe
  y : @field25519.Fe
}

///|
/// The same point in extended coordinates, `x = X/Z`, `y = Y/Z`, `T = XY/Z`.
/// Carrying `Z` is what lets a scalar multiplication go through 255 doublings
/// without one field inversion apiece; the single inversion happens on the way
/// back to affine.
priv struct Ext {
  x : @field25519.Fe
  y : @field25519.Fe
  z : @field25519.Fe
  t : @field25519.Fe
}

///|
let base : Point = {
  x: @field25519.from_bigint(
    BigInt::from_string(
      "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
      radix=16,
    ),
  ),
  y: @field25519.from_bigint(
    BigInt::from_string(
      "6666666666666666666666666666666666666666666666666666666666666658",
      radix=16,
    ),
  ),
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
fn is_odd(a : @field25519.Fe) -> Bool {
  (@field25519.to_le_bytes(a)[0].to_int() & 1) == 1
}

///|
/// Recover `x` from `y`: `x² = (y² - 1)/(d·y² + 1)`, taking the even root.
fn x_of(y : @field25519.Fe) -> @field25519.Fe {
  let yy = @field25519.sqr(y)
  let yy1 = @field25519.sub(yy, @field25519.one)
  let dy1 = @field25519.add(@field25519.mul(d, yy), @field25519.one)
  let xx = @field25519.mul(yy1, @field25519.inv(dy1))
  let mut x = @field25519.pow_8(xx)
  if !@field25519.eq(@field25519.sqr(x), xx) {
    x = @field25519.mul(x, sqrt_m1)
  }
  if is_odd(x) {
    x = @field25519.sub(zero, x)
  }
  x
}

///|
fn to_ext(p : Point) -> Ext {
  { x: p.x, y: p.y, z: @field25519.one, t: @field25519.mul(p.x, p.y), }
}

///|
fn to_affine(p : Ext) -> Point {
  let zi = @field25519.inv(p.z)
  { x: @field25519.mul(p.x, zi), y: @field25519.mul(p.y, zi), }
}

///|
fn identity() -> Ext {
  { x: zero, y: @field25519.one, z: @field25519.one, t: zero, }
}

///|
/// `add-2008-hwcd-3` for `a = -1`: one law for every pair of points, including
/// a point with itself, so there is no special case to get wrong.
fn ext_add(a : Ext, b : Ext) -> Ext {
  let aa = @field25519.mul(@field25519.sub(a.y, a.x), @field25519.sub(b.y, b.x))
  let bb = @field25519.mul(@field25519.add(a.y, a.x), @field25519.add(b.y, b.x))
  let cc = @field25519.mul(@field25519.mul(a.t, two_d), b.t)
  let dd = @field25519.mul(@field25519.add(a.z, a.z), b.z)
  let e = @field25519.sub(bb, aa)
  let f = @field25519.sub(dd, cc)
  let g = @field25519.add(dd, cc)
  let h = @field25519.add(bb, aa)
  {
    x: @field25519.mul(e, f),
    y: @field25519.mul(g, h),
    z: @field25519.mul(f, g),
    t: @field25519.mul(e, h),
  }
}

///|
/// `dbl-2008-hwcd`, which is cheaper than the unified law on the half of the
/// steps that only need a doubling.
fn ext_double(a : Ext) -> Ext {
  let aa = @field25519.sqr(a.x)
  let bb = @field25519.sqr(a.y)
  let cc = @field25519.add(@field25519.sqr(a.z), @field25519.sqr(a.z))
  let dd = @field25519.sub(zero, aa)
  let xy = @field25519.add(a.x, a.y)
  let e = @field25519.sub(@field25519.sub(@field25519.sqr(xy), aa), bb)
  let g = @field25519.add(dd, bb)
  let f = @field25519.sub(g, cc)
  let h = @field25519.sub(dd, bb)
  {
    x: @field25519.mul(e, f),
    y: @field25519.mul(g, h),
    z: @field25519.mul(f, g),
    t: @field25519.mul(e, h),
  }
}

///|
fn ext_select(mask : UInt64, a : Ext, b : Ext) -> Ext {
  {
    x: @field25519.select(mask, a.x, b.x),
    y: @field25519.select(mask, a.y, b.y),
    z: @field25519.select(mask, a.z, b.z),
    t: @field25519.select(mask, a.t, b.t),
  }
}

///|
/// `digit·P` for a secret `digit < 16`: the whole table is read and the match
/// kept with a mask, so the work does not depend on the digit.
fn window_lookup(table : FixedArray[Ext], digit : Int32, start : Ext) -> Ext {
  let mut slot = start
  for i in 0..<16 {
    let diff = (i ^ digit).to_uint64()
    let mask = ((diff | (0UL - diff)) >> 63) - 1UL
    slot = ext_select(mask, table[i], slot)
  }
  slot
}

///|
/// `[e]P`, four bits at a time and over the scalar's full width: 64 additions
/// against a table of the sixteen small multiples instead of 255 steps of a
/// double-and-add, and neither the count nor the table access follows `e`.
fn mul(e : BigInt, pt : Point) -> Point {
  let base_e = to_ext(pt)
  let table = FixedArray::make(16, identity())
  table[0] = identity()
  table[1] = base_e
  for i in 2..<16 {
    table[i] = ext_add(table[i - 1], base_e)
  }
  let bytes = e.to_octets(length=32)
  let mut acc = identity()
  let mut slot = identity()
  for i in 0..<64 {
    if i > 0 {
      for _ in 0..<4 {
        acc = ext_double(acc)
      }
    }
    let byte = bytes[i / 2].to_int()
    let digit = if i % 2 == 0 { (byte >> 4) & 0xF } else { byte & 0xF }
    slot = window_lookup(table, digit, slot)
    acc = ext_add(acc, slot)
  }
  to_affine(acc)
}

///|
fn add(a : Point, b : Point) -> Point {
  to_affine(ext_add(to_ext(a), to_ext(b)))
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
fn le_bytes(n : BigInt, length : Int32) -> Bytes {
  let be = n.to_octets(length~)
  let le : Array[Byte] = []
  for i = length - 1; i >= 0; i = i - 1 {
    le.push(be[i])
  }
  Bytes::from_array(le)
}

///|
fn encode(pt : Point) -> Bytes {
  let out = @field25519.to_le_bytes(pt.y)
  let bytes = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    bytes[i] = out[i]
  }
  let sign = if is_odd(pt.x) { 0x80 } else { 0 }
  bytes[31] = (bytes[31].to_int() | sign).to_byte()
  Bytes::from_array(bytes)
}

///|
fn decode(s : BytesView) -> Point {
  let raw = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    raw[i] = s[i]
  }
  let sign = (raw[31].to_int() >> 7) & 1
  raw[31] = (raw[31].to_int() & 0x7F).to_byte()
  let y = @field25519.from_le_bytes(Bytes::from_array(raw)[:])
  let even = x_of(y)
  let x = if is_odd(even).to_int() != sign {
    @field25519.sub(zero, even)
  } else {
    even
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
