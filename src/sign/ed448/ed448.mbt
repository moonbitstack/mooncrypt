// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An Ed448 verification key: a point on edwards448 in its 57-byte encoding.
struct PublicKey {
  raw : Bytes
  point : Point
}

///|
/// An Ed448 signing key: the 57-byte secret, not the expanded scalar.
struct PrivateKey {
  seed : Bytes
  scalar : BigInt
  prefix : Bytes
}

///|
/// The length of a secret, a public key and half a signature: 57 bytes, which is
/// 456 bits — the bit width `b` in RFC 8032's table, not the field width.
pub let key_size : Int32 = 57

///|
/// The length of a signature: `R ∥ S`, 114 bytes.
pub let sig_size : Int32 = 114

///|
/// The longest context RFC 8032 allows, since `dom4` writes its length in one
/// octet.
pub let max_context : Int32 = 255

///|
/// Read a public key from its 57-byte encoding.
///
/// Raises [`@spec.Broken::Weak`] when the bytes are not a point on the curve: a
/// key that does not decode cannot verify anything, and accepting it invites a
/// caller to compare garbage against garbage.
pub fn PublicKey::new(raw : BytesView) -> PublicKey raise @spec.Broken {
  guard raw.length() == key_size else {
    raise @spec.Broken::Size(want=key_size, got=raw.length())
  }
  { raw: raw.to_owned(), point: decode(raw), }
}

///|
/// The 57 bytes this key is written as.
pub fn PublicKey::bytes(self : PublicKey) -> Bytes {
  self.raw
}

///|
/// A fresh signing key from 57 bytes of `source`, as RFC 8032 §5.2.5 describes.
pub fn[S : @moonseed.Source] PrivateKey::generate(
  source : S,
) -> PrivateKey raise @moonseed.Unavailable {
  expand(@moonseed.bytes(key_size, source))
}

///|
/// Read a signing key from its 57-byte secret.
pub fn PrivateKey::new(seed : BytesView) -> PrivateKey raise @spec.Broken {
  guard seed.length() == key_size else {
    raise @spec.Broken::Size(want=key_size, got=seed.length())
  }
  expand(seed)
}

///|
/// RFC 8032 §5.2.5: the secret's digest splits in two. Pruning clears the two
/// low bits of the first octet to kill the cofactor, clears the last octet
/// entirely, and sets the top bit of the second to last — which together pin the
/// scalar to a fixed width and a fixed multiple of four.
fn expand(seed : BytesView) -> PrivateKey {
  let h = @sha3.shake256(seed, 114)
  let clamped : FixedArray[Byte] = FixedArray::make(key_size, b'\x00')
  for i in 0..<key_size {
    clamped[i] = h[i]
  }
  clamped[0] = (clamped[0].to_int() & 252).to_byte()
  clamped[55] = (clamped[55].to_int() | 128).to_byte()
  clamped[56] = b'\x00'
  {
    seed: seed.to_owned(),
    scalar: le_int(Bytes::from_array(clamped)[:]),
    prefix: h[57:114].to_owned(),
  }
}

///|
/// The secret this key was built from.
pub fn PrivateKey::bytes(self : PrivateKey) -> Bytes {
  self.seed
}

///|
/// The verification key that matches this signing key: `A = [s]B`.
///
/// The point is decoded from its own encoding so that a `PublicKey` always holds
/// the pair together. That decode cannot fail — `[s]B` is a point on the curve by
/// construction — so a failure here is a bug in this file, not something a caller
/// could cause or handle.
pub fn PrivateKey::public(self : PrivateKey) -> PublicKey {
  let raw = encode(mul(self.scalar, base))
  let point = try decode(raw[:]) catch {
    _ => abort("ed448: the public key does not decode, which cannot happen")
  } noraise {
    point => point
  }
  { raw, point, }
}

///|
/// `dom4(phflag, context)` from RFC 8032 §2: the literal `SigEd448`, then one
/// octet for the flag and one for the context length, then the context.
///
/// Its job is to stop a signature made under one algorithm, or in one protocol,
/// from being presented as a signature under another. Every byte of it is
/// hashed, so leaving it out is not a small mistake: it changes the answer.
fn dom4(prehash : Bool, context : BytesView) -> Bytes {
  let out : Array[Byte] = []
  for b in @utf8.encode("SigEd448") {
    out.push(b)
  }
  out.push(if prehash { b'\x01' } else { b'\x00' })
  out.push(context.length().to_byte())
  for b in context {
    out.push(b)
  }
  Bytes::from_array(out)
}

///|
/// The part of a message that is hashed: the message itself, or its SHAKE256
/// digest at 64 bytes for Ed448ph.
fn message(prehash : Bool, msg : BytesView) -> Bytes {
  if prehash {
    @sha3.shake256(msg, 64)
  } else {
    msg.to_owned()
  }
}

///|
/// Sign with what has already been reduced to the two byte strings the scheme
/// actually hashes.
fn PrivateKey::sign_dom(
  self : PrivateKey,
  ph : BytesView,
  dom : BytesView,
) -> Bytes {
  let a = encode(mul(self.scalar, base))
  let r = mod_l(
    le_int(@sha3.shake256(join([dom, self.prefix[:], ph])[:], 114)[:]),
  )
  let big_r = encode(mul(r, base))
  let k = mod_l(
    le_int(@sha3.shake256(join([dom, big_r[:], a[:], ph])[:], 114)[:]),
  )
  join([big_r[:], le_bytes(mod_l(r + k * self.scalar), key_size)[:]])
}

///|
/// Sign a message with a context, RFC 8032 §5.2.6.
///
/// The context is optional and defaults to empty, which is the plain Ed448 of
/// the RFC. `prehash` selects Ed448ph, where the message is replaced by its
/// 64-byte SHAKE256 digest before signing — the variant for streams too large to
/// hold in memory.
///
/// As with Ed25519 the signature is deterministic: `r` comes from the key's
/// prefix and the message, not from a random source.
pub fn PrivateKey::sign_with(
  self : PrivateKey,
  msg : BytesView,
  context~ : BytesView = b"",
  prehash~ : Bool = false,
) -> Bytes raise @spec.Broken {
  guard context.length() <= max_context else {
    raise @spec.Broken::Size(want=max_context, got=context.length())
  }
  self.sign_dom(message(prehash, msg)[:], dom4(prehash, context)[:])
}

///|
pub extend PrivateKey with @spec.Signer::{sign}

///|
/// Sign a message with no context and no prehash, which is what the [`Signer`]
/// contract can express.
pub impl @spec.Signer for PrivateKey with fn sign(
  self : PrivateKey,
  msg : BytesView,
) -> Bytes {
  self.sign_dom(msg, dom4(false, b"")[:])
}

///|
/// Check a signature with a context, RFC 8032 §5.2.7.
///
/// Returns `false` for anything wrong with the signature — a point that does not
/// decode, `S` at or above the group order, the equation not holding — and
/// raises only when the *caller* is at fault, which for Ed448 means a context
/// longer than 255 bytes.
pub fn PublicKey::verify_with(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
  context~ : BytesView = b"",
  prehash~ : Bool = false,
) -> Bool raise @spec.Broken {
  guard context.length() <= max_context else {
    raise @spec.Broken::Size(want=max_context, got=context.length())
  }
  if sig.length() != sig_size {
    return false
  }
  let s = le_int(sig[57:114])
  if s >= l {
    return false
  }
  // A signature whose `R` is not a point on the curve is not a signature. It is
  // collected rather than returned from inside the handler so that the only
  // early exit in this function is at the top level, where it reads plainly.
  let decoded : Array[Point] = []
  try decode(sig[0:57]) catch {
    _ => ()
  } noraise {
    point => decoded.push(point)
  }
  guard decoded.length() == 1 else { return false }
  let r_pt = decoded[0]
  let ph = message(prehash, msg)
  let k = mod_l(
    le_int(
      @sha3.shake256(
        join([dom4(prehash, context), sig[0:57], self.raw[:], ph[:]])[:],
        114,
      )[:],
    ),
  )
  let lhs = mul(s, base)
  let rhs = add(r_pt, mul(k, self.point))
  same(lhs, rhs)
}

///|
pub extend PublicKey with @spec.Verifier::{verify}

///|
/// Check a signature with no context and no prehash.
///
/// Every path that can fail is a `false` here, because that is all the
/// [`Verifier`] contract offers and all a caller should have to handle: a bad
/// signature is an answer, not an exception.
pub impl @spec.Verifier for PublicKey with fn verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  try self.verify_with(msg, sig) catch {
    _ => false
  } noraise {
    ok => ok
  }
}

// ------------------------------------------------------------------ the curve

///|
/// `p = 2^448 - 2^224 - 1`, the field prime.
let p : BigInt = (1N << 448) - (1N << 224) - 1N

///|
/// The curve coefficient `d = -39081`.
///
/// Positive here, unlike Ed25519's quotient, and the curve is untwisted — `a =
/// 1` — so `d` appears in the addition law without a companion `a`.
let d : BigInt = p - 39081N

///|
/// `L`, the order of the base point's subgroup.
let l : BigInt = BigInt::from_string(
  "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3",
  radix=16,
)

///|
/// A point in projective coordinates: `x = X/Z`, `y = Y/Z`.
///
/// Projective rather than affine because every addition in affine coordinates
/// needs an inversion, and an inversion is a full modular exponentiation. The
/// neutral element is `(0, Z, Z)` — no special case, because the addition law is
/// complete.
priv struct Point {
  x : BigInt
  y : BigInt
  z : BigInt
}

///|
/// The base point of edwards448, in the decimal the RFC states it and converted
/// to hex.
let base : Point = {
  x: BigInt::from_string(
    "4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E",
    radix=16,
  ),
  y: BigInt::from_string(
    "693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14",
    radix=16,
  ),
  z: 1N,
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
  mod_p(a).pow(p - 2N, modulus=p)
}

///|
/// Point addition on an untwisted Edwards curve, RFC 8032 §5.2.4.
///
/// Complete: it works for any pair of valid points, including the neutral one
/// and a point with itself, so there is no branch on the inputs and nothing to
/// get wrong when a scalar multiplication happens to add a point to itself.
fn add(a : Point, b : Point) -> Point {
  let aa = mod_p(a.z * b.z)
  let bb = mod_p(aa * aa)
  let cc = mod_p(a.x * b.x)
  let dd = mod_p(a.y * b.y)
  let e = mod_p(d * cc * dd)
  let f = mod_p(bb - e)
  let g = mod_p(bb + e)
  let h = mod_p((a.x + a.y) * (b.x + b.y))
  {
    x: mod_p(aa * f * (h - cc - dd)),
    y: mod_p(aa * g * (dd - cc)),
    z: mod_p(f * g),
  }
}

///|
/// Doubling, RFC 8032 §5.2.4: the addition formulas with the two inputs made
/// equal, which turns four multiplications into squares.
fn twice(a : Point) -> Point {
  let bb = mod_p((a.x + a.y) * (a.x + a.y))
  let cc = mod_p(a.x * a.x)
  let dd = mod_p(a.y * a.y)
  let e = mod_p(cc + dd)
  let h = mod_p(a.z * a.z)
  let j = mod_p(e - 2N * h)
  { x: mod_p((bb - e) * j), y: mod_p(e * (cc - dd)), z: mod_p(e * j), }
}

///|
fn mul(e : BigInt, pt : Point) -> Point {
  let mut acc : Point = { x: 0, y: 1, z: 1, }
  let mut addend = pt
  let mut k = e
  while k > (0 : BigInt) {
    if k % 2 == (1 : BigInt) {
      acc = add(acc, addend)
    }
    addend = twice(addend)
    k = k / 2
  }
  acc
}

///|
/// Whether two projective points are the same affine point.
fn same(a : Point, b : Point) -> Bool {
  mod_p(a.x * b.z) == mod_p(b.x * a.z) && mod_p(a.y * b.z) == mod_p(b.y * a.z)
}

///|
/// The 57-byte encoding of a point, RFC 8032 §5.2.2: `y` little-endian, with the
/// low bit of `x` folded into the top bit of the last octet — which is otherwise
/// always zero, because the field is 448 bits and the encoding is 456.
fn encode(pt : Point) -> Bytes {
  let zinv = inv(pt.z)
  let y = mod_p(pt.y * zinv)
  let x = mod_p(pt.x * zinv)
  let out = Array::make(key_size, b'\x00')
  let mut acc = y
  for i in 0..<key_size {
    out[i] = (acc % 256N).to_int().to_byte()
    acc = acc / 256N
  }
  if x % 2 == (1 : BigInt) {
    out[56] = b'\x80'
  }
  Bytes::from_array(out)
}

///|
/// Decode a point, RFC 8032 §5.2.3.
///
/// The square root is the part that can fail: `x² = (y² - 1)/(d·y² - 1)` has no
/// solution for most values of `y`, and a value that is not on the curve is
/// refused rather than mapped to the nearest point that is.
fn decode(s : BytesView) -> Point raise @spec.Broken {
  guard s.length() == key_size else {
    raise @spec.Broken::Size(want=key_size, got=s.length())
  }
  let raw : FixedArray[Byte] = FixedArray::make(key_size, b'\x00')
  for i in 0..<key_size {
    raw[i] = s[i]
  }
  let sign = (raw[56].to_int() >> 7) & 1
  raw[56] = (raw[56].to_int() & 0x7F).to_byte()
  let y = le_int(Bytes::from_array(raw)[:])
  guard y < p else { raise @spec.Broken::Weak }
  // p ≡ 3 (mod 4), so a square root is a^((p+1)/4) whenever one exists at all.
  let yy = mod_p(y * y)
  let u = mod_p(yy - 1)
  let v = mod_p(d * yy - 1)
  let mut x = mod_p(u * inv(v)).pow((p + 1) / 4N, modulus=p)
  guard mod_p(v * x * x) == u else { raise @spec.Broken::Weak }
  guard !(x == (0 : BigInt) && sign == 1) else { raise @spec.Broken::Weak }
  let parity = if x % 2 == (1 : BigInt) { 1 } else { 0 }
  if parity != sign {
    x = p - x
  }
  { x, y, z: 1N, }
}

///|
/// Little-endian bytes as an integer, which is how every Ed448 scalar and
/// coordinate is written.
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
fn join(parts : Array[BytesView]) -> Bytes {
  let out : Array[Byte] = []
  for part in parts {
    for b in part {
      out.push(b)
    }
  }
  Bytes::from_array(out)
}
