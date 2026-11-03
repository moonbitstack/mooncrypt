// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The length of a scalar, a u-coordinate and a shared secret, in bytes. All
/// three are 32; X25519 has no other size.
pub let size : Int32 = 32

///|
/// The ladder constant `(A - 2) / 4`, which is 121665 for Curve25519.
let a24 : @field25519.Fe = @field25519.from_bigint(121665N)

///|
/// The base point, `u = 9`, little-endian (RFC 7748 §4.1).
pub let base : Bytes = {
  let out = Array::make(32, b'\x00')
  out[0] = b'\x09'
  Bytes::from_array(out)
}

///|
/// The 32 bytes as a field element, high bit masked by the caller.
fn decode(b : FixedArray[Int32]) -> @field25519.Fe {
  let raw = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    raw[i] = b[i].to_byte()
  }
  @field25519.from_le_bytes(Bytes::from_array(raw)[:])
}

///|
/// The Montgomery ladder (RFC 7748 §5), over the shared 25519 field.
///
/// The conditional swap is a mask, not a branch: the scalar's bits are clamped
/// and secret, so a swap that showed in the timing would show the key.
fn ladder(scalar : FixedArray[Int32], x1 : @field25519.Fe) -> @field25519.Fe {
  let mut x2 = @field25519.one
  let mut z2 = @field25519.from_bigint(0N)
  let mut x3 = x1
  let mut z3 = @field25519.one
  let mut swap = 0UL
  for t = 254; t >= 0; t = t - 1 {
    let bit = ((scalar[t / 8] >> (t % 8)) & 1).to_uint64()
    swap = swap ^ bit
    let mask = 0UL - swap
    let sx2 = @field25519.select(mask, x3, x2)
    let sz2 = @field25519.select(mask, z3, z2)
    let sx3 = @field25519.select(mask, x2, x3)
    let sz3 = @field25519.select(mask, z2, z3)
    x2 = sx2
    z2 = sz2
    x3 = sx3
    z3 = sz3
    swap = bit
    let a = @field25519.add(x2, z2)
    let aa = @field25519.sqr(a)
    let b = @field25519.sub(x2, z2)
    let bb = @field25519.sqr(b)
    let e = @field25519.sub(aa, bb)
    let c = @field25519.add(x3, z3)
    let d = @field25519.sub(x3, z3)
    let da = @field25519.mul(d, a)
    let cb = @field25519.mul(c, b)
    x3 = @field25519.sqr(@field25519.add(da, cb))
    z3 = @field25519.mul(x1, @field25519.sqr(@field25519.sub(da, cb)))
    x2 = @field25519.mul(aa, bb)
    z2 = @field25519.mul(e, @field25519.add(aa, @field25519.mul(a24, e)))
  }
  let mask = 0UL - swap
  let fx2 = @field25519.select(mask, x3, x2)
  let fz2 = @field25519.select(mask, z3, z2)
  @field25519.mul(fx2, @field25519.inv(fz2))
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
  let out = @field25519.to_le_bytes(ladder(k, decode(u)))
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
/// A fresh private scalar: 32 bytes from `source`, as RFC 7748 §6.1 has it;
/// the bits are clamped where the scalar is used.
pub fn[S : @moonseed.Source] generate(
  source : S,
) -> Bytes raise @moonseed.Unavailable {
  @moonseed.bytes(32, source)
}

///|
/// The public key for a private one: the scalar applied to the base point.
pub fn public(scalar : BytesView) -> Bytes raise @spec.Broken {
  shared(scalar, base[:])
}
