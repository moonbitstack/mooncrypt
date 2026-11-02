// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// The four byte layouts of FIPS 204 §7, each writer next to its reader so a
// change to one cannot be forgotten in the other.

///|
/// `pk = rho || t1`, ten bits per coefficient.
fn public_bytes(kind : Kind, rho : BytesView, t1 : Array[Poly]) -> Bytes {
  let parts : Array[BytesView] = [rho]
  for i in 0..<kind.k() {
    parts.push(pack(t1[i], 10))
  }
  concat(parts)
}

///|
fn public_parse(kind : Kind, pk : BytesView) -> (Bytes, Array[Poly]) {
  let t1 = polys(kind.k())
  for i in 0..<kind.k() {
    t1[i] = unpack(pk[32 + i * 320:32 + (i + 1) * 320], 10)
  }
  (pk[0:32].to_owned(), t1)
}

///|
/// Write `offset - coefficient` at `bits` per coefficient, which is how the
/// signed vectors of FIPS 204 are packed: `eta - s` for the secrets and
/// `2^(d-1) - t0` for the low half of `t`.
fn pack_shifted(r : Poly, bits : Int32, offset : Int32) -> Bytes {
  let tmp = poly()
  for i in 0..<degree {
    tmp[i] = freeze(offset - r[i])
  }
  pack(tmp, bits)
}

///|
fn unpack_shifted(b : BytesView, bits : Int32, offset : Int32) -> Poly {
  let r = unpack(b, bits)
  for i in 0..<degree {
    r[i] = offset - r[i]
  }
  r
}

///|
/// `sk = rho || K || tr || s1 || s2 || t0`.
fn secret_bytes(
  kind : Kind,
  rho : BytesView,
  key : BytesView,
  tr : BytesView,
  s1 : Array[Poly],
  s2 : Array[Poly],
  t0 : Array[Poly],
) -> Bytes {
  let bits = if kind.eta() == 2 { 3 } else { 4 }
  let parts : Array[BytesView] = [rho, key, tr]
  for i in 0..<kind.l() {
    parts.push(pack_shifted(s1[i], bits, kind.eta()))
  }
  for i in 0..<kind.k() {
    parts.push(pack_shifted(s2[i], bits, kind.eta()))
  }
  for i in 0..<kind.k() {
    parts.push(pack_shifted(t0[i], 13, 1 << (dropped - 1)))
  }
  concat(parts)
}

///|
/// The three header seeds of a private key followed by its vectors.
fn secret_parse(
  kind : Kind,
  sk : BytesView,
) -> (Bytes, Bytes, Bytes, Array[Poly], Array[Poly], Array[Poly]) {
  let bits = if kind.eta() == 2 { 3 } else { 4 }
  let w = kind.secret_width()
  let eta = kind.eta()
  let s1 = polys(kind.l())
  let s2 = polys(kind.k())
  let t0 = polys(kind.k())
  let mut at = 128
  for i in 0..<kind.l() {
    s1[i] = unpack_shifted(sk[at:at + w], bits, eta)
    at += w
  }
  for i in 0..<kind.k() {
    s2[i] = unpack_shifted(sk[at:at + w], bits, eta)
    at += w
  }
  for i in 0..<kind.k() {
    t0[i] = unpack_shifted(sk[at:at + 416], 13, 1 << (dropped - 1))
    at += 416
  }
  (sk[0:32].to_owned(), sk[32:64].to_owned(), sk[64:128].to_owned(), s1, s2, t0)
}

///|
/// `w1` serialised for the challenge hash, at the width the parameter set's
/// number of high bits needs.
fn high_bits_bytes(kind : Kind, w1 : Array[Poly]) -> Bytes {
  let parts : Array[BytesView] = []
  for i in 0..<kind.k() {
    parts.push(pack(w1[i], kind.high_bits_width()))
  }
  concat(parts)
}

///|
/// `hint` as the standard writes it: the positions of the ones, in order, then
/// for each row the cumulative count so far.
///
/// The counts sit at `omega + i` because a row's positions may fill the space
/// before it; the reader uses them to know where one row's list ends.
fn hint_bytes(kind : Kind, hint : Array[Poly]) -> Bytes {
  let out = Array::make(kind.omega() + kind.k(), b'\x00')
  let mut at = 0
  for i in 0..<kind.k() {
    for j in 0..<degree {
      if hint[i][j] != 0 {
        out[at] = j.to_byte()
        at += 1
      }
    }
    out[kind.omega() + i] = at.to_byte()
  }
  Bytes::from_array(out)
}

///|
/// Read a hint, refusing the encodings the standard forbids: an index list that
/// is not strictly increasing, a count that goes backwards or past `omega`, or
/// a byte left over at the end.
///
/// Without these the same hint would have several encodings and a signature
/// could be altered without being invalidated — the malleability FIPS 204's
/// "strong unforgeability" note is about.
fn hint_parse(kind : Kind, b : BytesView) -> Array[Poly] raise @spec.Broken {
  let hint = polys(kind.k())
  let omega = kind.omega()
  let mut at = 0
  for i in 0..<kind.k() {
    let end = b[omega + i].to_int()
    guard end >= at && end <= omega else { raise @spec.Weak }
    for j in at..<end {
      guard j == at || b[j] > b[j - 1] else { raise @spec.Weak }
      hint[i][b[j].to_int()] = 1
    }
    at = end
  }
  for j in at..<omega {
    guard b[j] == 0 else { raise @spec.Weak }
  }
  hint
}

///|
/// `sig = c_tilde || z || h`.
fn signature_bytes(
  kind : Kind,
  c_tilde : BytesView,
  z : Array[Poly],
  hint : Array[Poly],
) -> Bytes {
  let bits = mask_bits(kind)
  let gamma1 = kind.gamma1()
  let parts : Array[BytesView] = [c_tilde]
  for i in 0..<kind.l() {
    parts.push(pack_shifted(z[i], bits, gamma1))
  }
  parts.push(hint_bytes(kind, hint))
  concat(parts)
}

///|
fn signature_parse(
  kind : Kind,
  sig : BytesView,
) -> (Bytes, Array[Poly], Array[Poly]) raise @spec.Broken {
  let bits = mask_bits(kind)
  let gamma1 = kind.gamma1()
  let width = 32 * bits
  let z = polys(kind.l())
  let c_tilde = sig[0:kind.challenge()].to_owned()
  for i in 0..<kind.l() {
    let at = kind.challenge() + i * width
    z[i] = unpack_shifted(sig[at:at + width], bits, gamma1)
  }
  let at = kind.challenge() + kind.l() * width
  let hint = hint_parse(kind, sig[at:at + kind.omega() + kind.k()])
  (c_tilde, z, hint)
}
