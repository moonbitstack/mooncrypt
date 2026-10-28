// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// An elliptic-curve private key as SEC1 (RFC 5915) holds it.
///
/// The curve name and the public point are both optional in the format. A key
/// without them is still a key — the scalar is the secret — but it cannot be used
/// without being told which curve it is on, so [`curve`](#curve) being `None` is
/// the parser saying "this file is not enough on its own".
pub(all) struct EcPrivate {
  curve : @curve.Curve?
  scalar : BigInt
  public : Bytes?
}

///|
/// The SEC1 `ECPrivateKey` of RFC 5915 §3, with the curve always written.
///
/// `public` is written when it is given. It is derivable from the scalar — it is
/// the scalar times the generator — so a file that carries it is carrying a
/// convenience, not a second secret.
pub fn sec1_der(
  curve : @curve.Curve,
  scalar : BytesView,
  public~ : BytesView? = None,
) -> Bytes {
  let fields = [
    @asn1.integer(b"\x01"),
    @asn1.octet_string(scalar.to_owned()),
    @asn1.explicit(0, @asn1.oid(curve_oid(curve))),
  ]
  match public {
    Some(point) =>
      fields.push(@asn1.explicit(1, @asn1.bit_string(point.to_owned())))
    None => ()
  }
  @asn1.sequence(fields)
}

///|
/// Read a SEC1 `ECPrivateKey`.
///
/// The optional fields are found by their tag rather than by their position,
/// because RFC 5915 marks them `OPTIONAL` and a writer that omits the curve is
/// encoding the same type as one that includes it.
pub fn parse_sec1(der : BytesView) -> EcPrivate raise @asn1.Refused {
  let fields = members(@asn1.only(der))
  guard fields.length() >= 2 else {
    raise @asn1.Malformed("ECPrivateKey is not two fields")
  }
  guard fields[0].int() == (1 : BigInt) else {
    raise @asn1.Unsupported("ECPrivateKey version is not ecPrivkeyVer1")
  }
  let scalar = BigInt::from_octets(fields[1].octets())
  let mut curve = None
  let mut public = None
  for i in 2..<fields.length() {
    let field = fields[i]
    if @asn1.context(field.tag, 0) {
      // `[0]` is explicit, so what it holds is the OID itself — read the
      // contents rather than asserting a SEQUENCE, which `members` would.
      let inner = field.items()
      guard inner.length() == 1 else {
        raise @asn1.Malformed("ECParameters is not one field")
      }
      let named = inner[0].oid()
      curve = match curve_of_oid(named) {
        Some(c) => Some(c)
        None => raise @asn1.Unsupported("unknown named curve " + named)
      }
    } else if @asn1.context(field.tag, 1) {
      let inner = field.items()
      guard inner.length() == 1 else {
        raise @asn1.Malformed("publicKey is not one field")
      }
      public = Some(payload(inner[0]))
    } else {
      raise @asn1.Unsupported("unexpected field in ECPrivateKey")
    }
  }
  { curve, scalar, public, }
}
