// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The object identifiers these formats name. Kept as arcs rather than as strings
// because that is what the encoder takes, and as strings for the reader because
// that is what it gives back.

///|
/// `rsaEncryption` from PKCS#1: what a PKCS#8 or SubjectPublicKeyInfo says when
/// the octets inside are an RSA key.
let rsa_encryption : Array[Int32] = [1, 2, 840, 113549, 1, 1, 1]

///|
let rsa_encryption_oid : String = "1.2.840.113549.1.1.1"

///|
/// `id-ecPublicKey` from RFC 5480: the algorithm identifier for any key on a
/// named short-Weierstrass curve.
let ec_public_key : Array[Int32] = [1, 2, 840, 10045, 2, 1]

///|
let ec_public_key_oid : String = "1.2.840.10045.2.1"

///|
/// The namedCurve identifier of a curve, as the arcs a SEC1 key writes in its
/// `[0]` field and a SubjectPublicKeyInfo writes in its parameters.
pub fn curve_oid(curve : @curve.Curve) -> Array[Int32] {
  match curve {
    P256 => [1, 2, 840, 10045, 3, 1, 7]
    P384 => [1, 3, 132, 0, 34]
    P521 => [1, 3, 132, 0, 35]
    Secp256k1 => [1, 3, 132, 0, 10]
  }
}

///|
/// The curve a namedCurve identifier names, or `None` for a curve this library
/// does not have parameters for.
pub fn curve_of_oid(oid : StringView) -> @curve.Curve? {
  match oid.to_owned() {
    "1.2.840.10045.3.1.7" => Some(P256)
    "1.3.132.0.34" => Some(P384)
    "1.3.132.0.35" => Some(P521)
    "1.3.132.0.10" => Some(Secp256k1)
    _ => None
  }
}

///|
/// An RSA verification key as PKCS#1 holds it: two integers.
pub(all) struct RsaPublic {
  modulus : BigInt
  exponent : BigInt
} derive(Eq)

///|
/// An RSA signing key as PKCS#1 holds it.
///
/// The seven numbers after the modulus and the two exponents are the CRT
/// parameters: they let a signer do two half-size exponentiations instead of one
/// full-size one. They are carried rather than recomputed because a format that
/// stores them would lose information otherwise, and because computing them back
/// from silence costs two big-integer factorisations per load.
pub(all) struct RsaPrivate {
  modulus : BigInt
  public_exponent : BigInt
  private_exponent : BigInt
  prime1 : BigInt
  prime2 : BigInt
  exponent1 : BigInt
  exponent2 : BigInt
  coefficient : BigInt
} derive(Eq)

///|
/// The PKCS#1 `RSAPublicKey` of RFC 8017 §A.1.1.
pub fn rsa_public_der(modulus : BytesView, exponent : BytesView) -> Bytes {
  @asn1.sequence([
    @asn1.integer(modulus.to_owned()),
    @asn1.integer(exponent.to_owned()),
  ])
}

///|
/// Read a PKCS#1 `RSAPublicKey`.
pub fn parse_rsa_public(der : BytesView) -> RsaPublic raise @asn1.Refused {
  let fields = members(@asn1.only(der))
  guard fields.length() == 2 else {
    raise @asn1.Malformed("RSAPublicKey is not two integers")
  }
  { modulus: fields[0].int(), exponent: fields[1].int(), }
}

///|
/// The PKCS#1 `RSAPrivateKey` of RFC 8017 §A.1.2, version 0.
///
/// The two-prime form is the only one written: `version` 1 exists for keys with
/// more than two primes, which no library here generates and no format in
/// practice carries.
pub fn rsa_private_der(key : RsaPrivate) -> Bytes {
  @asn1.sequence([
    @asn1.integer(b"\x00"),
    @asn1.integer(key.modulus.to_octets()),
    @asn1.integer(key.public_exponent.to_octets()),
    @asn1.integer(key.private_exponent.to_octets()),
    @asn1.integer(key.prime1.to_octets()),
    @asn1.integer(key.prime2.to_octets()),
    @asn1.integer(key.exponent1.to_octets()),
    @asn1.integer(key.exponent2.to_octets()),
    @asn1.integer(key.coefficient.to_octets()),
  ])
}

///|
/// Read a PKCS#1 `RSAPrivateKey`.
pub fn parse_rsa_private(der : BytesView) -> RsaPrivate raise @asn1.Refused {
  let fields = members(@asn1.only(der))
  guard fields.length() == 9 else {
    raise @asn1.Malformed("RSAPrivateKey is not nine integers")
  }
  guard fields[0].int() == (0 : BigInt) else {
    raise @asn1.Unsupported("RSAPrivateKey with otherPrimeInfos")
  }
  {
    modulus: fields[1].int(),
    public_exponent: fields[2].int(),
    private_exponent: fields[3].int(),
    prime1: fields[4].int(),
    prime2: fields[5].int(),
    exponent1: fields[6].int(),
    exponent2: fields[7].int(),
    coefficient: fields[8].int(),
  }
}

///|
/// Wrap a PKCS#1 `RSAPrivateKey` in the PKCS#8 `PrivateKeyInfo` of RFC 5958.
pub fn pkcs8_der(rsa_private : BytesView) -> Bytes {
  @asn1.sequence([
    @asn1.integer(b"\x00"),
    algorithm(rsa_encryption),
    @asn1.octet_string(rsa_private.to_owned()),
  ])
}

///|
/// Read a PKCS#8 `PrivateKeyInfo` and return the octets inside, which for an RSA
/// key are a PKCS#1 `RSAPrivateKey`.
///
/// The algorithm identifier is checked rather than returned: a caller that got
/// back the octets of an EC key and parsed them as RSA integers would not find
/// out until the numbers failed to make sense, and that is a long way from the
/// mistake.
pub fn parse_pkcs8(der : BytesView) -> Bytes raise @asn1.Refused {
  let fields = members(@asn1.only(der))
  guard fields.length() >= 3 else {
    raise @asn1.Malformed("PrivateKeyInfo is not three fields")
  }
  guard fields[0].int() == (0 : BigInt) || fields[0].int() == (1 : BigInt) else {
    raise @asn1.Malformed("PrivateKeyInfo version out of range")
  }
  check_algorithm(fields[1], rsa_encryption_oid, "PrivateKeyInfo")
  fields[2].octets().to_owned()
}

///|
/// Wrap a PKCS#1 `RSAPublicKey` in a `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7).
pub fn spki_der(rsa_public : BytesView) -> Bytes {
  @asn1.sequence([
    algorithm(rsa_encryption),
    @asn1.bit_string(rsa_public.to_owned()),
  ])
}

///|
/// Read a `SubjectPublicKeyInfo` and return the DER inside its BIT STRING.
pub fn parse_spki(der : BytesView) -> Bytes raise @asn1.Refused {
  let fields = members(@asn1.only(der))
  guard fields.length() == 2 else {
    raise @asn1.Malformed("SubjectPublicKeyInfo is not two fields")
  }
  check_algorithm(fields[0], rsa_encryption_oid, "SubjectPublicKeyInfo")
  payload(fields[1])
}

///|
/// A `SubjectPublicKeyInfo` for an EC key: the algorithm identifier names the
/// curve, and the BIT STRING holds the point in its uncompressed form.
pub fn spki_ec_der(curve : @curve.Curve, point : BytesView) -> Bytes {
  @asn1.sequence([
    @asn1.sequence([@asn1.oid(ec_public_key), @asn1.oid(curve_oid(curve))]),
    @asn1.bit_string(point.to_owned()),
  ])
}

///|
/// Read an EC `SubjectPublicKeyInfo`: the curve it names and the point.
pub fn parse_spki_ec(
  der : BytesView,
) -> (@curve.Curve, Bytes) raise @asn1.Refused {
  let fields = members(@asn1.only(der))
  guard fields.length() == 2 else {
    raise @asn1.Malformed("SubjectPublicKeyInfo is not two fields")
  }
  let algorithm = members(fields[0])
  guard algorithm.length() == 2 else {
    raise @asn1.Malformed("AlgorithmIdentifier is not two fields")
  }
  guard algorithm[0].oid() == ec_public_key_oid else {
    raise @asn1.Unsupported("SubjectPublicKeyInfo does not name an EC key")
  }
  let named = algorithm[1].oid()
  let curve = match curve_of_oid(named) {
    Some(c) => c
    None => raise @asn1.Unsupported("unknown named curve " + named)
  }
  (curve, payload(fields[1]))
}

///|
/// An `AlgorithmIdentifier` with a NULL parameter — what RSA has written since
/// RFC 3279.
fn algorithm(oid : Array[Int32]) -> Bytes {
  @asn1.sequence([@asn1.oid(oid), @asn1.null()])
}

///|
/// Check that a field is the `AlgorithmIdentifier` for `want`.
fn check_algorithm(
  field : @asn1.Tlv,
  want : String,
  what : String,
) -> Unit raise @asn1.Refused {
  let fields = members(field)
  guard fields.length() >= 1 else {
    raise @asn1.Malformed(what + ": empty AlgorithmIdentifier")
  }
  guard fields[0].oid() == want else {
    raise @asn1.Unsupported(what + " does not name " + want)
  }
}

///|
/// The contents of a BIT STRING that must carry whole bytes — a key is never
/// bit-aligned, so a non-zero unused-bit count is a malformed file rather than a
/// variant to be handled.
fn payload(field : @asn1.Tlv) -> Bytes raise @asn1.Refused {
  let bits = field.bits()
  guard bits.unused == 0 else {
    raise @asn1.Malformed("BIT STRING has unused bits")
  }
  bits.bytes
}

///|
/// The elements of a SEQUENCE.
fn members(field : @asn1.Tlv) -> Array[@asn1.Tlv] raise @asn1.Refused {
  guard field.tag == 0x30 else { raise @asn1.Malformed("not a SEQUENCE") }
  field.items()
}

///|
pub extend RsaPublic with Eq::{equal, not_equal}

///|
pub extend RsaPrivate with Eq::{equal, not_equal}
