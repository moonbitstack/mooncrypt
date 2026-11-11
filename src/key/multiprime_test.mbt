// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A key with a third prime, as the structure the reader is expected to give
/// back. The numbers are synthetic — they satisfy the shape of the format and
/// nothing more, because what is under test here is the encoding, not the
/// arithmetic.
///
/// `n = p·q·r` for three small primes is enough: a reader that recomposes a
/// modulus from the wrong fields, or a writer that drops `otherPrimeInfos`,
/// fails on any numbers at all.
fn multi_key() -> (@key.RsaPrivate, Array[@key.OtherPrime]) {
  let key : @key.RsaPrivate = {
    modulus: 61N * 53N * 47N,
    public_exponent: 17N,
    private_exponent: 2753N,
    prime1: 61N,
    prime2: 53N,
    exponent1: 53N,
    exponent2: 13N,
    coefficient: 38N,
  }
  (key, [{ prime: 47N, exponent: 11N, coefficient: 3N, }])
}

///|
test "a version-1 PKCS#1 key round-trips through its other primes" {
  let (key, others) = multi_key()
  let der = @key.rsa_private_multi_der(key, others)
  let (back, extra) = @key.parse_rsa_private_multi(der[:])
  assert_eq(back == key, true)
  assert_eq(extra == others, true)
  // The plain reader refuses it rather than answering with the first two primes,
  // which would be a key that signs to the wrong modulus.
  let refused = try {
    let _ = @key.parse_rsa_private(der[:])
    false
  } catch {
    @asn1.Unsupported(_) => true
    _ => false
  }
  assert_eq(refused, true)
}

///|
test "a two-prime key written by the multi-prime writer is the same bytes" {
  let (key, _) = multi_key()
  assert_eq(@key.rsa_private_multi_der(key, []), @key.rsa_private_der(key))
}

///|
test "a version that disagrees with the primes is refused" {
  let (key, others) = multi_key()
  // No `otherPrimeInfos` at all, but the version says there are.
  let nine = @asn1.sequence([
    @asn1.integer(b"\x01"),
    @asn1.integer(key.modulus.to_octets()),
    @asn1.integer(key.public_exponent.to_octets()),
    @asn1.integer(key.private_exponent.to_octets()),
    @asn1.integer(key.prime1.to_octets()),
    @asn1.integer(key.prime2.to_octets()),
    @asn1.integer(key.exponent1.to_octets()),
    @asn1.integer(key.exponent2.to_octets()),
    @asn1.integer(key.coefficient.to_octets()),
  ])
  let missing = try {
    let _ = @key.parse_rsa_private_multi(nine[:])
    false
  } catch {
    @asn1.Malformed(_) => true
    _ => false
  }
  assert_eq(missing, true)
  // Ten fields, but the version says the key has only its first two primes.
  let ten = @asn1.sequence([
    @asn1.integer(b"\x00"),
    @asn1.integer(key.modulus.to_octets()),
    @asn1.integer(key.public_exponent.to_octets()),
    @asn1.integer(key.private_exponent.to_octets()),
    @asn1.integer(key.prime1.to_octets()),
    @asn1.integer(key.prime2.to_octets()),
    @asn1.integer(key.exponent1.to_octets()),
    @asn1.integer(key.exponent2.to_octets()),
    @asn1.integer(key.coefficient.to_octets()),
    @asn1.sequence([
      @asn1.sequence([
        @asn1.integer(others[0].prime.to_octets()),
        @asn1.integer(others[0].exponent.to_octets()),
        @asn1.integer(others[0].coefficient.to_octets()),
      ]),
    ]),
  ])
  let extra = try {
    let _ = @key.parse_rsa_private_multi(ten[:])
    false
  } catch {
    @asn1.Malformed(_) => true
    _ => false
  }
  assert_eq(extra, true)
}
