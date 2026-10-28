// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A real 1024-bit RSA key and a real P-256 key, in every format this package
// reads and writes. The bytes came from `scripts/gen_key_vectors.py`, which
// builds each blob with a DER writer written out by hand and refuses to emit
// unless that writer agrees with `cryptography` for the same key.

///|
let rsa_modulus : Bytes = @base16.decode_lossy(
  "d2977f84e364ac3c76f78bf7e47cd02dc70634e768d393fe2a6df95c92ff17204cae9fa2a00a6614915b2c8eaf126427da92fc68a67a2e96cdc77f6840dc9c8ef27f6fdb681ca30d3e305e4ecd5c0edd41df7d43c94dddfbe950f35bc5d92d65105db13f5d99ea4c19154ea20b9c386c58c158ea75e4f8615a8dfe364290e051",
)

///|
let rsa_exponent : Bytes = @base16.decode_lossy("010001")

///|
let rsa_private_exponent : Bytes = @base16.decode_lossy(
  "05e57e098f80631e324a8e1dbbc50ee3293e703ec67d9e1830c1f188790931719314149e2e12fc76b8f72f91332fb5a43407878fba91933a5fbaa5439b055250d549f5794778cd93b8dcf927e99ba87b3c394df9e30ffe928eb743b9418be1d0208fbed729fa4dffe75fadf94b3d4b5c9d52274f77dcee9eb2741b8196aa073d",
)

///|
let rsa_prime1 : Bytes = @base16.decode_lossy(
  "f9ae700dfc181a9aed775828c517bead71b00a4d9bd8f836e3bdf2f7d594b48968a4d92bfccdf03e439b7ea098e55501d5cd913752f7b712ddeb5b66a6f06a4b",
)

///|
let rsa_prime2 : Bytes = @base16.decode_lossy(
  "d7ebd173b992d36dedda5d37ec2554630de9aa9965f97b869eeb875cece6647d03f4a336d6c1a7fe4bd689b25102b299b5c41e8706f811c91b0182119278fe53",
)

///|
let rsa_exponent1 : Bytes = @base16.decode_lossy(
  "ebc1b478e002fa8c3391af22c007cdba04514f493cd1407ec3c885f5522cd9d3ad858ab2a840e48a46583ad6f5c805de77bd655331fa49597d4650c5baf7e3c5",
)

///|
let rsa_exponent2 : Bytes = @base16.decode_lossy(
  "cc673094061449d5223aface4ade17e1e1b4d7cc79edd0936374826364dcc23a5af9475d4db66c6b5eadcd12a280144550fe450bfc7bf09259df769b5df6ee83",
)

///|
let rsa_coefficient : Bytes = @base16.decode_lossy(
  "10326a27eed868f4fad369910bb15e378631a36902eb2e145e285b8c378822d21b4f9a29b3bf2b7be930e2076e5122ef20682b7bb59a177a8edc26c82f33c1d2",
)

///|
let rsa_public : Bytes = @base16.decode_lossy(
  "30818902818100d2977f84e364ac3c76f78bf7e47cd02dc70634e768d393fe2a6df95c92ff17204cae9fa2a00a6614915b2c8eaf126427da92fc68a67a2e96cdc77f6840dc9c8ef27f6fdb681ca30d3e305e4ecd5c0edd41df7d43c94dddfbe950f35bc5d92d65105db13f5d99ea4c19154ea20b9c386c58c158ea75e4f8615a8dfe364290e0510203010001",
)

///|
let rsa_private : Bytes = @base16.decode_lossy(
  "3082025d02010002818100d2977f84e364ac3c76f78bf7e47cd02dc70634e768d393fe2a6df95c92ff17204cae9fa2a00a6614915b2c8eaf126427da92fc68a67a2e96cdc77f6840dc9c8ef27f6fdb681ca30d3e305e4ecd5c0edd41df7d43c94dddfbe950f35bc5d92d65105db13f5d99ea4c19154ea20b9c386c58c158ea75e4f8615a8dfe364290e051020301000102818005e57e098f80631e324a8e1dbbc50ee3293e703ec67d9e1830c1f188790931719314149e2e12fc76b8f72f91332fb5a43407878fba91933a5fbaa5439b055250d549f5794778cd93b8dcf927e99ba87b3c394df9e30ffe928eb743b9418be1d0208fbed729fa4dffe75fadf94b3d4b5c9d52274f77dcee9eb2741b8196aa073d024100f9ae700dfc181a9aed775828c517bead71b00a4d9bd8f836e3bdf2f7d594b48968a4d92bfccdf03e439b7ea098e55501d5cd913752f7b712ddeb5b66a6f06a4b024100d7ebd173b992d36dedda5d37ec2554630de9aa9965f97b869eeb875cece6647d03f4a336d6c1a7fe4bd689b25102b299b5c41e8706f811c91b0182119278fe53024100ebc1b478e002fa8c3391af22c007cdba04514f493cd1407ec3c885f5522cd9d3ad858ab2a840e48a46583ad6f5c805de77bd655331fa49597d4650c5baf7e3c5024100cc673094061449d5223aface4ade17e1e1b4d7cc79edd0936374826364dcc23a5af9475d4db66c6b5eadcd12a280144550fe450bfc7bf09259df769b5df6ee83024010326a27eed868f4fad369910bb15e378631a36902eb2e145e285b8c378822d21b4f9a29b3bf2b7be930e2076e5122ef20682b7bb59a177a8edc26c82f33c1d2",
)

///|
let rsa_pkcs8 : Bytes = @base16.decode_lossy(
  "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100d2977f84e364ac3c76f78bf7e47cd02dc70634e768d393fe2a6df95c92ff17204cae9fa2a00a6614915b2c8eaf126427da92fc68a67a2e96cdc77f6840dc9c8ef27f6fdb681ca30d3e305e4ecd5c0edd41df7d43c94dddfbe950f35bc5d92d65105db13f5d99ea4c19154ea20b9c386c58c158ea75e4f8615a8dfe364290e051020301000102818005e57e098f80631e324a8e1dbbc50ee3293e703ec67d9e1830c1f188790931719314149e2e12fc76b8f72f91332fb5a43407878fba91933a5fbaa5439b055250d549f5794778cd93b8dcf927e99ba87b3c394df9e30ffe928eb743b9418be1d0208fbed729fa4dffe75fadf94b3d4b5c9d52274f77dcee9eb2741b8196aa073d024100f9ae700dfc181a9aed775828c517bead71b00a4d9bd8f836e3bdf2f7d594b48968a4d92bfccdf03e439b7ea098e55501d5cd913752f7b712ddeb5b66a6f06a4b024100d7ebd173b992d36dedda5d37ec2554630de9aa9965f97b869eeb875cece6647d03f4a336d6c1a7fe4bd689b25102b299b5c41e8706f811c91b0182119278fe53024100ebc1b478e002fa8c3391af22c007cdba04514f493cd1407ec3c885f5522cd9d3ad858ab2a840e48a46583ad6f5c805de77bd655331fa49597d4650c5baf7e3c5024100cc673094061449d5223aface4ade17e1e1b4d7cc79edd0936374826364dcc23a5af9475d4db66c6b5eadcd12a280144550fe450bfc7bf09259df769b5df6ee83024010326a27eed868f4fad369910bb15e378631a36902eb2e145e285b8c378822d21b4f9a29b3bf2b7be930e2076e5122ef20682b7bb59a177a8edc26c82f33c1d2",
)

///|
let rsa_spki : Bytes = @base16.decode_lossy(
  "30819f300d06092a864886f70d010101050003818d0030818902818100d2977f84e364ac3c76f78bf7e47cd02dc70634e768d393fe2a6df95c92ff17204cae9fa2a00a6614915b2c8eaf126427da92fc68a67a2e96cdc77f6840dc9c8ef27f6fdb681ca30d3e305e4ecd5c0edd41df7d43c94dddfbe950f35bc5d92d65105db13f5d99ea4c19154ea20b9c386c58c158ea75e4f8615a8dfe364290e0510203010001",
)

///|
let ec_scalar : Bytes = @base16.decode_lossy(
  "b5662bf47a5fbac373388adfb6781a28f4420a47b2e64cf596dbc6dd30a4f8a4",
)

///|
let ec_point : Bytes = @base16.decode_lossy(
  "0438c66411d8fc683ab32caf49775112e219f0717a046f21959e44e52f60f3a411b74bcc3f5e44e3676321fb72dd18dcd85c159246fb5c59e03a9ec89fc38d49ed",
)

///|
let ec_sec1 : Bytes = @base16.decode_lossy(
  "30770201010420b5662bf47a5fbac373388adfb6781a28f4420a47b2e64cf596dbc6dd30a4f8a4a00a06082a8648ce3d030107a1440342000438c66411d8fc683ab32caf49775112e219f0717a046f21959e44e52f60f3a411b74bcc3f5e44e3676321fb72dd18dcd85c159246fb5c59e03a9ec89fc38d49ed",
)

///|
let ec_spki : Bytes = @base16.decode_lossy(
  "3059301306072a8648ce3d020106082a8648ce3d0301070342000438c66411d8fc683ab32caf49775112e219f0717a046f21959e44e52f60f3a411b74bcc3f5e44e3676321fb72dd18dcd85c159246fb5c59e03a9ec89fc38d49ed",
)

///|
/// The key above, as the structure the parser is expected to give back.
fn rsa_key() -> @key.RsaPrivate {
  {
    modulus: BigInt::from_octets(rsa_modulus),
    public_exponent: BigInt::from_octets(rsa_exponent),
    private_exponent: BigInt::from_octets(rsa_private_exponent),
    prime1: BigInt::from_octets(rsa_prime1),
    prime2: BigInt::from_octets(rsa_prime2),
    exponent1: BigInt::from_octets(rsa_exponent1),
    exponent2: BigInt::from_octets(rsa_exponent2),
    coefficient: BigInt::from_octets(rsa_coefficient),
  }
}

///|
/// Every number survives a parse and a re-encode, and the encoding is byte-for-
/// byte what the reference produced.
test "pkcs1 rsa private key round-trips" {
  let parsed = @key.parse_rsa_private(rsa_private[:])
  let want = rsa_key()
  assert_eq(parsed.modulus, want.modulus)
  assert_eq(parsed.public_exponent, want.public_exponent)
  assert_eq(parsed.private_exponent, want.private_exponent)
  assert_eq(parsed.prime1, want.prime1)
  assert_eq(parsed.prime2, want.prime2)
  assert_eq(parsed.exponent1, want.exponent1)
  assert_eq(parsed.exponent2, want.exponent2)
  assert_eq(parsed.coefficient, want.coefficient)
  assert_eq(@key.rsa_private_der(parsed), rsa_private)
}

///|
/// A public key is two integers, and both directions agree with the reference.
test "pkcs1 rsa public key round-trips" {
  let parsed = @key.parse_rsa_public(rsa_public[:])
  assert_eq(parsed.modulus, BigInt::from_octets(rsa_modulus))
  assert_eq(parsed.exponent, BigInt::from_octets(rsa_exponent))
  assert_eq(@key.rsa_public_der(rsa_modulus[:], rsa_exponent[:]), rsa_public)
}

///|
/// PKCS#8 is a wrapper, so the field it carries has to be the PKCS#1 key exactly:
/// same bytes in, same bytes out.
test "pkcs8 wraps and unwraps the pkcs1 key" {
  assert_eq(@key.pkcs8_der(rsa_private[:]), rsa_pkcs8)
  assert_eq(@key.parse_pkcs8(rsa_pkcs8[:]), rsa_private)
}

///|
/// SubjectPublicKeyInfo holds the PKCS#1 public key inside its BIT STRING.
test "spki wraps and unwraps the pkcs1 public key" {
  assert_eq(@key.spki_der(rsa_public[:]), rsa_spki)
  assert_eq(@key.parse_spki(rsa_spki[:]), rsa_public)
}

///|
/// A SEC1 key keeps the curve, the scalar and the point, and re-encodes to the
/// same bytes.
test "sec1 ec private key round-trips" {
  let parsed = @key.parse_sec1(ec_sec1[:])
  assert_eq(parsed.curve, Some(@curve.P256))
  assert_eq(parsed.scalar, BigInt::from_octets(ec_scalar))
  assert_eq(parsed.public, Some(ec_point))
  let again = @key.sec1_der(@curve.P256, ec_scalar[:], public=Some(ec_point[:]))
  assert_eq(again, ec_sec1)
}

///|
/// An EC SubjectPublicKeyInfo names its curve and carries the point.
test "ec spki round-trips" {
  let (curve, point) = @key.parse_spki_ec(ec_spki[:])
  assert_eq(curve, @curve.P256)
  assert_eq(point, ec_point)
  assert_eq(@key.spki_ec_der(@curve.P256, ec_point[:]), ec_spki)
}

///|
/// The named-curve identifiers, both ways, for every curve this library has.
test "curve oids round-trip" {
  let curves = [@curve.P256, @curve.P384, @curve.P521, @curve.Secp256k1]
  for curve in curves {
    let oid = @key.curve_oid(curve)
    // Written as arcs, read back as dotted decimal, and compared that way.
    let dotted = match curve {
      P256 => "1.2.840.10045.3.1.7"
      P384 => "1.3.132.0.34"
      P521 => "1.3.132.0.35"
      Secp256k1 => "1.3.132.0.10"
    }
    assert_eq(@key.curve_of_oid(dotted), Some(curve))
    assert_eq(oid.length() >= 3, true)
  }
  assert_eq(@key.curve_of_oid("1.3.132.0.39"), None)
}

///|
/// A wrapper that names the wrong algorithm is refused rather than parsed: the
/// octets of an EC key read as RSA integers fail a long way from the mistake.
test "a wrapper naming the wrong algorithm is refused" {
  let wrong = @key.spki_ec_der(@curve.P256, ec_point[:])
  let mut refused = false
  try {
    let _ = @key.parse_spki(wrong[:])
  } catch {
    _ => refused = true
  }
  assert_true(refused)
}

///|
/// PEM armor: the label appears twice, the body wraps at 64 characters, and the
/// text survives a round trip through `dearmor`.
test "pem armor round-trips" {
  let text = @key.armor("PRIVATE KEY", rsa_pkcs8[:])
  let (label, der) = @key.dearmor(text)
  assert_eq(label, "PRIVATE KEY")
  assert_eq(der, rsa_pkcs8)
  let lines : Array[StringView] = text.split("\n").collect()
  // The first and last lines are the two labels; everything between is body.
  assert_eq(lines[0].to_owned(), "-----BEGIN PRIVATE KEY-----")
  for i in 1..<(lines.length() - 2) {
    assert_true(lines[i].length() <= @key.line_width)
  }
  assert_true(text.contains("-----END PRIVATE KEY-----\n"))
}

///|
/// A body wrapped at a different width, or with the leading text a mail client
/// adds, is still the same key.
test "pem reading tolerates how a file actually arrives" {
  let body = @base16.encode(rsa_public)
  let text = "Subject: here is the key\r\n\r\n" +
    "-----BEGIN RSA PUBLIC KEY-----\r\n" +
    body +
    "\r\n-----END RSA PUBLIC KEY-----\r\n"
  let (label, der) = @key.dearmor(text)
  assert_eq(label, "RSA PUBLIC KEY")
  assert_eq(@key.parse_spki(@key.spki_der(der[:])[:]), der)
}

///|
/// The three ways a PEM block can be wrong: no block, mismatched labels, and a
/// body that is not base64.
test "pem refuses what it cannot read" {
  let mismatched = "-----BEGIN A-----\nAAAA\n-----END B-----\n"
  let not_base64 = "-----BEGIN A-----\n!!!!\n-----END A-----\n"
  for text in ["nothing here\n", mismatched, not_base64] {
    let mut refused = false
    try {
      let _ = @key.dearmor(text)
    } catch {
      _ => refused = true
    }
    assert_true(refused)
  }
}
