// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
fn unhex(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
fn ascii(s : String) -> Bytes {
  @moonbase.ascii(s)
}

///|
/// The private scalar, public point and signature of the worked example in
/// GB/T 32918.5-2017 §A.2, which is the example every SM2 implementation is
/// first measured against.
let example_d = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"

///|
let example_x = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"

///|
let example_y = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"

///|
let example_sig = "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"

///|
/// The scalar maps to the point the standard publishes, and the standard's
/// signature over "message digest" checks out — which exercises the curve
/// arithmetic, ZA, the digest and the verification equation in one go.
test "SM2 matches the GB/T 32918.5 example" {
  let sk = @sm2.PrivateKey::new(unhex(example_d)[:])
  let pk = sk.public()
  assert_eq(hex(pk.encode()), ("04" + example_x + example_y).to_lower())
  assert_eq(
    pk.verify_with(ascii("message digest")[:], unhex(example_sig)[:]),
    true,
  )
  // The identity is signed, so another one does not check out.
  assert_eq(
    pk.verify_with(
      ascii("message digest")[:],
      unhex(example_sig)[:],
      id=ascii("other")[:],
    ),
    false,
  )
  // Neither does another message.
  assert_eq(
    pk.verify_with(ascii("message digesT")[:], unhex(example_sig)[:]),
    false,
  )
}

///|
/// Signing is deterministic: the nonce comes from RFC 6979 over SM3, so the
/// same key and message give the same signature every time, and a signature
/// that changes is a change in the code rather than a change in entropy.
test "SM2 signs deterministically" {
  let sk = @sm2.PrivateKey::new(unhex(example_d)[:])
  let pk = sk.public()
  let sig = sk.sign_with(ascii("message digest")[:])
  assert_eq(
    hex(sig),
    "24858ee71d63e687feefe41f5af80a59f0791eb1dabc2bbe71daf0e57f06c3673d15550de52785a435004c937256ac715c0e04176ac57062c6722fa692f7a491",
  )
  assert_eq(hex(sk.sign_with(ascii("message digest")[:])), hex(sig))
  assert_eq(pk.verify_with(ascii("message digest")[:], sig[:]), true)
  assert_eq(pk.verify_with(ascii("message digest ")[:], sig[:]), false)
}

///|
/// A flipped bit anywhere in the signature is refused, and so is a signature
/// whose halves are out of range.
test "SM2 refuses a tampered signature" {
  let sk = @sm2.PrivateKey::new(unhex(example_d)[:])
  let pk = sk.public()
  let sig = sk.sign_with(b"the quick brown fox"[:])
  let bad : Bytes = Bytes::from_array(
    Array::make(64, 0).mapi(fn(i, _) {
      if i == 63 {
        (sig[i].to_int() ^ 1).to_byte()
      } else {
        sig[i]
      }
    }),
  )
  assert_eq(pk.verify_with(b"the quick brown fox"[:], bad[:]), false)
  let zero = Bytes::from_array(Array::make(64, b'\x00'))
  assert_eq(pk.verify_with(b"the quick brown fox"[:], zero[:]), false)
  assert_eq(pk.verify_with(b"the quick brown fox"[:], sig[0:63]), false)
}

///|
/// Both SEC 1 encodings are read, and a point that is not on the curve is
/// refused rather than used.
test "SM2 reads public keys" {
  let uncompressed = unhex("04" + example_x + example_y)
  let compressed = unhex("03" + example_x)
  assert_eq(
    hex(@sm2.PublicKey::new(compressed[:]).encode()),
    hex(@sm2.PublicKey::new(uncompressed[:]).encode()),
  )
  // A point one step off the curve.
  let off = unhex(
    "04" +
    example_x +
    "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD14",
  )
  try @sm2.PublicKey::new(off[:]) |> ignore catch {
    e => assert_eq(e, @spec.Weak)
  } noraise {
    _ => fail("a point off the curve was accepted")
  }
  try @sm2.PublicKey::new(unhex("0411")[:]) |> ignore catch {
    e => assert_eq(e, @spec.Size(want=65, got=2))
  } noraise {
    _ => fail("a two-byte public key was accepted")
  }
}

///|
/// Scalars are checked against the group order.
test "SM2 refuses a private key out of range" {
  let zero = Bytes::from_array(Array::make(32, b'\x00'))
  try @sm2.PrivateKey::new(zero[:]) |> ignore catch {
    e => assert_eq(e, @spec.Weak)
  } noraise {
    _ => fail("the zero scalar was accepted")
  }
  try @sm2.PrivateKey::new(unhex("FF")[:]) |> ignore catch {
    e => assert_eq(e, @spec.Size(want=32, got=1))
  } noraise {
    _ => fail("a one-byte private key was accepted")
  }
  let sk = @sm2.PrivateKey::new(unhex(example_d)[:])
  assert_eq(hex(sk.encode()), example_d.to_lower())
}

///|
/// The two contracts, so SM2 signs anywhere a `Signer` is expected.
test "SM2 satisfies the signing contracts" {
  let sk = @sm2.PrivateKey::new(unhex(example_d)[:])
  let signer : &@spec.Signer = sk
  let verifier : &@spec.Verifier = sk.public()
  let sig = signer.sign(b"payload"[:])
  assert_eq(verifier.verify(b"payload"[:], sig[:]), true)
  assert_eq(@sm2.default_id.length(), 16)
  assert_eq(@sm2.size, 32)
}
