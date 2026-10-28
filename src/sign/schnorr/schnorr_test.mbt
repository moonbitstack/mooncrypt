// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The vectors come from `scripts/gen_schnorr_vectors.py`, which signs with
// libsecp256k1 — the reference implementation of BIP 340 — and checks the first
// case against the published CSV before emitting anything.

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One signature: a key, the auxiliary input, a message and the result.
struct Case {
  sk : String
  pubkey : String
  aux : String
  msg : String
  sig : String
}

///|
/// The group order of secp256k1, which a signature's second half must be below.
let order : String = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

///|
/// The field prime, which a signature's first half must be below.
let prime : String = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"

///|
let cases : Array[Case] = [
  {
    sk: "0000000000000000000000000000000000000000000000000000000000000003",
    pubkey: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    aux: "0000000000000000000000000000000000000000000000000000000000000000",
    msg: "0000000000000000000000000000000000000000000000000000000000000000",
    sig: "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
  },
  {
    sk: "0000000000000000000000000000000000000000000000000000000000000003",
    pubkey: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    aux: "0000000000000000000000000000000000000000000000000000000000000000",
    msg: "0000000000000000000000000000000000000000000000000000000000000001",
    sig: "cc61a39980a0a6895a9895bd921a242faa7e7af19e3223a6a86b3588cb3efa0e953a3daebdb060ea76702bc68e433a16404f92386ed3038a76332a23990151ac",
  },
  {
    sk: "0000000000000000000000000000000000000000000000000000000000000001",
    pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    aux: "0000000000000000000000000000000000000000000000000000000000000000",
    msg: "13ecbb182cbb19f22107f009ed3a0eabb8140bfba054c74261fd82f5f52223e2",
    sig: "fc5b0a46a7c146f96909a461682fea32ebc0442389a3a3bddfb4854535486230f6b4af8bbb40a606ca16640f98544b2e751009ce788189a285c971c3814da9a2",
  },
  {
    sk: "0000000000000000000000000000000000000000000000000000000000000002",
    pubkey: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    aux: "0000000000000000000000000000000000000000000000000000000000000000",
    msg: "cf4dae45c66b3e807ccd69737967090a557d634ff11cce30d23de35aeade3790",
    sig: "44c678246fb78781ea3e6c3a6818d8c27ea5b8806edde686d7f74fee4e35eda53d359bf8a7eb5e81194bd0479ef448edfbefe2a6e4951a6aa8f65fe8e23ffc07",
  },
  {
    sk: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    aux: "0000000000000000000000000000000000000000000000000000000000000000",
    msg: "dbaf2e91e7548bca1d8c4606aa6cfb04422f18da3d094ab90acc1f264d406ce1",
    sig: "eaac6dc013d0f8e81c5cd5532d9205c1aeb2ccae95a6b97791e835892e8b4551761e9a62225bf93a631c101308e89e47444258321376f2a189520f00a6cba003",
  },
  {
    sk: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
    pubkey: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    aux: "b984265b9b0aa5962ff5b95f7588e65888ffdf85fa65ef79c4bfebfd01dce5aa",
    msg: "cd3da192417eb5525bdf36bab4c1c83d0cd767dd4ecc4cf618014f996d7cacd8",
    sig: "d0a1322d6fbbf60a835b412ddbc5340c0f6dd85ae90cbb42f36f5c60eded91725f4e833434337899f45bb51ed3c62e68a7c3046c8d65f2e2e8922316f6b84783",
  },
  {
    sk: "00837bbc6e40469e00f13f366d526550afce82d1cd497816baafc02488cafe87",
    pubkey: "d8c704edced6308f50b2e8efc5811ba897aab41fe53699598a8065b7fbb8eebf",
    aux: "6893acb4bfab19056378645ecdfa3b274cffd965af15d1a7a1ec59a02b1c4a9c",
    msg: "97313805b6cd56448c8255fed622702958cfe19a3bf17408ce31f922af2a90c2",
    sig: "995fd7d3c4fefb5b01266fdf7c6b2494e225a15b0cff418980026720846a907aecd450a7829f4aec5fd9e9ec9094299656147c10bf1f14ace1616ea45b43cf89",
  },
  {
    sk: "b395ad0cb844b16ecc47d06457f89a34c9373062e8af782c68e46c01eec02ae9",
    pubkey: "e9a988db1cf30813f0f055d4ba251d3d10440709d2eb45b0d6d741fa9c8cba13",
    aux: "959c8666853a0c263d76f2b80cd97a178883817dd5eeeb8a30b69026461a8915",
    msg: "2f68aee4f323751418a8e7eb9921684d1e91972f6fc91d92524b679a8f95a01a",
    sig: "7f70491898c0febe057fea03d4b7a13b56e670f154a34d48cbc5602b5d1574275ef3b5b2a0110cf75fa1b6948161bbfa352fd64acfa24437a9f1e13096fdcc07",
  },
  {
    sk: "bbd79a49311c40f4c093fe3c36e40b83553413d3308211aa07136f7cd0a8a19d",
    pubkey: "b22e36da4efccd6d22ba615ee5e6038063db9157526987c301322820abd19174",
    aux: "c7d509456895fa1a830ca156f985dbebb5c7cd2663c22cee2f83ecdf5e143265",
    msg: "74cfb931e4bfc653a184a6132c0f9b821fc45f6814fdcbc93f1f185450deced7",
    sig: "e31543b02d7f6bcb988c702909a542678e264eb38169e75a6fc9d919c7fb1d7e45d8be55cfe1f896e308094d80498da3468b843871d4d9f6fd910943dc07b338",
  },
  {
    sk: "50d68ba1359747e1edc9b4bd398b2904141fc3377ca657d7b5e44d658742aa14",
    pubkey: "7d7cf940dab09953267b20b86dde37fe5cc2caa1cb609a5f79e6336dc138b9fd",
    aux: "2747a03c76828819572e73c88a2723adab00a370798f176152ee5a95218f8eb4",
    msg: "46a2dfe52287bf8711809b3111f0474e28ee09b2e860c27981af2af4e53989ba",
    sig: "a8c629a5dcd5ed04d9d8f8dfe105d6cfb43d0c80963ed3bc66cbecba527fa37e2880874bb86caa5de08becb43a28805ee976f73177a3be0703479c2217aad8f7",
  },
  {
    sk: "3d7855316c0e8878f2181da71971d23a02de7c2d89daea0b67a1c896453ccc43",
    pubkey: "454756c8902f4f5a6e4286cf2f4abef4735778b65308eccf564a357972155c25",
    aux: "de231915de9d9fbc84e93f63fc2cce91eaca34dffc11cee0ca22296af7cd320d",
    msg: "5c43471a214b86e88fda7618194d4917248b7362aa93ac74306e4f20a03604b4",
    sig: "22162f1e6935d568d8086488ced0d7a86886b442d7402290d81265339218b741d41bc410f999b7e1ec9a7ddbd7fda0556fca7142fbb0cc9e985bd37e43c4fd71",
  },
  {
    sk: "414eb6258a1f861c7a102506817be49318b28c627471be5d4c7c3103941bdec8",
    pubkey: "ce8c6f24161a7be77ac855b97180bf8d51e89e73088c1c8745f876a6d89f9701",
    aux: "edfffeecb316a5c14d6fa14a51a1cd0ee90acf0fec619627aedcf3a7f623d3fd",
    msg: "1bdc9ad209df99485d1003bb51569ddc6846cd901e560b96d21ff3dcad6cdce2",
    sig: "d91d2f385e67fd3b72280fa0dd7f4277a681c30b18ca6e0ed5bc13b22828e4678751e433a01fd1557945504bb4a40f33a0b0ff42509c1bfcebf1d786a6596d71",
  },
]

///|
/// Every vector: the public key, the signature, and that the signature verifies.
///
/// The two halves are checked separately because they fail separately — a wrong
/// public key with a right signature is a parity bug, and a wrong signature with
/// a right key is a nonce bug.
test "bip 340 vectors" {
  assert_eq(cases.length(), 12)
  for case in cases {
    let key = @schnorr.PrivateKey::new(raw(case.sk)[:])
    let public = key.public()
    assert_eq(public.bytes(), raw(case.pubkey))
    let sig = key.sign_with(raw(case.msg)[:], aux=raw(case.aux)[:])
    assert_eq(sig, raw(case.sig))
    assert_eq(sig.length(), @schnorr.sig_size)
    assert_true(public.verify(raw(case.msg)[:], sig[:]))
  }
}

///|
/// The first vector is the one BIP 340 publishes, and it is worth seeing written
/// out: a key of three, no auxiliary randomness, and a message of zeroes.
test "the published vector" {
  let key = @schnorr.PrivateKey::new(raw(cases[0].sk)[:])
  assert_eq(
    key.public().bytes(),
    raw("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
  )
  assert_eq(
    key.sign(raw(cases[0].msg)[:]),
    raw(
      "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
    ),
  )
}

///|
/// Signing is deterministic, and the trait form is the same as signing with no
/// auxiliary randomness.
test "signing is deterministic" {
  // Case four is the one whose auxiliary input is already all zeroes.
  assert_eq(
    raw(cases[4].aux),
    raw("0000000000000000000000000000000000000000000000000000000000000000"),
  )
  let key = @schnorr.PrivateKey::new(raw(cases[4].sk)[:])
  let msg = raw(cases[4].msg)
  let zeros = raw(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  assert_eq(key.sign(msg[:]), key.sign(msg[:]))
  assert_eq(key.sign(msg[:]), key.sign_with(msg[:], aux=zeros[:]))
  assert_eq(key.sign_with(msg[:], aux=zeros[:]), raw(cases[4].sig))
}

///|
/// Auxiliary randomness changes the nonce and therefore the signature, while both
/// signatures still verify — that is what it is for.
test "auxiliary randomness changes the signature and not its validity" {
  let key = @schnorr.PrivateKey::new(raw(cases[0].sk)[:])
  let public = key.public()
  let msg = raw(cases[0].msg)
  let one = raw(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let two = raw(
    "0200000000000000000000000000000000000000000000000000000000000000",
  )
  let a = key.sign_with(msg[:], aux=one[:])
  let b = key.sign_with(msg[:], aux=two[:])
  assert_true(a != b)
  assert_true(public.verify(msg[:], a[:]))
  assert_true(public.verify(msg[:], b[:]))
}

///|
/// A message of any length signs and verifies, not only the 32-byte ones the
/// vectors use. BIP 340 hashes the message directly and puts no length on it.
test "a message of any length" {
  let key = @schnorr.PrivateKey::new(raw(cases[5].sk)[:])
  let public = key.public()
  let long = @utf8.encode(
    "the quick brown fox jumps over the lazy dog, and then keeps going",
  )
  for
    msg in [
      b""[:],
      b"a"[:],
      raw("0102030405")[:],
      raw(cases[5].msg)[:],
      long[:],
    ] {
    let sig = key.sign(msg)
    assert_eq(sig.length(), @schnorr.sig_size)
    assert_true(public.verify(msg, sig[:]))
  }
}

///|
/// A signature that does not verify is refused, in each of the ways one can fail.
test "a bad signature is refused" {
  let key = @schnorr.PrivateKey::new(raw(cases[0].sk)[:])
  let public = key.public()
  let msg = raw(cases[0].msg)
  let sig = raw(cases[0].sig)

  // A different message under the same signature.
  assert_false(
    public.verify(
      raw("0100000000000000000000000000000000000000000000000000000000000000")[:],
      sig[:],
    ),
  )
  // A flipped bit in each half.
  let flipped_r = raw(
      "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8216",
    ) +
    sig[32:64].to_owned()
  assert_false(public.verify(msg[:], flipped_r[:]))
  let flipped_s = sig[0:32].to_owned() +
    raw("25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c1")
  assert_false(public.verify(msg[:], flipped_s[:]))
  // The wrong length, one byte short and one over.
  assert_false(public.verify(msg[:], sig[0:63]))
  let longer : Array[Byte] = []
  for i in 0..<sig.length() {
    longer.push(sig[i])
  }
  longer.push(b'\x00')
  assert_false(public.verify(msg[:], Bytes::from_array(longer)[:]))
  // `s` at or above the group order is a second encoding of a signature that
  // this scheme does not admit.
  let big_s = sig[0:32].to_owned() + raw(order)
  assert_false(public.verify(msg[:], big_s[:]))
  // And `r` at or above the field prime is not an x coordinate.
  let big_r = raw(prime) + sig[32:64].to_owned()
  assert_false(public.verify(msg[:], big_r[:]))
  // A signature from a different key.
  let other = @schnorr.PrivateKey::new(raw(cases[5].sk)[:])
  assert_false(public.verify(msg[:], other.sign(msg[:])[:]))
}

///|
/// Keys that cannot exist are refused where they are read, not where they are
/// used: zero and the group order are not scalars, and most 32-byte strings are
/// not x coordinates of any point.
test "keys that cannot exist are refused" {
  let zero = raw(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  assert_true(refused_private(zero))
  assert_true(refused_private(raw(order)))
  // One and one below the order are both keys.
  assert_false(
    refused_private(
      raw("0000000000000000000000000000000000000000000000000000000000000001"),
    ),
  )
  assert_false(
    refused_private(
      raw("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"),
    ),
  )
  // An x coordinate at or above the field prime has no point.
  assert_true(refused_public(raw(prime)))
  // And about half of the small ones are not on the curve either, while some are.
  let mut on = 0
  let mut off = 0
  for i in 0..<16 {
    // The number `i`, as a 32-byte big-endian key.
    let cells : Array[Byte] = []
    for _ in 0..<31 {
      cells.push(b'\x00')
    }
    cells.push(i.to_byte())
    if refused_public(Bytes::from_array(cells)) {
      off = off + 1
    } else {
      on = on + 1
    }
  }
  assert_true(off > 0)
  assert_true(on > 0)
}

///|
fn refused_private(secret : Bytes) -> Bool {
  try {
    let _ = @schnorr.PrivateKey::new(secret[:])
    false
  } catch {
    _ => true
  }
}

///|
fn refused_public(raw_key : Bytes) -> Bool {
  try {
    let _ = @schnorr.PublicKey::new(raw_key[:])
    false
  } catch {
    _ => true
  }
}
