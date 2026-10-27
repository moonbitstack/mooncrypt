// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
/// RFC 8032 §7.1's TEST 1, TEST 2, TEST 3 and TEST SHA(abc), plus a 1023-byte
/// message — the last two run the hash past one and many SHA-512 blocks, which
/// is where a wrong length field would show.
test "Ed25519 matches RFC 8032" {
  let cases = [
    (
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "af82", "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
      "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42", "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
      "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
    (
      "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5", "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
      "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21466b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21466b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21466b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21466b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1",
      "21ce03fafbb2032a4609c6cdc48206790fbd9462dd18418e040d4eb690b5011b3fa5548d5382599ff673b0e627c7929465e347a67a5635746dc4250588e00702",
    ),
  ]
  for case in cases {
    let (seed, want_pub, msg, want_sig) = case
    let sk = @ed25519.PrivateKey::new(raw(seed)[:])
    assert_eq(@base16.encode(sk.public().bytes()), want_pub)
    assert_eq(@base16.encode(sk.sign(raw(msg)[:])), want_sig)
    let pk = @ed25519.PublicKey::new(raw(want_pub)[:])
    assert_true(pk.verify(raw(msg)[:], raw(want_sig)[:]))
  }
}

///|
/// A signature must not verify a different message, under a different key, or
/// with a single bit of itself flipped.
test "a signature does not verify what it did not sign" {
  let sk = @ed25519.PrivateKey::new(
    raw("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")[:],
  )
  let pk = sk.public()
  let sig = sk.sign(b"attack at dawn"[:])
  assert_true(pk.verify(b"attack at dawn"[:], sig[:]))
  assert_false(pk.verify(b"attack at dusk"[:], sig[:]))
  let other = @ed25519.PrivateKey::new(
    raw("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")[:],
  )
  assert_false(other.public().verify(b"attack at dawn"[:], sig[:]))
  for i in [0, 31, 32, 63] {
    let bent = sig.to_array()
    bent[i] = (bent[i].to_int() ^ 1).to_byte()
    assert_false(pk.verify(b"attack at dawn"[:], Bytes::from_array(bent)[:]))
  }
}

///|
/// A scalar at or above the group order would give one message two valid
/// signatures, so it is refused; so is a signature of the wrong length.
test "an out-of-range scalar is refused" {
  let sk = @ed25519.PrivateKey::new(
    raw("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")[:],
  )
  let pk = sk.public()
  let sig = sk.sign(b"hello"[:])
  let over = sig.to_array()
  // The order's top byte is 0x10, so 0xFF is far past it.
  over[63] = b'\xFF'
  assert_false(pk.verify(b"hello"[:], Bytes::from_array(over)[:]))
  assert_false(pk.verify(b"hello"[:], sig[0:63]))
}

///|
/// Keys are fixed-size, and anything else is a mistake worth naming.
test "a key of the wrong length is refused" {
  let short = raw("00112233")
  try @ed25519.PublicKey::new(short[:]) |> ignore catch {
    e => assert_eq(e, @spec.Size(want=32, got=4))
  } noraise {
    _ => fail("a four-byte public key was accepted")
  }
  try @ed25519.PrivateKey::new(short[:]) |> ignore catch {
    e => assert_eq(e, @spec.Size(want=32, got=4))
  } noraise {
    _ => fail("a four-byte seed was accepted")
  }
  assert_eq(@ed25519.key_size, 32)
  assert_eq(@ed25519.sig_size, 64)
}
