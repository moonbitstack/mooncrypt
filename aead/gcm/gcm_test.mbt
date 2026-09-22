// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
fn aes_gcm(key : String, tag? : Int = 16) -> @gcm.Gcm raise {
  @gcm.Gcm::new(@aes.Cipher::new(raw(key)[:]), tag~)
}

///|
/// The test cases from the GCM specification's own appendix B, which is where
/// every implementation's first bugs show: an empty message, an empty AAD, and
/// the full combination under all three key lengths.
test "the GCM specification's own test cases" {
  // Case 1: no plaintext, no associated data. The answer is a tag and nothing
  // else, which is where an implementation that mishandles empty input shows.
  let zero = aes_gcm("00000000000000000000000000000000")
  let nonce = raw("000000000000000000000000")
  assert_eq(
    @base16.encode(zero.seal(nonce=nonce[:], plain=b""[:])),
    "58e2fccefa7e3061367f1d57a4e7455a",
  )
  assert_eq(
    zero.open(nonce=nonce[:], cipher=raw("58e2fccefa7e3061367f1d57a4e7455a")[:]),
    b"",
  )
  // Case 2: one block of zeroes.
  assert_eq(
    @base16.encode(
      zero.seal(
        nonce=nonce[:],
        plain=raw("00000000000000000000000000000000")[:],
      ),
    ),
    "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
  )
  // Case 3: four whole blocks, still no associated data.
  let mode = aes_gcm("feffe9928665731c6d6a8f9467308308")
  let plain = raw(
    "d9313225f88406e5a55909c5aff5269a" +
    "86a7a9531534f7da2e4c303d8a318a72" +
    "1c3c0c95956809532fcf0e2449a6b525" +
    "b16aedf5aa0de657ba637b391aafd255",
  )
  let want = "42831ec2217774244b7221b784d0d49c" +
    "e3aa212f2c02a4e035c17e2329aca12e" +
    "21d514b25466931c7d8f6a5aac84aa05" +
    "1ba30b396a0aac973d58e091473f5985" +
    "4d5c2af327cd64a62cf35abd2ba6fab4"
  let made = mode.seal(nonce=raw("cafebabefacedbaddecaf888")[:], plain=plain[:])
  assert_eq(@base16.encode(made), want)
  assert_eq(
    mode.open(nonce=raw("cafebabefacedbaddecaf888")[:], cipher=made[:]),
    plain,
  )
}

///|
/// Case 4 of the same appendix, and the AES-192 and AES-256 versions of it: a
/// message that is not a whole number of blocks, with associated data.
test "a partial block with associated data, at all three key lengths" {
  let plain = raw(
    "d9313225f88406e5a55909c5aff5269a" +
    "86a7a9531534f7da2e4c303d8a318a72" +
    "1c3c0c95956809532fcf0e2449a6b525" +
    "b16aedf5aa0de657ba637b39",
  )
  let aad = raw("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let nonce = raw("cafebabefacedbaddecaf888")
  let cases = [
    (
      "feffe9928665731c6d6a8f9467308308",
      "42831ec2217774244b7221b784d0d49c" +
      "e3aa212f2c02a4e035c17e2329aca12e" +
      "21d514b25466931c7d8f6a5aac84aa05" +
      "1ba30b396a0aac973d58e091" +
      "5bc94fbc3221a5db94fae95ae7121a47",
    ),
    (
      "feffe9928665731c6d6a8f9467308308feffe9928665731c",
      "3980ca0b3c00e841eb06fac4872a2757" +
      "859e1ceaa6efd984628593b40ca1e19c" +
      "7d773d00c144c525ac619d18c84a3f47" +
      "18e2448b2fe324d9ccda2710" +
      "2519498e80f1478f37ba55bd6d27618c",
    ),
    (
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
      "522dc1f099567d07f47f37a32a84427d" +
      "643a8cdcbfe5c0c97598a2bd2555d1aa" +
      "8cb08e48590dbb3da7b08b1056828838" +
      "c5f61e6393ba7a0abcc9f662" +
      "76fc6ece0f4e1768cddf8853bb2d551b",
    ),
  ]
  for case in cases {
    let (key, want) = case
    let mode = aes_gcm(key)
    let made = mode.seal(nonce=nonce[:], plain=plain[:], aad=aad[:])
    assert_eq(@base16.encode(made), want)
    // And back out again, which is the half a vector table cannot check on its
    // own: sealing the right bytes is no use if opening them does not return.
    assert_eq(mode.open(nonce=nonce[:], cipher=made[:], aad=aad[:]), plain)
  }
}

///|
/// A nonce that is not 96 bits goes through GHASH instead of the cheap
/// construction. The specification allows any length, and an implementation that
/// only does 96 bits is the common shortcut.
test "a nonce of any length" {
  let mode = aes_gcm("feffe9928665731c6d6a8f9467308308")
  let plain = raw(
    "d9313225f88406e5a55909c5aff5269a" +
    "86a7a9531534f7da2e4c303d8a318a72" +
    "1c3c0c95956809532fcf0e2449a6b525" +
    "b16aedf5aa0de657ba637b39",
  )
  let aad = raw("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  // Case 5: a 64-bit nonce.
  let short = raw("cafebabefacedbad")
  assert_eq(
    @base16.encode(mode.seal(nonce=short[:], plain=plain[:], aad=aad[:])),
    "61353b4c2806934a777ff51fa22a4755" +
    "699b2a714fcdc6f83766e5f97b6c7423" +
    "73806900e49f24b22b097544d4896b42" +
    "4989b5e1ebac0f07c23f4598" +
    "3612d2e79e3b0785561be14aaca2fccb",
  )
  // Case 6: a 480-bit nonce.
  let long = raw(
    "9313225df88406e555909c5aff5269aa" +
    "6a7a9538534f7da1e4c303d2a318a728" +
    "c3c0c95156809539fcf0e2429a6b5254" +
    "16aedbf5a0de6a57a637b39b",
  )
  assert_eq(
    @base16.encode(mode.seal(nonce=long[:], plain=plain[:], aad=aad[:])),
    "8ce24998625615b603a033aca13fb894" +
    "be9112a5c3a211a8ba262a3cca7e2ca7" +
    "01e4a9a4fba43c90ccdcb281d48c7c6f" +
    "d62875d2aca417034c34aee5" +
    "619cc5aefffe0bfa462af43c1699d050",
  )
  // Every one of them round-trips.
  for nonce in [short, long, raw("cafebabefacedbaddecaf888")] {
    let made = mode.seal(nonce=nonce[:], plain=plain[:], aad=aad[:])
    assert_eq(mode.open(nonce=nonce[:], cipher=made[:], aad=aad[:]), plain)
  }
}

///|
/// A tag that does not match is refused, and refused as a tag failure rather
/// than as empty plaintext.
test "a tag that does not match is refused" {
  let mode = aes_gcm("feffe9928665731c6d6a8f9467308308")
  let nonce = raw("cafebabefacedbaddecaf888")
  let plain = raw("d9313225f88406e5a55909c5aff5269a")
  let aad = raw("feedfacedeadbeef")
  let made = mode.seal(nonce=nonce[:], plain=plain[:], aad=aad[:])
  assert_eq(mode.open(nonce=nonce[:], cipher=made[:], aad=aad[:]), plain)
  // A flipped bit anywhere: in the tag, in the ciphertext, in the AAD, in the
  // nonce. Each one has to fail.
  let bent = made.to_array()
  bent[bent.length() - 1] = (bent[bent.length() - 1].to_int() ^ 1).to_byte()
  let broken = Bytes::from_array(bent)
  try mode.open(nonce=nonce[:], cipher=broken[:], aad=aad[:]) |> ignore catch {
    e => assert_eq(e, @spec.Tag)
  } noraise {
    _ => fail("a flipped tag bit was accepted")
  }
  let bent = made.to_array()
  bent[0] = (bent[0].to_int() ^ 1).to_byte()
  let broken = Bytes::from_array(bent)
  try mode.open(nonce=nonce[:], cipher=broken[:], aad=aad[:]) |> ignore catch {
    e => assert_eq(e, @spec.Tag)
  } noraise {
    _ => fail("a flipped ciphertext bit was accepted")
  }
  try
    mode.open(nonce=nonce[:], cipher=made[:], aad=raw("feedfacedeadbeee")[:])
    |> ignore
  catch {
    e => assert_eq(e, @spec.Tag)
  } noraise {
    _ => fail("associated data that was not sealed was accepted")
  }
  try
    mode.open(
      nonce=raw("cafebabefacedbaddecaf889")[:],
      cipher=made[:],
      aad=aad[:],
    )
    |> ignore
  catch {
    e => assert_eq(e, @spec.Tag)
  } noraise {
    _ => fail("the wrong nonce was accepted")
  }
  // Something shorter than the tag cannot carry one.
  try
    mode.open(nonce=nonce[:], cipher=b"short"[:], aad=aad[:]) |> ignore
  catch {
    e => assert_eq(e, @spec.Size(want=16, got=5))
  } noraise {
    _ => fail("five bytes were read as a sealed message")
  }
}

///|
/// The tag length is a knob, because the specification defines seven of them and
/// picking a short one is a decision with a number attached.
test "the tag length is a knob" {
  let nonce = raw("cafebabefacedbaddecaf888")
  let plain = raw("d9313225f88406e5a55909c5aff5269a")
  let full = aes_gcm("feffe9928665731c6d6a8f9467308308")
  assert_eq(full.size(), 16)
  let made = full.seal(nonce=nonce[:], plain=plain[:])
  assert_eq(made.length(), plain.length() + 16)
  for n in [4, 8, 12, 13, 14, 15, 16] {
    let mode = aes_gcm("feffe9928665731c6d6a8f9467308308", tag=n)
    assert_eq(mode.size(), n)
    let short = mode.seal(nonce=nonce[:], plain=plain[:])
    assert_eq(short.length(), plain.length() + n)
    assert_eq(mode.open(nonce=nonce[:], cipher=short[:]), plain)
    // A shorter tag is the same bytes as the full one, cut.
    assert_eq(short[0:plain.length() + n], made[0:plain.length() + n])
  }
}

///|
test "panic a tag length the specification does not define" {
  aes_gcm("feffe9928665731c6d6a8f9467308308", tag=10) |> ignore
}

///|
/// The contract, so a caller can hold an AEAD without naming which one.
test "it satisfies the AEAD contract" {
  let mode : &@spec.Aead = aes_gcm("feffe9928665731c6d6a8f9467308308")
  let nonce = raw("cafebabefacedbaddecaf888")
  let plain = raw("d9313225f88406e5a55909c5aff5269a")
  let made = mode.seal(nonce=nonce[:], plain=plain[:], aad=b""[:])
  assert_eq(mode.open(nonce=nonce[:], cipher=made[:], aad=b""[:]), plain)
}
