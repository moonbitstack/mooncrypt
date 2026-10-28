// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn unhex(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
fn hx(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// A fresh AES cipher for a key of the given length.
fn aes(key : BytesView) -> @aes.Cipher {
  try @aes.Cipher::new(key) catch {
    _ => abort("bad test key")
  } noraise {
    cipher => cipher
  }
}

///|
/// A copy of `data` with one bit flipped, for the tamper tests.
fn flip(data : BytesView, at : Int32) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(data.length(), b'\x00')
  for i in 0..<data.length() {
    out[i] = data[i]
  }
  out[at] = (out[at].to_int() ^ 0x01).to_byte()
  Bytes::from_array(out)
}

///|
/// One case: a master key, the associated data components before the nonce, the
/// nonce, the plaintext and the synthetic IV followed by the ciphertext.
struct Case {
  key : String
  ads : Array[String]
  nonce : String
  plain : String
  expected : String
}

///|
/// The two vectors from RFC 5297 appendix A, then cases the reference in
/// `scripts/gen_siv_vectors.py` produced for the shapes they do not cover: an
/// empty message, a message of exactly one block and one byte past it, four
/// associated data components (one of them empty), an associated data string
/// spanning several blocks, and keys of all three AES sizes.
///
/// The reference is a from-scratch implementation and the script refuses to emit
/// anything unless it reproduces appendix A, so this table cannot drift silently.
let cases : Array[Case] = [
  {
    // RFC 5297 A.1: no nonce, one associated data component of two
    // blocks, and a plaintext that is not a whole number of blocks.
    key: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    ads: ["101112131415161718191a1b1c1d1e1f2021222324252627"],
    nonce: "",
    plain: "112233445566778899aabbccddee",
    expected: "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c",
  },
  {
    // RFC 5297 A.2: the nonce is the last associated data component, so
    // it changes the SIV without appearing in the ciphertext.
    key: "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
    ads: [
      "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
      "102030405060708090a0",
    ],
    nonce: "09f911029d74e35bd84156c5635688c0",
    plain: "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
    expected: "7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d",
  },
  {
    // An empty message with no associated data, which is the shortest
    // input S2V can be given.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ads: [],
    nonce: "",
    plain: "",
    expected: "6890e5685ed0253753a2121dab850fdf",
  },
  {
    // An empty message that still has associated data, so the tag
    // commits to something.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ads: ["a0a1a2a3a4a5a6a7"],
    nonce: "",
    plain: "",
    expected: "0b6f26eb1d2380c415d77e353aa04074",
  },
  {
    // Exactly one block of plaintext, which is the boundary between the
    // two arms of `len(Sn) >= 128` in S2V.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ads: ["cafebabe"],
    nonce: "",
    plain: "00112233445566778899aabbccddeeff",
    expected: "34a4cc7b44ed4da57037bda376df9a99cd8bce5a658126cf3af530ec6d52c78d",
  },
  {
    // One byte past that boundary.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ads: ["cafebabe"],
    nonce: "",
    plain: "00112233445566778899aabbccddeeff00",
    expected: "a064690c395a20c9fd7218d1621c1ca20b5d5b284021662b563c4bcde79b43326f",
  },
  {
    // Four associated data components, more than the two RFC 5297
    // exercises, so the doubling chain is walked further. One of them
    // is empty.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ads: ["deadbeef", "", "0badc0de", "00112233445566778899aabbccddeeff"],
    nonce: "",
    plain: "48656c6c6f2c2053495621",
    expected: "e6d3878d49712a5c2116a26e1329d1da0f1919ecf4921f23188bb5",
  },
  {
    // Associated data long enough to need several blocks, with a
    // nonce and a plaintext that is not aligned.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ads: [
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    ],
    nonce: "f0f1f2f3f4f5",
    plain: "48656c6c6f2c2053495621",
    expected: "149f91ccd3d594a43d3a66e3553a33a857c8c3c0b98c1f5a9ac13f",
  },
  {
    // A 192-bit key, so both halves are AES-192.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    ads: ["a1b2c3"],
    nonce: "0102030405060708090a0b0c",
    plain: "00112233445566778899aabbccddeeff",
    expected: "77af786b8ee388a592b8d0d0dac660f2bbc957d517a937dc83320143b6c954d4",
  },
  {
    // A 512-bit key, so both halves are AES-256.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    ads: ["a1b2c3"],
    nonce: "0102030405060708090a0b0c",
    plain: "00112233445566778899aabbccddeeff",
    expected: "8c0c65015a12478686aa280fc834476121e3d49133120ce653156b5ac811bb74",
  },
  {
    // A message several blocks long, so the counter carries past a block
    // boundary.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ads: ["ad"],
    nonce: "",
    plain: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
    expected: "e1815a8a1d0df47253678e70dca346ba568a445c1813919719b11777ff887d0c5d2ccbd21117aee60a8460186a25403e0f9a9f6691a589befbc5b452c69d7689271a8f9a3b8a6bad",
  },
]

///|
/// The associated data of a case, kept alive as `Bytes` so the views into it
/// outlive the call.
fn ads_of(case : Case) -> (Array[Bytes], Array[BytesView]) {
  let owned : Array[Bytes] = []
  for text in case.ads {
    owned.push(unhex(text))
  }
  let views : Array[BytesView] = []
  for data in owned {
    views.push(data[:])
  }
  (owned, views)
}

///|
/// Every case: the synthetic IV and ciphertext match the reference, and opening
/// gives the plaintext back.
test "siv matches the reference and round-trips" {
  for case in cases {
    let (k1, k2) = try @siv.halves(unhex(case.key)[:]) catch {
      _ => abort("bad test key")
    } noraise {
      pair => pair
    }
    let mac = aes(k1[:])
    let ctr = aes(k2[:])
    let mode = try @siv.Siv::new(mac, ctr) catch {
      _ => abort("bad block size")
    } noraise {
      mode => mode
    }
    let (_, ads) = ads_of(case)
    let nonce = unhex(case.nonce)
    let plain = unhex(case.plain)
    let box = mode.seal_with(plain[:], ads, nonce=nonce[:])
    assert_eq(hx(box), case.expected)
    assert_eq(hx(mode.open_with(box[:], ads, nonce=nonce[:])), case.plain)
  }
}

///|
/// The one-string form agrees with the vector form over a single component, and
/// the trait form agrees with both.
test "siv agrees with itself across the three call shapes" {
  let (k1, k2) = try
    @siv.halves(
      unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")[:],
    )
  catch {
    _ => abort("bad key")
  } noraise {
    pair => pair
  }
  let mac = aes(k1[:])
  let ctr = aes(k2[:])
  let mode = try @siv.Siv::new(mac, ctr) catch {
    _ => abort("bad block size")
  } noraise {
    mode => mode
  }
  let plain = unhex("48656c6c6f2c2053495621")
  let aad = unhex("cafebabe")
  let nonce = unhex("0102030405")
  let one = mode.seal(nonce=nonce[:], plain=plain[:], aad=aad[:])
  let many = mode.seal_with(plain[:], [aad[:]], nonce=nonce[:])
  assert_eq(hx(one), hx(many))
  let via_trait = @spec.Aead::seal(
    mode,
    nonce=nonce[:],
    plain=plain[:],
    aad=aad[:],
  )
  assert_eq(hx(via_trait), hx(one))
  assert_eq(
    hx(@spec.Aead::open(mode, nonce=nonce[:], cipher=via_trait[:], aad=aad[:])),
    hx(plain[:]),
  )
  assert_eq(mode.size(), 16)
}

///|
/// Sealing the same message twice gives the same bytes. That is the property SIV
/// is chosen for: without a nonce it is deterministic, and deterministic
/// encryption is safe here because the IV commits to the whole message.
test "siv is deterministic" {
  let (k1, k2) = try
    @siv.halves(
      unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")[:],
    )
  catch {
    _ => abort("bad key")
  } noraise {
    pair => pair
  }
  let mac = aes(k1[:])
  let ctr = aes(k2[:])
  let mode = try @siv.Siv::new(mac, ctr) catch {
    _ => abort("bad block size")
  } noraise {
    mode => mode
  }
  let plain = unhex("48656c6c6f2c2053495621")
  assert_eq(
    hx(mode.seal(nonce=b""[:], plain=plain[:])),
    hx(mode.seal(nonce=b""[:], plain=plain[:])),
  )
  // A nonce, on the other hand, makes the same message look different.
  let a = mode.seal(nonce=b"\x01"[:], plain=plain[:])
  let b = mode.seal(nonce=b"\x02"[:], plain=plain[:])
  assert_true(a[:] != b[:])
  assert_eq(hx(mode.open(nonce=b"\x01"[:], cipher=a[:])), hx(plain[:]))
}

///|
/// Where a component sits in the vector is part of what it commits to, so
/// swapping two components, joining them, or splitting one in two all change the
/// IV. This is the property that makes SIV usable for structured data.
test "siv separates components that a concatenation would not" {
  let (k1, k2) = try
    @siv.halves(
      unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")[:],
    )
  catch {
    _ => abort("bad key")
  } noraise {
    pair => pair
  }
  let mac = aes(k1[:])
  let ctr = aes(k2[:])
  let mode = try @siv.Siv::new(mac, ctr) catch {
    _ => abort("bad block size")
  } noraise {
    mode => mode
  }
  let plain = unhex("00")
  let ab = mode.seal_with(plain[:], [b"a"[:], b"b"[:]])
  let ba = mode.seal_with(plain[:], [b"b"[:], b"a"[:]])
  let joined = mode.seal_with(plain[:], [b"ab"[:]])
  let single = mode.seal_with(plain[:], [b"a"[:]])
  assert_true(ab[:] != ba[:])
  assert_true(ab[:] != joined[:])
  assert_true(ab[:] != single[:])
  // Each one still opens with the vector it was sealed with.
  assert_eq(hx(mode.open_with(ab[:], [b"a"[:], b"b"[:]])), hx(plain[:]))
  let mut refused = false
  try {
    let _ = mode.open_with(ab[:], [b"b"[:], b"a"[:]])
  } catch {
    @spec.Broken::Tag => refused = true
    _ => fail("expected a tag error")
  }
  assert_true(refused)
}

///|
/// A modified synthetic IV, ciphertext, associated data or nonce fails to open,
/// and so does anything shorter than an IV.
test "siv refuses anything that was changed" {
  let (k1, k2) = try
    @siv.halves(
      unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")[:],
    )
  catch {
    _ => abort("bad key")
  } noraise {
    pair => pair
  }
  let mac = aes(k1[:])
  let ctr = aes(k2[:])
  let mode = try @siv.Siv::new(mac, ctr) catch {
    _ => abort("bad block size")
  } noraise {
    mode => mode
  }
  let plain = unhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let aad = unhex("cafebabe")
  let nonce = unhex("0102030405")
  let box = mode.seal(nonce=nonce[:], plain=plain[:], aad=aad[:])
  for at in [0, 3, 16, 20, 45] {
    let broken = flip(box[:], at)
    let mut refused = false
    try {
      let _ = mode.open(nonce=nonce[:], cipher=broken[:], aad=aad[:])
    } catch {
      @spec.Broken::Tag => refused = true
      _ => fail("expected a tag error")
    }
    assert_true(refused)
  }
  let mut wrong_aad = false
  try {
    let _ = mode.open(nonce=nonce[:], cipher=box[:], aad=unhex("cafebabc")[:])
  } catch {
    @spec.Broken::Tag => wrong_aad = true
    _ => fail("expected a tag error")
  }
  assert_true(wrong_aad)
  let mut wrong_nonce = false
  try {
    let _ = mode.open(nonce=unhex("0102030406")[:], cipher=box[:], aad=aad[:])
  } catch {
    @spec.Broken::Tag => wrong_nonce = true
    _ => fail("expected a tag error")
  }
  assert_true(wrong_nonce)
  let mut short = false
  try {
    let _ = mode.open(nonce=nonce[:], cipher=box[0:8], aad=aad[:])
  } catch {
    @spec.Broken::Size(..) => short = true
    _ => fail("expected a size error")
  }
  assert_true(short)
}

///|
/// SIV is defined on 128-bit block ciphers only, and a key that does not split
/// into two equal halves is refused rather than padded.
test "siv refuses a key or a block size it cannot use" {
  let odd = "000102030405060708090a0b0c0d0e0f10"
  let mut refused = false
  try {
    let _ = @siv.halves(unhex(odd)[:])
  } catch {
    @spec.Broken::Size(..) => refused = true
    _ => fail("expected a size error")
  }
  assert_true(refused)
  // Blowfish has a 64-bit block, so it cannot be used with SIV.
  let blowfish = try
    @blowfish.Cipher::new(unhex("000102030405060708090a0b0c0d0e0f")[:])
  catch {
    _ => abort("bad test key")
  } noraise {
    cipher => cipher
  }
  let aes_cipher = aes(unhex("000102030405060708090a0b0c0d0e0f")[:])
  let mut bad = false
  try {
    let _ = @siv.Siv::new(blowfish, aes_cipher)
  } catch {
    @spec.Broken::Size(..) => bad = true
    _ => fail("expected a size error")
  }
  assert_true(bad)
}
