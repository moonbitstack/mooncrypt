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
/// A fresh AES-128 key object.
fn aes128(k : String) -> @aes.Cipher {
  try @aes.Cipher::new(unhex(k)[:]) catch {
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
/// One case: a key, a nonce, associated data, a plaintext and a tag length, with
/// the ciphertext-then-tag that the reference produces.
struct Case {
  key : String
  nonce : String
  aad : String
  plain : String
  tag : Int32
  expected : String
}

///|
/// The RFC 3610 packet vector #1, which is the one everybody checks, and then
/// cases an independent implementation produced for the shapes RFC 3610 does not
/// cover: an empty plaintext, an empty associated data, a seven-byte nonce, a
/// thirteen-byte nonce, a single byte, a tag of every size CCM allows, and the
/// two longer keys.
///
/// `scripts/gen_ccm_vectors.py` writes this table; do not edit it by hand.
let cases : Array[Case] = [
  {
    // RFC 3610 packet vector #1.
    key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce: "00000003020100a0a1a2a3a4a5",
    aad: "0001020304050607",
    plain: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
    tag: 8,
    expected: "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0",
  },
  {
    // The same inputs with a longer tag: not the same computation
    // truncated, but a different one, because the tag length is
    // in the first block.
    key: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce: "00000003020100a0a1a2a3a4a5",
    aad: "0001020304050607",
    plain: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
    tag: 16,
    expected: "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384509da654e32deac369c2dae7133cb08d",
  },
  {
    // Nothing but a tag: an empty message with no associated data.
    key: "000102030405060708090a0b0c0d0e0f",
    nonce: "000102030405060708090a0b0c",
    aad: "",
    plain: "",
    tag: 16,
    expected: "54c92fe45510d6b3b0d46eac2fee8e63",
  },
  {
    // Associated data but no plaintext.
    key: "000102030405060708090a0b0c0d0e0f",
    nonce: "000102030405060708090a0b0c",
    aad: "0001020304050607",
    plain: "",
    tag: 12,
    expected: "9722b69b6eea0cd5e11e02b2",
  },
  {
    // Associated data past the first block, so the length header
    // spills into a second block, and still no plaintext.
    key: "000102030405060708090a0b0c0d0e0f",
    nonce: "000102030405060708090a0b0c",
    aad: "000102030405060708090a0b0c0d0e0f1011121314151617",
    plain: "",
    tag: 10,
    expected: "c78ff938e445603031e7",
  },
  {
    // The shortest tag CCM allows, over one byte.
    key: "000102030405060708090a0b0c0d0e0f",
    nonce: "000102030405060708090a0b0c",
    aad: "f0f1f2f3",
    plain: "41",
    tag: 4,
    expected: "577d86e842",
  },
  {
    // Exactly one block of plaintext and no associated data.
    key: "000102030405060708090a0b0c0d0e0f",
    nonce: "000102030405060708090a0b0c",
    aad: "",
    plain: "000102030405060708090a0b0c0d0e0f",
    tag: 16,
    expected: "1635b68b570cfc85529e39ac913910d7c7c5c394b685b08b3f00dcd81256f0d0",
  },
  {
    // An eight-byte nonce, so `L = 7`, and a plaintext that is not
    // a whole number of blocks.
    key: "000102030405060708090a0b0c0d0e0f",
    nonce: "0001020304050607",
    aad: "cafebabe",
    plain: "48656c6c6f2c2043434d21",
    tag: 8,
    expected: "4592169e944ff644644f67a333260aae195b24",
  },
  {
    // A seven-byte nonce, the shortest CCM allows, which leaves
    // `L = 8`: the widest length field the format has.
    key: "000102030405060708090a0b0c0d0e0f",
    nonce: "00010203040506",
    aad: "cafebabe",
    plain: "48656c6c6f2c2043434d21",
    tag: 8,
    expected: "1f71df8052aa214cef418e8bff0e41194d5da5",
  },
  {
    // A twelve-byte nonce with a two-byte tag: a tag length that is
    // neither short nor long.
    key: "000102030405060708090a0b0c0d0e0f",
    nonce: "0008090a0b0c0d0e0f101112",
    aad: "deadbeef",
    plain: "48656c6c6f2c2043434d21",
    tag: 14,
    expected: "506c54dc57807454b7b7c551636f7b9c3bcdecf65e84cb7430",
  },
  {
    // A thirteen-byte nonce, the longest CCM allows, so `L = 2` and
    // the message length has to fit in two bytes.
    key: "000102030405060708090a0b0c0d0e0f",
    nonce: "000102030405060708090a0b0c",
    aad: "a0a1",
    plain: "00112233445566778899aabbccddeeff1021324354657687",
    tag: 6,
    expected: "162596bb175c9cf5d20e991c51e9f027f321366122480761bab78f2a6f40",
  },
  {
    // An AES-192 key.
    key: "000102030405060708090a0b0c0d0e0f1011121314151617",
    nonce: "0001020304050607",
    aad: "feedface",
    plain: "000102030405060708090a0b0c0d0e0f",
    tag: 16,
    expected: "b97b8c1f8d879ad965823026946e3e76e75f74f54decc8ffaa9341f8e87d4722",
  },
  {
    // An AES-256 key.
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: "0001020304050607",
    aad: "feedface",
    plain: "000102030405060708090a0b0c0d0e0f",
    tag: 16,
    expected: "b5daee18f7eb7185f8db7cc24c67e0d5c902b4063a34cfb878e919ae65c2317b",
  },
]

///|
/// Every case: the ciphertext and tag match, and opening gives the plaintext
/// back.
test "ccm matches the reference and round-trips" {
  for case in cases {
    let cipher = aes128(case.key)
    let box = @ccm.seal(
      cipher,
      unhex(case.nonce)[:],
      unhex(case.plain)[:],
      aad=unhex(case.aad)[:],
      tag=case.tag,
    )
    assert_eq(hx(box), case.expected)
    assert_eq(
      hx(
        @ccm.open(
          cipher,
          unhex(case.nonce)[:],
          box[:],
          aad=unhex(case.aad)[:],
          tag=case.tag,
        ),
      ),
      case.plain,
    )
  }
}

///|
/// A tag length CCM cannot express is refused, because the first byte has three
/// bits for `(M - 2) / 2` and there is no encoding for an odd or a tiny one.
test "ccm refuses tag lengths it cannot express" {
  let cipher = aes128("000102030405060708090a0b0c0d0e0f")
  for size in [0, 1, 2, 3, 5, 7, 17, 18] {
    let mut refused = false
    try {
      let _ = @ccm.Ccm::new(cipher, tag=size)
    } catch {
      @spec.Broken::Size(..) => refused = true
      _ => fail("expected a size error")
    }
    assert_true(refused)
  }
  for size in [4, 6, 8, 10, 12, 14, 16] {
    let mode = try @ccm.Ccm::new(cipher, tag=size) catch {
      _ => abort("a legal tag length was refused")
    } noraise {
      mode => mode
    }
    assert_eq(mode.size(), size)
  }
}

///|
/// A modified ciphertext, tag, associated data or nonce fails to open, and so
/// does one that is shorter than a tag.
test "ccm refuses anything that was changed" {
  let cipher = aes128("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
  let nonce = unhex("00000003020100a0a1a2a3a4a5")
  let aad = unhex("0001020304050607")
  let plain = unhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
  let box = @ccm.seal(cipher, nonce[:], plain[:], aad=aad[:], tag=8)
  let mode = try @ccm.Ccm::new(cipher, tag=8) catch {
    _ => abort("bad tag length")
  } noraise {
    mode => mode
  }
  for at in [0, 10, 22] {
    let broken = flip(box[:], at)
    let mut refused = false
    try {
      let _ = mode.open(nonce~, cipher=broken[:], aad=aad[:])
    } catch {
      @spec.Broken::Tag => refused = true
      _ => fail("expected a tag error")
    }
    assert_true(refused)
  }
  // The associated data is authenticated too, so changing it is a different
  // message even though the plaintext is the same.
  let other = unhex("0001020304050608")
  let mut refused = false
  try {
    let _ = mode.open(nonce~, cipher=box[:], aad=other[:])
  } catch {
    @spec.Broken::Tag => refused = true
    _ => fail("expected a tag error")
  }
  assert_true(refused)
  let mut short = false
  try {
    let _ = mode.open(nonce~, cipher=box[0:4], aad=aad[:])
  } catch {
    @spec.Broken::Size(..) => short = true
    _ => fail("expected a size error")
  }
  assert_true(short)
}

///|
/// The trait form works and agrees with the inherent one, and a nonce outside
/// seven to thirteen bytes is refused rather than stretched.
test "ccm through the trait" {
  let cipher = aes128("000102030405060708090a0b0c0d0e0f")
  let nonce = unhex("000102030405060708090a0b0c")
  let mode = try @ccm.Ccm::new(cipher) catch {
    _ => abort("bad")
  } noraise {
    mode => mode
  }
  let box = @spec.Aead::seal(mode, nonce~, plain=b"hello"[:], aad=b"ctx"[:])
  assert_eq(
    hx(@spec.Aead::open(mode, nonce~, cipher=box[:], aad=b"ctx"[:])),
    hx(b"hello"[:]),
  )
  // `seal` cannot raise — the trait it implements does not allow it — so a
  // nonce of the wrong length is a programming error there, while `open` has an
  // error channel and uses it.
  for text in ["0001020304", "000102030405060708090a0b0c0d0e"] {
    let mut refused = false
    try {
      let _ = mode.open(nonce=unhex(text)[:], cipher=box[:], aad=b"ctx"[:])
    } catch {
      @spec.Broken::Size(..) => refused = true
      _ => fail("expected a size error")
    }
    assert_true(refused)
  }
}
