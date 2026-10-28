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
/// A cipher for a hex key.
fn cipher_for(key : String) -> @xchacha20.Cipher {
  try @xchacha20.Cipher::new(unhex(key)[:]) catch {
    _ => abort("bad test key")
  } noraise {
    cipher => cipher
  }
}

///|
/// One case: a key, a twenty-four byte nonce, a starting block counter, the
/// plaintext and the keystream applied to it.
struct Case {
  key : String
  nonce : String
  counter : UInt32
  plain : String
  expected : String
}

///|
/// Both vectors from draft-irtf-cfrg-xchacha appendix A.3.2, then cases the
/// reference in `scripts/gen_xchacha20_vectors.py` produced for the shapes they
/// do not cover: an empty message, an all-zero key and nonce, exactly one block,
/// one byte, a counter near the top of its range, and a nonce whose two halves
/// are unrelated.
///
/// The reference is written from scratch and refuses to emit anything unless it
/// reproduces the draft's HChaCha20 vector and both appendix A.3.2 vectors.
let cases : Array[Case] = [
  {
    // draft-irtf-cfrg-xchacha §A.3.2.1: a 162-byte message starting at
    // counter 0, so the keystream runs for three blocks.
    key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce: "404142434445464748494a4b4c4d4e4f5051525354555658",
    counter: 0,
    plain: "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
    expected: "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5",
  },
  {
    // The same key, nonce and message starting at counter 1, which must
    // produce something entirely different — one block of keystream is
    // skipped.
    key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce: "404142434445464748494a4b4c4d4e4f5051525354555658",
    counter: 1,
    plain: "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
    expected: "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee053a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd20112f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d316838a9c71f70b5b5907a66f7ea49aadc409",
  },
  {
    // An empty message, which produces no keystream at all and must not
    // fail.
    key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce: "404142434445464748494a4b4c4d4e4f5051525354555658",
    counter: 0,
    plain: "",
    expected: "",
  },
  {
    // An all-zero key and nonce, the weakest input the cipher will ever
    // be handed.
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    nonce: "000000000000000000000000000000000000000000000000",
    counter: 0,
    plain: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    expected: "bcd02a18bf3f01d19292de30a7a8fdaca4b65e50a6002cc72cd6d2f7c91ac3d5728f83e0aad2bfcf9abd2d2db58faedd65015dd83fc09b131e271043019e8e0f",
  },
  {
    // Exactly one block, so the counter is used once and never
    // incremented.
    key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce: "404142434445464748494a4b4c4d4e4f5051525354555658",
    counter: 0,
    plain: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    expected: "1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9aadec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d",
  },
  {
    // One byte, the shortest non-empty message.
    key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce: "404142434445464748494a4b4c4d4e4f5051525354555658",
    counter: 0,
    plain: "ff",
    expected: "ee",
  },
  {
    // A counter near the top of its range, to check that it is used as a
    // full thirty-two bit word rather than being truncated.
    key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce: "404142434445464748494a4b4c4d4e4f5051525354555658",
    counter: 4294967294,
    plain: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    expected: "f9eda1cc83abb544ad2d96961406718073987da0cdcccaa9a3a8d7dad9389b7dcebeaa0095bb5c7f11589cfb8c3039232c127d17e493aade2b087934db9db464f266b93c50184b66b7863f6cd51c36135bb9f032e65159220358fcb95094360f",
  },
  {
    // A nonce whose halves are unrelated: only the first sixteen bytes
    // go into the subkey and only the last eight become the ChaCha20
    // nonce, so swapping them must not go unnoticed.
    key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce: "000102030405060708090a0b0c0d0e0f1011121314151617",
    counter: 0,
    plain: "48656c6c6f2c2058436861436861323021",
    expected: "6e125f15d4b595024618230a18f9e7c665",
  },
  {
    // A message of 2 blocks plus one byte with a nonce that differs from
    // the draft's only in its last byte.
    key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonce: "404142434445464748494a4b4c4d4e4f5051525354555659",
    counter: 0,
    plain: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    expected: "8d06e6693866e16bd697cf4f3d5d878eb3038cb24a825346088d92b4434c908eb507ddf3a49daaaf0063e63ebff226275d7fe9247558c3870ad1da4776c15de34b0c49ea29572c2d196cdf22bcccc431b723707a7c246347a723791b2b441e7bfc2316ea4f799f27b37fbb960c75d348b53b33c7dfa42fd8ac1872c11a232455b1",
  },
]

///|
/// Every case: the keystream matches the reference, and applying it twice is the
/// identity.
test "xchacha20 matches the draft and round-trips" {
  for case in cases {
    let cipher = cipher_for(case.key)
    let nonce = unhex(case.nonce)
    let plain = unhex(case.plain)
    let box = cipher.xor(nonce=nonce[:], plain[:], counter=case.counter)
    assert_eq(hx(box), case.expected)
    assert_eq(
      hx(cipher.xor(nonce=nonce[:], box[:], counter=case.counter)),
      case.plain,
    )
  }
}

///|
/// The first block of the stream is what `block` reports, and the counter really
/// is a block counter: starting at n is the same as throwing away the first n
/// blocks.
test "xchacha20 blocks and counters agree with the stream" {
  let key = unhex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = unhex("404142434445464748494a4b4c4d4e4f5051525354555658")
  let cipher = cipher_for(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let first = try cipher.block(0, nonce[:]) catch {
    _ => abort("bad nonce")
  } noraise {
    block => block
  }
  assert_eq(first.length(), 64)
  let zeros : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  let stream = cipher.xor(
    nonce=nonce[:],
    Bytes::from_array(zeros)[:],
    counter=0,
  )
  assert_eq(hx(first), hx(stream))
  // Skipping one block by counter and by slicing agree.
  let skipped = cipher.xor(
    nonce=nonce[:],
    Bytes::from_array(zeros)[:],
    counter=1,
  )
  let two = cipher.xor(
    nonce=nonce[:],
    Bytes::from_array(FixedArray::make(128, b'\x00'))[:],
    counter=0,
  )
  assert_eq(hx(skipped), hx(two[64:]))
  // The key is what the cipher keeps, so it is 32 bytes and nothing else.
  assert_eq(key.length(), @xchacha20.key_size)
  assert_eq(nonce.length(), @xchacha20.nonce_size)
}

///|
/// A key or a nonce that is the wrong length is refused rather than stretched,
/// and the twenty-four byte nonce is not silently accepted by the sixteen-byte
/// derivation.
test "xchacha20 refuses the wrong lengths" {
  for size in [0, 16, 31, 33, 64] {
    let key = Bytes::make(size, b'\x00')
    let mut refused = false
    try {
      let _ = @xchacha20.Cipher::new(key[:])
    } catch {
      @spec.Broken::Size(..) => refused = true
      _ => fail("expected a size error")
    }
    assert_true(refused)
  }
  let cipher = cipher_for(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  for size in [0, 8, 12, 16, 23, 25, 32] {
    let nonce = Bytes::make(size, b'\x00')
    let mut refused = false
    try {
      let _ = cipher.xor(nonce=nonce[:], b""[:])
    } catch {
      @spec.Broken::Size(..) => refused = true
      _ => fail("expected a size error")
    }
    assert_true(refused)
  }
  // `subkey` wants exactly the sixteen bytes HChaCha20 consumes.
  for size in [0, 15, 17, 24] {
    let half = Bytes::make(size, b'\x00')
    let mut refused = false
    try {
      let _ = @xchacha20.subkey(
        unhex(
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )[:],
        half[:],
      )
    } catch {
      @spec.Broken::Size(..) => refused = true
      _ => fail("expected a size error")
    }
    assert_true(refused)
  }
}

///|
/// XChaCha20 is ChaCha20 under a derived key, so the derivation has to be
/// reproducible from the outside: the subkey of a nonce's first half, fed to
/// ChaCha20 with a zero-prefixed tail, must give exactly the same keystream.
test "xchacha20 is chacha20 under the derived subkey" {
  let key = unhex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = unhex("404142434445464748494a4b4c4d4e4f5051525354555658")
  let derived = try @xchacha20.subkey(key[:], nonce[0:16]) catch {
    _ => abort("bad nonce")
  } noraise {
    subkey => subkey
  }
  assert_eq(derived.length(), 32)
  let inner = try @chacha20.Cipher::new(derived[:]) catch {
    _ => abort("bad subkey")
  } noraise {
    cipher => cipher
  }
  let tail : Array[Byte] = [b'\x00', b'\x00', b'\x00', b'\x00']
  for b in nonce[16:] {
    tail.push(b)
  }
  let plain = unhex("00112233445566778899aabbccddeeff")
  let manual = inner.xor(nonce=Bytes::from_array(tail)[:], plain[:], counter=7)
  let cipher = cipher_for(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let direct = cipher.xor(nonce=nonce[:], plain[:], counter=7)
  assert_eq(hx(manual), hx(direct))
}
