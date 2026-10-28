// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The vectors come from `scripts/gen_salsa20_vectors.py`, which reproduces the
// keystream example in the Salsa20 specification before taking anything else
// from PyCryptodome.

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One block of keystream: a key, a nonce, and how many blocks in to start.
///
/// The block offsets go past 2^8, 2^16 and 2^32 so that a counter kept in the
/// wrong width shows up here rather than in a 256 GiB stream.
struct Case {
  key : String
  nonce : String
  block : UInt64
  expected : String
}

///|
let cases : Array[Case] = [
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: "0001020304050607",
    block: 0UL,
    expected: "2ead0f5f185729ced672b3a928e454f72fdb44a87b9cd8d219e4ec14aef9c6bc77bf057f5659d7753848f8d3fe769ca5fdd8057d46326990e5f136e2fcb7bb7c",
  },
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: "0001020304050607",
    block: 1UL,
    expected: "a13a2b59d9047b8dbeb93ec4b78ce1a59bc210641318ccce694d30ff81d2afe7bdf5a3d58cb4f9a4ed5247823e14618f06dc61cfe4b8e2ba836783b280efedca",
  },
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: "0001020304050607",
    block: 2UL,
    expected: "8740bfe7d23f9c0432c259039c79573aa220c0722b049623f3a19e9cd1b143f2c36c1afcd419270f66c0789af6a9702d2da4e676e3d5ad4a62234fb3f5c4eab3",
  },
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: "0001020304050607",
    block: 255UL,
    expected: "c3c97972766aa45d67aa5442eb6d94f4c75084bbc43aca105fc547c4d680fee302c1407d0aef5947c149a72f09d3f7487e4d4cec013da69fcc8ea739e5284a04",
  },
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: "0001020304050607",
    block: 256UL,
    expected: "402de17404ff44428855776aae931a56da07504dacd1f4faa6a464bf983612b7fa8c44cc52cabf43b28cf5863e2861f1b0f82137ac10af9c08833caebea30051",
  },
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: "0001020304050607",
    block: 65535UL,
    expected: "3c042eecb77ba98cde8e666f8845120f2a99b48f6c13dddd20644980d7784db3c7ed219a847349c61b88b83055206fbb39b352e349e270a28ba000ac921818b1",
  },
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: "0001020304050607",
    block: 65536UL,
    expected: "f19bbd9675ffd47305b642bd7c0602d24a8c6f76e60361cd28ec5008e45322113a55aa8cad8e1f43227ebfe67aff4ad851febfb9597025e14df2794f0bda4a0d",
  },
  {
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce: "0001020304050607",
    block: 4294967296UL,
    expected: "e58a3ce12a19d89b151819eec0956ae8b8ba7df7d537480a39b6678cbbda10f3f095aa1bc8e860392de7b267fb1245d1ff12efd12887cd1c797ea18bb7261e74",
  },
  {
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 0UL,
    expected: "9a97f65b9b4c721b960a672145fca8d4e32e67f9111ea979ce9c4826806aeee63de9c0da2bd7f91ebcb2639bf989c6251b29bf38d39a9bdce7c55f4b2ac12a39",
  },
  {
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 1UL,
    expected: "abea8a17646d1a7782f4f2ae5e9f2bdeac1241460ba80bd5beefbf8794988834c4d94bb6c9134d512664c90dd0ecbb218d5a24fffb69ceb42f5efab584be6e10",
  },
  {
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 2UL,
    expected: "0ba7d1944375213cea2cd792086425021e939aa73233c3d0e606e0cc799431135352e8dea006b448f418528667425d28a0e524fb582e34b900ace05836a5ba8a",
  },
  {
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 255UL,
    expected: "66cecf0f30b445c539d3da3dba6c74a8ac9f176e022fdf49ad0092f92883aa2556ce240cab5777305635a8dcf7a7db5b46908d11d27420bd0cfd0479355aed39",
  },
  {
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 256UL,
    expected: "915cf63b9275eea7e82f5b15c953750390d672678e8aa25b40974e3bd8bdeae2a3b0fff354a521783dbb47d95c67c2db58b0db881304ce9766ec158e27333c9a",
  },
  {
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 65535UL,
    expected: "ebe54d44c667a209c683707f9f52b9b498a2f7d03287d300db4b4ad1ad92b5a8b20f968b7b503ad263bb67826e7a9f0d6dc3d1f6e1dc0e70e82c29e76d9a0ac5",
  },
  {
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 65536UL,
    expected: "da5700375fe011ab71e41fb1095d74dc2898726b75c7e1fb90801a6aada7623b356a8ffac0e7b499cf1e715a65ba44f5e74c21210c2a7c0308409d64ffd89862",
  },
  {
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 4294967296UL,
    expected: "b65fc777c4f950ec0274ff0ffbb0a6e3ededf78477e94945e87f26e3162bf6a1050933421833f249da1162db6e92a7678505190c80dc46350b81e831f974b28c",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce: "ffffffffffffffff",
    block: 0UL,
    expected: "12f0ae4cda6e672bcf8bc8ee87f9657fc366d0c5bc1066b5bc053b29bd1bf0eabfef62bc2ae8770faef55ccad927519427fc32cd7b79767ea966344e83bc1fcc",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce: "ffffffffffffffff",
    block: 1UL,
    expected: "cabd9af93429424e6b1602b6d2fbb78a096b4df308f2d72c8c4905cfc81b61b5cd9cbaabb26c06ecf8af63e98dcce776960f75ada54aee1825a8da40000eb407",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce: "ffffffffffffffff",
    block: 2UL,
    expected: "a220d6691393c367b1f3d277c96490b72e41e3487d641e53efe637c51c8e87d8707d7415c9ed5c7621a6bf05eafc35990e5e0e459857c1c8dea53eafa620024b",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce: "ffffffffffffffff",
    block: 255UL,
    expected: "e75e5f9661bba9c55eb77f7b18fad2faa2f201c27f0c68ae4dd39c32c60eef32dd8ea28f658d0568e23dc151c31c8e6ac07bababeffc70ccd2cc06c06cfe36c8",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce: "ffffffffffffffff",
    block: 256UL,
    expected: "7210117da5eecd5cca8da36f02330169c90b7cf55abf46c2aafedc6a3011352d7251ecbb8dfca8249c684cd36eb1f0f1069b5922b2e845882d71986316d54db9",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce: "ffffffffffffffff",
    block: 65535UL,
    expected: "1bc41f1990b918d4068ec5d1c9edf7ccd80992883c5319844e7a151cb5a2d1f281955c2c560d8ca47f4ceabcf8394a3a4fc5d2f0fcfe6f51f85e623c20c97114",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce: "ffffffffffffffff",
    block: 65536UL,
    expected: "e9aaaa931bb6445ebb89747636ae1fc2b7898433da4a2636065c53dbb0cae45ae2b0e0035f4f8da9f90cd5ad3594d63c2ee6c6087928a36007eb793a4c98b681",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce: "ffffffffffffffff",
    block: 4294967296UL,
    expected: "96cedb2d4916b124809612c763dd5522fa3cde820da86743a4cf02f9345c53ec9894375e58cbf24ba3fc1e3b584d92961c9173056d9f1c37786820795e2cd2fb",
  },
  {
    key: "8000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 0UL,
    expected: "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117",
  },
  {
    key: "8000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 1UL,
    expected: "8da2b74eef1b6283e7e20166abcae538e9716e4669e2816b6b20c5c356802001cc1403a9a117d12a2669f456366d6ebb0f1246f1265150f793cdb4b253e348ae",
  },
  {
    key: "8000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 2UL,
    expected: "203d89bc025e802a7e0e00621d70aa36b7e07cb1e7d5b38d5e222b8b0e4b84070142b1e29504767d76824850320b5368129fdd74e861b498e3be8d16f2d7d169",
  },
  {
    key: "8000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 255UL,
    expected: "f284ad191ed614a83589fc751209d923a9e25f8b01d4d2381edf422a266b5eeeda3b5728adfbee5e6130f8fd0e83154b65fba62fe8523fba6cbcadeac7db345f",
  },
  {
    key: "8000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 256UL,
    expected: "47d7ad0a6c6241a1d2e9c06e7473f95d2d95723c034d436d9f14793db86d56d67cd113b4b0f869bff2da93043c63123dbaea4cc0cc3bad7ba778a5c5e62ccc7a",
  },
  {
    key: "8000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 65535UL,
    expected: "26fedec102972fffa504baf06ed07890200fb514f3a36dda522c0d91d6e4055e02fdd2d77c849e6f58ae114b3df38af937b8394676a6862c2d77aa780a811ac0",
  },
  {
    key: "8000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 65536UL,
    expected: "83728d22f931654ab1671fa4a298c455256c7a638f1b18c8adc90251374c2dfad19c97d084dfaf17fdae93336e320209a39b63fe7d9e127ad8d562591c9ac76e",
  },
  {
    key: "8000000000000000000000000000000000000000000000000000000000000000",
    nonce: "0000000000000000",
    block: 4294967296UL,
    expected: "f58c0a5ba638a4ee71075a0258232f0c307d1c207366001b556c22fbbe1fd636a6a219d7fa360a71f9e2866bb313162ea7098ae50069837dcce98f6ee5fd6b96",
  },
]

///|
/// Every sample, taken at its block offset.
test "salsa20 keystream matches the reference" {
  assert_eq(cases.length(), 32)
  for case in cases {
    let cipher = @salsa20.Cipher::new(raw(case.key)[:])
    assert_eq(cipher.block(case.block, raw(case.nonce)[:]), raw(case.expected))
  }
}

///|
/// The example the specification itself gives: the key 0x80 and thirty-one zero
/// bytes, a zero nonce, and the first block.
test "the specification's example" {
  let key = raw(
    "8000000000000000000000000000000000000000000000000000000000000000",
  )
  assert_eq(
    @salsa20.stream(key[:], raw("0000000000000000")[:], 64),
    raw(
      "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117",
    ),
  )
}

///|
/// Encryption and decryption are one operation, and the one-shot form agrees with
/// the block-at-a-time form.
test "salsa20 is its own inverse" {
  let key = raw(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = raw("0001020304050607")
  let plain = raw(
    "the quick brown fox jumps over the lazy dog, and keeps going for another block",
  )
  let encrypted = @salsa20.salsa20(key[:], nonce[:], plain[:])
  assert_eq(encrypted.length(), plain.length())
  assert_eq(@salsa20.salsa20(key[:], nonce[:], encrypted[:]), plain)

  // The same bytes, block by block, from explicit counters.
  let cipher = @salsa20.Cipher::new(key[:])
  let pieces : Array[Byte] = []
  for i in 0..<2 {
    let start = i * 64
    let end = if start + 64 < plain.length() {
      start + 64
    } else {
      plain.length()
    }
    let piece = cipher.xor(
      nonce=nonce[:],
      plain[start:end],
      counter=i.to_uint64(),
    )
    for j in 0..<piece.length() {
      pieces.push(piece[j])
    }
  }
  assert_eq(Bytes::from_array(pieces), encrypted)
}

///|
/// A block is sixty-four bytes, and the counter is what separates them.
test "blocks differ and are sixty-four bytes" {
  let key = raw(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = raw("0001020304050607")
  let cipher = @salsa20.Cipher::new(key[:])
  let first = cipher.block(0UL, nonce[:])
  assert_eq(first.length(), 64)
  assert_true(first != cipher.block(1UL, nonce[:]))
  // And a different nonce is a different keystream at the same counter.
  assert_true(first != cipher.block(0UL, raw("0001020304050606")[:]))
}

///|
/// The key and the nonce are both fixed lengths.
test "wrong key or nonce lengths are refused" {
  assert_true(refused_key(raw("00")[:]))
  assert_true(refused_key(raw("000102030405060708090a0b0c0d0e0f")[:]))
  let key = raw(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  assert_false(refused_key(key[:]))

  let cipher = @salsa20.Cipher::new(key[:])
  let mut short_nonce = false
  try {
    let _ = cipher.block(0UL, raw("00")[:])
  } catch {
    _ => short_nonce = true
  }
  assert_true(short_nonce)
}

///|
fn refused_key(key : BytesView) -> Bool {
  try {
    let _ = @salsa20.Cipher::new(key)
    false
  } catch {
    _ => true
  }
}
