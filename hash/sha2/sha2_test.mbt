// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn ascii(s : String) -> Bytes {
  @moonbase.ascii(s)
}

///|
/// The two-block example from FIPS 180-4 §D.2 / §C.2 (448 bits).
let two_block = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

///|
/// The wide two-block example from FIPS 180-4 §C.4 / §D.4 (896 bits).
let wide_block = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

///|
/// FIPS 180-4's own worked examples, which are the vectors every implementation
/// is first measured against.
test "SHA-224 matches the FIPS 180-4 examples" {
  assert_eq(
    @base16.encode(@sha2.hash(ascii("")[:], kind=Sha224)),
    "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii("abc")[:], kind=Sha224)),
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii(two_block)[:], kind=Sha224)),
    "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
  )
}

///|
test "SHA-256 matches the FIPS 180-4 examples" {
  assert_eq(
    @base16.encode(@sha2.hash(ascii("")[:])),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii("abc")[:])),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii(two_block)[:])),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
}

///|
test "SHA-384 matches the FIPS 180-4 examples" {
  assert_eq(
    @base16.encode(@sha2.hash(ascii("")[:], kind=Sha384)),
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii("abc")[:], kind=Sha384)),
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii(wide_block)[:], kind=Sha384)),
    "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
  )
}

///|
test "SHA-512 matches the FIPS 180-4 examples" {
  assert_eq(
    @base16.encode(@sha2.hash(ascii("")[:], kind=Sha512)),
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii("abc")[:], kind=Sha512)),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii(wide_block)[:], kind=Sha512)),
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
  )
}

///|
/// The truncated pair is not SHA-512 cut short: a different initial vector gives
/// a different digest for the same message, which these two vectors pin.
test "SHA-512/224 and SHA-512/256 match the FIPS 180-4 examples" {
  assert_eq(
    @base16.encode(@sha2.hash(ascii("abc")[:], kind=Sha512_224)),
    "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii(wide_block)[:], kind=Sha512_224)),
    "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii("abc")[:], kind=Sha512_256)),
    "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
  )
  assert_eq(
    @base16.encode(@sha2.hash(ascii(wide_block)[:], kind=Sha512_256)),
    "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
  )
}

///|
/// A hasher fed in pieces must agree with the one-shot for every split, which is
/// what exercises the block buffer's carry between calls — including splits that
/// land exactly on a block boundary and ones that straddle it.
test "streaming in chunks agrees with the one-shot" {
  let kinds : Array[@sha2.Kind] = [
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
  ]
  let msg : Array[Byte] = []
  for i in 0..<300 {
    msg.push((i * 7 % 251).to_byte())
  }
  let whole = Bytes::from_array(msg)
  for kind in kinds {
    let want = @sha2.hash(whole[:], kind~)
    for cut in [1, 31, 63, 64, 65, 111, 127, 128, 129, 200] {
      let h = @sha2.Hasher::new(kind~)
      let mut at = 0
      while at < whole.length() {
        let end = if at + cut < whole.length() {
          at + cut
        } else {
          whole.length()
        }
        h.write(whole[at:end])
        at = end
      }
      assert_eq(h.finish(), want)
    }
  }
}

///|
/// Reading a digest must not disturb the state: the same hasher keeps absorbing
/// and the second digest is the one for the whole message.
test "finish leaves the hasher usable" {
  let h = @sha2.Hasher::new()
  h.write(ascii("a")[:])
  assert_eq(
    @base16.encode(h.finish()),
    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
  )
  h.write(ascii("bc")[:])
  assert_eq(
    @base16.encode(h.finish()),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  h.reset()
  h.write(ascii("abc")[:])
  assert_eq(
    @base16.encode(h.finish()),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
/// A message exactly one byte short of the padding boundary, one byte over it
/// and exactly on it: the three lengths where a wrong `<` versus `<=` shows up.
test "padding boundaries" {
  for n in [54, 55, 56, 63, 64, 119, 111, 112, 127, 128] {
    let msg : Array[Byte] = []
    for _ in 0..<n {
      msg.push(b'a')
    }
    let whole = Bytes::from_array(msg)
    let h = @sha2.Hasher::new(kind=Sha512)
    h.write(whole[:])
    assert_eq(h.finish().length(), 64)
    let g = @sha2.Hasher::new()
    g.write(whole[:])
    assert_eq(g.finish().length(), 32)
  }
  // 'a' × 56 is the first SHA-256 message needing a second padding block.
  let fifty_six : Array[Byte] = []
  for _ in 0..<56 {
    fifty_six.push(b'a')
  }
  assert_eq(
    @base16.encode(@sha2.hash(Bytes::from_array(fifty_six)[:])),
    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
  )
}

///|
/// What HMAC and the KDFs read off a hash before they start.
test "sizes and block lengths" {
  let want : Array[(@sha2.Kind, Int, Int)] = [
    (Sha224, 28, 64),
    (Sha256, 32, 64),
    (Sha384, 48, 128),
    (Sha512, 64, 128),
  ]
  for case in want {
    let (kind, size, block) = case
    let h = @sha2.Hasher::new(kind~)
    assert_eq(h.size(), size)
    assert_eq(h.block(), block)
    assert_eq(h.finish().length(), size)
  }
  assert_eq(@sha2.Hasher::new(kind=Sha512_224).size(), 28)
  assert_eq(@sha2.Hasher::new(kind=Sha512_256).size(), 32)
}
