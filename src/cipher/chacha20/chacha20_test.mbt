// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
fn refused(f : () -> Unit raise) -> Bool {
  try {
    f()
    false
  } catch {
    _ => true
  }
}

///|
let blocks : Array[(String, UInt32, String, String)] = [
  (
    "0000000000000000000000000000000000000000000000000000000000000000", 0U, "000000000000000000000000",
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
  ),
  (
    "0000000000000000000000000000000000000000000000000000000000000000", 1U, "000000000000000000000000",
    "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
  ),
  (
    "0000000000000000000000000000000000000000000000000000000000000001", 1U, "000000000000000000000000",
    "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
  ),
  (
    "00ff000000000000000000000000000000000000000000000000000000000000", 2U, "000000000000000000000000",
    "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
  ),
  (
    "0000000000000000000000000000000000000000000000000000000000000000", 0U, "000000000000000000000002",
    "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
  ),
]

///|
let encryptions : Array[(String, UInt32, String, String, String)] = [
  (
    "0000000000000000000000000000000000000000000000000000000000000000", 0U, "000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
  ),
  (
    "0000000000000000000000000000000000000000000000000000000000000001", 1U, "000000000000000000000002",
    "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
    "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
  ),
  (
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", 42U, "000000000000000000000002",
    "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
    "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
  ),
]

///|
test "RFC 8439 A.1: the block function" {
  for v in blocks {
    let (key, counter, nonce, keystream) = v
    let c = @chacha20.Cipher::new(raw(key)[:])
    assert_eq(@base16.encode(c.block(counter, raw(nonce)[:])), keystream)
  }
}

///|
test "RFC 8439 A.2: encryption, and decryption is the same operation" {
  for v in encryptions {
    let (key, counter, nonce, plain, cipher) = v
    let c = @chacha20.Cipher::new(raw(key)[:])
    let wire = c.xor(nonce=raw(nonce)[:], raw(plain)[:], counter~)
    assert_eq(@base16.encode(wire), cipher)
    assert_eq(
      @base16.encode(c.xor(nonce=raw(nonce)[:], wire[:], counter~)),
      plain,
    )
  }
}

///|
test "the keystream continues across blocks, whatever the slicing" {
  let c = @chacha20.Cipher::new(raw(encryptions[1].0)[:])
  let nonce = raw(encryptions[1].2)
  let whole = c.xor(nonce=nonce[:], Bytes::make(200, b'\x00'), counter=7)
  let first = c.block(7, nonce[:])
  let second = c.block(8, nonce[:])
  assert_eq(whole[0:64].to_owned(), first)
  assert_eq(whole[64:128].to_owned(), second)
  assert_eq(c.xor(nonce=nonce[:], b""[:]), b"")
}

///|
test "a key or nonce of the wrong length is refused" {
  assert_eq(
    refused(() => ignore(@chacha20.Cipher::new(Bytes::make(31, b'\x00')[:]))),
    true,
  )
  let c = @chacha20.Cipher::new(Bytes::make(32, b'\x00')[:])
  let refused = try c.block(0, Bytes::make(8, b'\x00')[:]) catch {
    Size(want~, got~) => (want, got)
    _ => (0, 0)
  } noraise {
    _ => (0, 0)
  }
  assert_eq(refused, (12, 8))
}

///|
/// HChaCha20 from draft-irtf-cfrg-xchacha §2.2.1, plus the property that makes
/// it HChaCha20 rather than ChaCha20: the feed-forward of the input state is
/// left out, so the output is not keystream.
test "draft-irtf-cfrg-xchacha §2.2.1: HChaCha20" {
  let key = raw(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = raw("000000090000004a0000000031415927")
  assert_eq(
    @base16.encode(@chacha20.hchacha20(key[:], nonce[:])),
    "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
  )
  // Sixteen bytes is what it takes; the twelve-byte ChaCha20 nonce is not
  // enough, and a longer one is not silently cut.
  for size in [0, 12, 15, 17, 24] {
    let wrong = Bytes::make(size, b'\x00')
    let got = try @chacha20.hchacha20(key[:], wrong[:]) catch {
      Size(want~, got~) => (want, got)
      _ => (0, 0)
    } noraise {
      _ => (0, 0)
    }
    assert_eq(got, (16, size))
  }
  let got = try
    @chacha20.hchacha20(Bytes::make(31, b'\x00')[:], nonce[:])
  catch {
    Size(want~, got~) => (want, got)
    _ => (0, 0)
  } noraise {
    _ => (0, 0)
  }
  assert_eq(got, (32, 31))
}
