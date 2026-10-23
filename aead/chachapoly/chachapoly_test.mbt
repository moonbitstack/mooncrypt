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
let keys : Array[(String, String, String)] = [
  (
    "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
  ),
  (
    "0000000000000000000000000000000000000000000000000000000000000001", "000000000000000000000002",
    "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739",
  ),
  (
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", "000000000000000000000002",
    "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae",
  ),
]

///|
test "RFC 8439 A.5: decryption checks the tag, then decrypts" {
  let aead = @chachapoly.ChaChaPoly::new(
    raw("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")[:],
  )
  let nonce = raw("000000000102030405060708")
  let aad = raw("f33388860000000000004e91")
  let wire = raw(
    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38",
  )
  let plain = aead.open(nonce=nonce[:], cipher=wire[:], aad=aad[:])
  assert_eq(
    @base16.encode(plain),
    "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
  )
  assert_eq(aead.seal(nonce=nonce[:], plain=plain[:], aad=aad[:]), wire)
}

///|
test "RFC 8439 A.4: the one-time key is block 0 of the keystream" {
  for v in keys {
    let (key, nonce, otk) = v
    let block = @chacha20.Cipher::new(raw(key)[:]).block(0, raw(nonce)[:])
    assert_eq(@base16.encode(block[0:32].to_owned()), otk)
  }
}

///|
test "any change to the ciphertext, the tag or the AAD is refused" {
  let aead = @chachapoly.ChaChaPoly::new(
    raw("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")[:],
  )
  let nonce = raw("000000000102030405060708")
  let aad = raw("f33388860000000000004e91")
  let wire = raw(
    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38",
  )
  for at in [0, 100, wire.length() - 1] {
    let bent = Bytes::makei(wire.length(), i => {
      if i == at {
        wire[i] ^ b'\x01'
      } else {
        wire[i]
      }
    })
    assert_eq(
      refused(() => {
        ignore(aead.open(nonce=nonce[:], cipher=bent[:], aad=aad[:]))
      }),
      true,
      msg="byte \{at}",
    )
  }
  assert_eq(
    refused(() => ignore(aead.open(nonce=nonce[:], cipher=wire[:], aad=b"x"[:]))),
    true,
  )
  assert_eq(
    refused(() => {
      ignore(aead.open(nonce=nonce[:], cipher=wire[0:15], aad=aad[:]))
    }),
    true,
  )
}

///|
test "an empty message seals to its tag alone" {
  let aead = @chachapoly.ChaChaPoly::new(Bytes::make(32, b'\x07')[:])
  let nonce = Bytes::make(12, b'\x00')
  let wire = aead.seal(nonce=nonce[:], plain=b""[:])
  assert_eq(wire.length(), 16)
  assert_eq(aead.open(nonce=nonce[:], cipher=wire[:]), b"")
}
