// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
fn unhex(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
/// The key, nonce, plaintext and associated data of a GCM case whose answer was
/// computed twice: once from SM4 as another implementation provides it and the
/// GHASH definition, once by the code under test.
let key = "0123456789abcdeffedcba9876543210"

///|
let example_nonce = "00001234567800000000ABCD"

///|
let example_plain = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"

///|
let example_aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2"

///|
test "SM4-GCM seals to a known answer" {
  let out = @sm4gcm.seal(
    unhex(key)[:],
    nonce=unhex(example_nonce)[:],
    plain=unhex(example_plain)[:],
    aad=unhex(example_aad)[:],
  )
  assert_eq(
    hex(out),
    "17f399f08c67d5ee19d0dc9969c4bb7dab72f4074680da74646a016fd230af6b",
  )
  assert_eq(out.length(), 32)
}

///|
test "SM4-GCM opens what it sealed" {
  let box = @sm4gcm.seal(
    unhex(key)[:],
    nonce=unhex(example_nonce)[:],
    plain=b"the quick brown fox"[:],
    aad=b"header"[:],
  )
  let opened = @sm4gcm.open(
    unhex(key)[:],
    nonce=unhex(example_nonce)[:],
    cipher=box[:],
    aad=b"header"[:],
  )
  assert_eq(hex(opened), hex(b"the quick brown fox"[:]))
  // The same ciphertext under other associated data does not open.
  try
    @sm4gcm.open(
      unhex(key)[:],
      nonce=unhex(example_nonce)[:],
      cipher=box[:],
      aad=b"headers"[:],
    )
    |> ignore
  catch {
    e => assert_eq(e, @spec.Tag)
  } noraise {
    _ => fail("a tag under other associated data was accepted")
  }
}

///|
test "SM4-GCM refuses a tampered ciphertext" {
  let box = @sm4gcm.seal(
    unhex(key)[:],
    nonce=unhex(example_nonce)[:],
    plain=unhex(example_plain)[:],
    aad=unhex(example_aad)[:],
  )
  let flipped : Bytes = Bytes::from_array(
    Array::make(box.length(), 0).mapi(fn(i, _) {
      if i == 0 {
        (box[i].to_int() ^ 0x80).to_byte()
      } else {
        box[i]
      }
    }),
  )
  try
    @sm4gcm.open(
      unhex(key)[:],
      nonce=unhex(example_nonce)[:],
      cipher=flipped[:],
      aad=unhex(example_aad)[:],
    )
    |> ignore
  catch {
    e => assert_eq(e, @spec.Tag)
  } noraise {
    _ => fail("a flipped ciphertext bit authenticated")
  }
  assert_eq(@sm4gcm.tag, 16)
  assert_eq(@sm4gcm.key_size, 16)
}
