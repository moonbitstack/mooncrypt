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
/// The SP 800-38A key and four-block message that both F.2.1 and F.5.1 use, so
/// the two modes can be compared on the same input.
let key : String = "2b7e151628aed2a6abf7158809cf4f3c"

///|
let message : String = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"

///|
/// A context over AES-128 with a fresh key object, since a key schedule is
/// immutable and one can be shared.
fn aes128(k : String) -> @aes.Cipher {
  try @aes.Cipher::new(unhex(k)[:]) catch {
    _ => abort("bad test key")
  } noraise {
    cipher => cipher
  }
}

///|
/// SP 800-38A F.2.1, the four CBC blocks, and the decryption that undoes them.
test "cbc matches the SP 800-38A vector" {
  let iv = unhex("000102030405060708090a0b0c0d0e0f")
  let plain = unhex(message)
  let mode = @mode.Cbc::new(aes128(key), iv[:])
  let cipher = mode.encrypt(plain[:])
  assert_eq(
    hx(cipher),
    "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
  )
  let back = @mode.Cbc::new(aes128(key), iv[:])
  assert_eq(hx(back.decrypt(cipher[:])), message)
}

///|
/// SP 800-38A F.5.1: the same key, message and length, with a counter instead
/// of a chaining vector. Since the keystream is independent of the plaintext,
/// encrypting and decrypting are the same call.
test "ctr matches the SP 800-38A vector" {
  let nonce = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
  let plain = unhex(message)
  let cipher = @mode.Ctr::new(aes128(key), nonce[:]).apply(plain[:])
  assert_eq(
    hx(cipher),
    "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
  )
  assert_eq(hx(@mode.Ctr::new(aes128(key), nonce[:]).apply(cipher[:])), message)
}

///|
/// Chaining survives being split across calls, and resetting puts it back: an
/// eighth of the message at a time gives the same bytes as all at once.
test "cbc and ctr continue across calls" {
  let iv = unhex("000102030405060708090a0b0c0d0e0f")
  let plain = unhex(message)
  let whole = @mode.Cbc::new(aes128(key), iv[:]).encrypt(plain[:])
  let piecewise = @mode.Cbc::new(aes128(key), iv[:])
  let parts : Array[Byte] = []
  for at in 0..<4 {
    let part = piecewise.encrypt(plain[at * 16:at * 16 + 16])
    for i in 0..<16 {
      parts.push(part[i])
    }
  }
  assert_eq(hx(Bytes::from_array(parts)), hx(whole))
  // A reset makes the context encrypt the message from the start again.
  let reused = @mode.Cbc::new(aes128(key), iv[:])
  let first = reused.encrypt(plain[0:16])
  reused.reset()
  assert_eq(hx(reused.encrypt(plain[0:16])), hx(first))
  // CTR holds on to the unused part of a keystream block, so odd splits still
  // line up with the whole-message answer.
  let stream = @mode.Ctr::new(
    aes128(key),
    unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")[:],
  )
  let bits : Array[Byte] = []
  for at in 0..<64 {
    let one = stream.apply(plain[at:at + 1])
    bits.push(one[0])
  }
  assert_eq(
    hx(Bytes::from_array(bits)),
    "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
  )
}

///|
/// The counter goes up by one and wraps like an integer: a block of all ones
/// becomes a block of all zeroes, and the last byte is the one that changes
/// first.
test "ctr counts" {
  let nonce = unhex("000000000000000000000000000000ff")
  let mode = @mode.Ctr::new(aes128(key), nonce[:])
  let keystream = mode.apply(
    unhex("0000000000000000000000000000000000000000000000000000000000000000")[:],
  )
  let next = @mode.Ctr::new(
    aes128(key),
    unhex("00000000000000000000000000000100")[:],
  ).apply(unhex("00000000000000000000000000000000")[:])
  assert_eq(hx(keystream[16:]), hx(next))
  let wrapping = @mode.Ctr::new(
    aes128(key),
    unhex("ffffffffffffffffffffffffffffffff")[:],
  )
  let after = @mode.Ctr::new(
    aes128(key),
    unhex("00000000000000000000000000000000")[:],
  )
  assert_eq(
    hx(
      wrapping.apply(
        unhex(
          "0000000000000000000000000000000000000000000000000000000000000000",
        )[:],
      )[16:],
    ),
    hx(after.apply(unhex("00000000000000000000000000000000")[:])),
  )
}

///|
/// A chaining vector or counter of the wrong length is refused with what was
/// expected, and a partial block is refused by CBC because there is no way to
/// chain one.
test "the modes refuse what they cannot chain" {
  let mut short_iv = false
  try {
    let _ = @mode.Cbc::new(aes128(key), unhex("00112233")[:])
  } catch {
    @spec.Broken::Size(want~, got~) => {
      assert_eq(want, 16)
      assert_eq(got, 4)
      short_iv = true
    }
    _ => fail("expected a size error")
  }
  assert_true(short_iv)
  let mut short_nonce = false
  try {
    let _ = @mode.Ctr::new(aes128(key), unhex("0011")[:])
  } catch {
    @spec.Broken::Size(want~, got~) => {
      assert_eq(want, 16)
      assert_eq(got, 2)
      short_nonce = true
    }
    _ => fail("expected a size error")
  }
  assert_true(short_nonce)
  assert_eq(
    @mode.Cbc::new(aes128(key), unhex("000102030405060708090a0b0c0d0e0f")[:]).block(),
    16,
  )
  assert_eq(
    @mode.Ctr::new(aes128(key), unhex("000102030405060708090a0b0c0d0e0f")[:]).block(),
    16,
  )
}

///|
/// PKCS#7 padding rounds up to the block size, and an input that is already a
/// whole number of blocks grows by a whole one.
test "padding round-trips at every length" {
  for n in 0..<40 {
    let data : FixedArray[Byte] = FixedArray::make(n, b'\x41')
    let padded = @mode.pad(16, Bytes::from_array(data)[:])
    assert_eq(padded.length(), (n / 16 + 1) * 16)
    assert_eq(hx(@mode.unpad(16, padded[:])), hx(Bytes::from_array(data)))
  }
  assert_eq(hx(@mode.pad(8, b"abc"[:])), "6162630505050505")
  assert_eq(hx(@mode.pad(8, b""[:])), "0808080808080808")
  assert_eq(
    hx(@mode.pad(8, b"12345678"[:])),
    "3132333435363738" + "0808080808080808",
  )
}

///|
/// A ciphertext whose padding is not there is refused, and the error is the same
/// one a bad tag gives — a caller that tells the two apart has a padding oracle.
test "unpadding refuses what is not padding" {
  let cases = [
    // Last byte says nine, which is more than the block.
    "6162636465666768" + "0909090909090909",
    // Last byte says three but the bytes before it do not agree.
    "6162636465666768" + "0101010101010103",
    // Last byte says zero, which no padding uses.
    "6162636465666768" + "0000000000000000",
    // Not a whole number of blocks.
    "616263",
  ]
  for text in cases {
    let mut refused = false
    try {
      let _ = @mode.unpad(8, unhex(text)[:])
    } catch {
      @spec.Broken::Tag => refused = true
      @spec.Broken::Size(..) => refused = true
      _ => ()
    }
    assert_true(refused)
  }
}
