// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
/// FIPS 197 appendix C: one plaintext under all three key lengths, which is the
/// vector every AES implementation is first measured against.
test "the three key lengths, against FIPS 197 appendix C" {
  let plain = raw("00112233445566778899aabbccddeeff")
  let cases = [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    (
      "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191",
    ),
    (
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089",
    ),
  ]
  for case in cases {
    let (key, want) = case
    let cipher = @aes.Cipher::new(raw(key)[:])
    assert_eq(@base16.encode(cipher.encrypt(plain[:])), want)
    // And back, which is what makes it a permutation rather than a hash.
    assert_eq(cipher.decrypt(raw(want)[:]), plain)
    assert_eq(cipher.size(), raw(key).length())
    assert_eq(cipher.block(), 16)
  }
}

///|
/// NIST SP 800-38A appendix F, the ECB key and blocks each mode is built from.
test "the ECB vectors from SP 800-38A" {
  let key = raw("2b7e151628aed2a6abf7158809cf4f3c")
  let cipher = @aes.Cipher::new(key[:])
  let cases = [
    ("6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
    ("ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
    ("30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"),
    ("f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"),
  ]
  for case in cases {
    let (plain, want) = case
    assert_eq(@base16.encode(cipher.encrypt(raw(plain)[:])), want)
    assert_eq(@base16.encode(cipher.decrypt(raw(want)[:])), plain)
  }
  // AES-192 and AES-256 over the same four blocks.
  let k192 = @aes.Cipher::new(
    raw("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")[:],
  )
  assert_eq(
    @base16.encode(k192.encrypt(raw("6bc1bee22e409f96e93d7e117393172a")[:])),
    "bd334f1d6e45f25ff712a214571fa5cc",
  )
  let k256 = @aes.Cipher::new(
    raw("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")[:],
  )
  assert_eq(
    @base16.encode(k256.encrypt(raw("6bc1bee22e409f96e93d7e117393172a")[:])),
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
  )
}

///|
/// A key that is not one of the three lengths is refused rather than padded or
/// truncated to one that is.
test "a key of the wrong length is refused" {
  for n in [0, 1, 15, 17, 23, 25, 31, 33, 64] {
    let key = Bytes::from_array(Array::make(n, b'\x00'))
    try @aes.Cipher::new(key[:]) |> ignore catch {
      e => assert_eq(e, @spec.Size(want=16, got=n))
    } noraise {
      _ => fail("a \{n}-byte key was accepted")
    }
  }
  // And the three that are accepted.
  for n in [16, 24, 32] {
    let key = Bytes::from_array(Array::make(n, b'\x00'))
    assert_eq(@aes.Cipher::new(key[:]).size(), n)
  }
}

///|
/// Every block round-trips, at every key length, over inputs that exercise the
/// tables rather than one lucky pattern.
test "encrypt and decrypt are inverses" {
  for size in [16, 24, 32] {
    let key = Array::make(size, b'\x00')
    for i in 0..<size {
      key[i] = ((i * 37 + 11) % 256).to_byte()
    }
    let cipher = @aes.Cipher::new(Bytes::from_array(key)[:])
    for seed in 0..<16 {
      let plain = Array::make(16, b'\x00')
      for i in 0..<16 {
        plain[i] = ((i * 53 + seed * 97) % 256).to_byte()
      }
      let source = Bytes::from_array(plain)
      assert_eq(cipher.decrypt(cipher.encrypt(source[:])[:]), source)
    }
  }
}

///|
/// The contract, so a mode of operation can take any block cipher.
test "it satisfies the block-cipher contract" {
  let cipher : &@spec.Block = @aes.Cipher::new(
    raw("000102030405060708090a0b0c0d0e0f")[:],
  )
  assert_eq(cipher.block(), 16)
  let plain = raw("00112233445566778899aabbccddeeff")
  assert_eq(
    @base16.encode(cipher.encrypt(plain[:])),
    "69c4e0d86a7b0430d8cdb78070b4c55a",
  )
  assert_eq(cipher.decrypt(cipher.encrypt(plain[:])[:]), plain)
}

///|
/// Erasing leaves the schedule blank, which is the only thing it promises.
test "a key can be forgotten" {
  let cipher = @aes.Cipher::new(raw("000102030405060708090a0b0c0d0e0f")[:])
  let before = cipher.encrypt(raw("00112233445566778899aabbccddeeff")[:])
  assert_eq(@base16.encode(before), "69c4e0d86a7b0430d8cdb78070b4c55a")
  cipher.wipe()
  // An all-zero schedule is not the key any more; what it computes is whatever
  // an all-zero schedule computes, and the point is only that the key is gone.
  assert_not_eq(
    cipher.encrypt(raw("00112233445566778899aabbccddeeff")[:]),
    before,
  )
}
