// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Checked against an independent implementation of SP 800-90A §10.1.1: a fresh
/// SHA-256 instance drawn for 64 bytes.
test "Hash-DRBG SHA-256 matches a reference implementation" {
  let entropy = @base16.decode_lossy(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = @base16.decode_lossy("000102030405060708090a0b0c0d0e0f")
  let d = @drbg.HashDrbg::new(
    fn() { @sha2.Hasher::new() },
    entropy=entropy[:],
    nonce=nonce[:],
    personalization=b""[:],
  )
  assert_eq(
    @base16.encode(d.generate(64)[:]),
    "d9ec69e0c34ede1f27faf2343066375cc867ec99977a1d94b013660693f2b2cc" +
    "23673b6c3b8eb04ee1f50f10e56351b5b13321bb3bc060cfbf1315bc1c102109",
  )
}

///|
test "Hash-DRBG folds in personalization and additional input" {
  let entropy = @base16.decode_lossy(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = @base16.decode_lossy("000102030405060708090a0b0c0d0e0f")
  let d = @drbg.HashDrbg::new(
    fn() { @sha2.Hasher::new() },
    entropy=entropy[:],
    nonce=nonce[:],
    personalization=b"ctx"[:],
  )
  let a = d.generate_with(32, additional=b"additional"[:])
  let b = d.generate(32)
  assert_eq(
    @base16.encode(a[:]),
    "2a2c33fe808a3753ba693fc2bfc43630a9054fde933479370a569f62875f4eb9",
  )
  assert_eq(
    @base16.encode(b[:]),
    "c820ae9803187240e4cb9761fae693548fb4ecdac67d8ea84f75fdafb0f6fb7a",
  )
}
