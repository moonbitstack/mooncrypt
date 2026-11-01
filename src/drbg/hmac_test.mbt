// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn unhex(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
fn sha() -> &@spec.Hash {
  @sha2.Hasher::new()
}

///|
test "HMAC-DRBG SHA-256 matches an independent implementation" {
  let entropy = unhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = unhex("000102030405060708090a0b0c0d0e0f")
  let drbg = @drbg.HmacDrbg::new(
    sha,
    entropy=entropy[:],
    nonce=nonce[:],
    personalization=b""[:],
  )
  // Drawn through the `Source` contract, which is how a key generator takes it.
  let out = @moonseed.bytes(64, drbg) catch {
    _ => abort("hmac-drbg: a generator must never exhaust")
  }
  assert_eq(
    @base16.encode(out[:]),
    "3e0013f6f1e74912f56fec7e73bb590c06ecd0f69e1fe019c2e04063e9207ab9" +
    "3042fbef098b1e5ed61856bb1b807fd4b23839e62f885d76082eebe1fa43e8e2",
  )
}

///|
test "HMAC-DRBG folds in personalization and additional input" {
  let entropy = unhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = unhex("000102030405060708090a0b0c0d0e0f")
  let perso = unhex("637478")
  let additional = unhex("6164646974696f6e616c")
  let drbg = @drbg.HmacDrbg::new(
    sha,
    entropy=entropy[:],
    nonce=nonce[:],
    personalization=perso[:],
  )
  let a = drbg.generate_with(32, additional=additional[:])
  let b = drbg.generate(32)
  assert_eq(
    @base16.encode(a[:]),
    "c4f6ca5c1f1cbcd6457521c4df9294b0030dff07050de4aadf5c5ee7e5187de0",
  )
  assert_eq(
    @base16.encode(b[:]),
    "543ec2540b7dce5c8ba2b510f6dceffbe23eb474131fc30f77adf82dd4742c84",
  )
}

///|
test "HMAC-DRBG reseeds and continues" {
  let entropy = unhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = unhex("000102030405060708090a0b0c0d0e0f")
  let drbg = @drbg.HmacDrbg::new(
    sha,
    entropy=entropy[:],
    nonce=nonce[:],
    personalization=b""[:],
  )
  let pre = drbg.generate(16)
  assert_eq(@base16.encode(pre[:]), "3e0013f6f1e74912f56fec7e73bb590c")
  let fresh = unhex(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  )
  let add = unhex("7265736565642d656e74726f7079")
  drbg.reseed(entropy=fresh[:], additional=add[:])
  let post = drbg.generate(32)
  assert_eq(
    @base16.encode(post[:]),
    "fdf05b14e75e4c2be75976138ae245d4bb87fba746ea0496861310ca3c4c4940",
  )
}
