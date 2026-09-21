// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : Bytes) -> String {
  @base16.encode(b[:])
}

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
fn sha256() -> &@spec.Hash {
  @sha2.Hasher::new()
}

///|
fn sha1() -> &@spec.Hash {
  @sha1.Hasher::new()
}

///|
/// RFC 6070's vectors, minus the 16 777 216-round case, which proves nothing the
/// 4096-round case does not and costs a minute of every test run. The case with
/// a NUL inside the password is the one that catches an implementation treating
/// it as a C string.
test "PBKDF2-HMAC-SHA1 matches RFC 6070" {
  let cases = [
    (
      "70617373776f7264", "73616c74", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6",
    ),
    (
      "70617373776f7264", "73616c74", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
    ),
    (
      "70617373776f7264", "73616c74", 4096, 20, "4b007901b765489abead49d926f721d065a429c1",
    ),
    (
      "70617373776f726450415353574f524470617373776f7264", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74",
      4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
    ),
    (
      "7061737300776f7264", "7361006c74", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3",
    ),
  ]
  for case in cases {
    let (password, salt, rounds, len, want) = case
    assert_eq(
      hex(@pbkdf2.key(raw(password)[:], raw(salt)[:], sha1, rounds~, len~)),
      want,
    )
  }
}

///|
/// The SHA-256 vectors that SCRAM-SHA-256 implementations are checked against.
test "PBKDF2-HMAC-SHA256 matches the published vectors" {
  let cases = [
    (
      "70617373776f7264", "73616c74", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    ),
    (
      "70617373776f7264", "73616c74", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
    ),
    (
      "70617373776f7264", "73616c74", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
    ),
    (
      "706173737764", "73616c74", 1, 64, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
    ),
  ]
  for case in cases {
    let (password, salt, rounds, len, want) = case
    assert_eq(
      hex(@pbkdf2.key(raw(password)[:], raw(salt)[:], sha256, rounds~, len~)),
      want,
    )
  }
}

///|
/// A key longer than one digest must continue rather than repeat: the counter
/// goes into the first HMAC of each block, so every block is its own derivation.
test "output spans several blocks without repeating" {
  let dk = @pbkdf2.key(b"password"[:], b"salt"[:], sha256, rounds=2, len=96)
  assert_eq(dk.length(), 96)
  assert_not_eq(dk[0:32].to_owned(), dk[32:64].to_owned())
  assert_not_eq(dk[32:64].to_owned(), dk[64:96].to_owned())
  assert_eq(
    @pbkdf2.key(b"password"[:], b"salt"[:], sha256, rounds=2, len=20),
    dk[0:20].to_owned(),
  )
}

///|
/// More rounds must give a different key, or the iteration is not happening.
test "the round count reaches the output" {
  let one = @pbkdf2.key(b"password"[:], b"salt"[:], sha256, rounds=1, len=32)
  let two = @pbkdf2.key(b"password"[:], b"salt"[:], sha256, rounds=2, len=32)
  assert_not_eq(one, two)
}
