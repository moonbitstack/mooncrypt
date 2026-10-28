// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn unhex(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// A byte string of `n` copies of one value.
fn repeated(byte : Byte, n : Int32) -> Bytes {
  Bytes::from_array(FixedArray::make(n, byte))
}

///|
/// Whether an optional parse found something, without caring what it found.
fn found(value : (Int32, Bytes)?) -> Bool {
  match value {
    Some(_) => true
    None => false
  }
}

///|
/// Every vector in `vectors_test.mbt`: the same password and salt must produce
/// the same string, and the reference library is the only authority on what
/// that string is.
test "bcrypt matches the reference library" {
  for vector in vectors {
    let (password, salt, cost, expected) = vector
    let stored = @bcrypt.encode(unhex(password)[:], unhex(salt)[:], cost~)
    assert_eq(stored, expected)
    assert_true(@bcrypt.verify(unhex(password)[:], expected))
  }
}

///|
/// The scheme's output is 24 bytes and the text format keeps 23 of them, so the
/// string is 31 characters after the salt: one character short of two full
/// base64 groups.
test "bcrypt keeps twenty-three of its twenty-four bytes" {
  let salt = unhex("43434343434343434343434343434343")
  let digest = @bcrypt.hash(b"password"[:], salt[:], cost=5)
  assert_eq(digest.length(), 24)
  let text = @bcrypt.encode(b"password"[:], salt[:], cost=5)
  assert_eq(text.length(), 60)
  assert_eq(
    text, "$2b$05$OyLBOyLBOyLBOyLBOyLBOukfy/WlNdjHyhR9VwUDAjC0biiUiTPse",
  )
  assert_true(@bcrypt.verify(b"password"[:], text))
}

///|
/// A stored hash carries its own cost and salt, so parsing one is enough to
/// re-derive it — and a single changed character anywhere in it is enough to
/// fail.
test "bcrypt reads a stored hash and checks it" {
  let text = "$2b$05$U56K5tMaI1mPGhLCTUX1g.kBBjIUknH4jn0mK8EKO48Hi.ftTzGrW"
  let password = b"correct horse battery staple"[:]
  assert_true(@bcrypt.verify(password, text))
  assert_true(!@bcrypt.verify(b"correct horse battery stapl"[:], text))
  assert_true(!@bcrypt.verify(b""[:], text))
  assert_true(
    !@bcrypt.verify(
      password, "$2b$05$U56K5tMaI1mPGhLCTUX1g.kBBjIUknH4jn0mK8EKO48Hi.ftTzGrX",
    ),
  )
  match @bcrypt.parse(text) {
    Some((cost, salt)) => {
      assert_eq(cost, 5)
      assert_eq(salt.length(), 16)
      assert_eq(@bcrypt.encode(password, salt[:], cost~), text)
    }
    None => fail("the string should parse")
  }
}

///|
/// The older prefixes name the same function here. `$2a$` is what most of the
/// world wrote, `$2x$` and `$2y$` are other implementations' spellings of the
/// same fix, and a hash made with any of them verifies.
test "bcrypt accepts the older prefixes" {
  let text = "$2b$05$U56K5tMaI1mPGhLCTUX1g.kBBjIUknH4jn0mK8EKO48Hi.ftTzGrW"
  let password = b"correct horse battery staple"[:]
  let encoded = @utf8.encode(text)
  for variant in [b'a', b'x', b'y'] {
    let copy : FixedArray[Byte] = FixedArray::make(encoded.length(), b' ')
    for i in 0..<encoded.length() {
      copy[i] = encoded[i]
    }
    copy[2] = variant
    let alt = @utf8.decode_lossy(Bytes::from_array(copy))
    assert_true(@bcrypt.verify(password, alt))
  }
}

///|
/// Malformed strings do not raise and do not verify: too short, wrong prefix, a
/// cost outside the format, a character outside the alphabet, and a salt whose
/// last character sets bits that the sixteen bytes have no room for.
test "bcrypt refuses strings that are not hashes" {
  let password = b"password"[:]
  let bad = [
    "", "$2b$05$", "$3b$05$U56K5tMaI1mPGhLCTUX1g.kBBjIUknH4jn0mK8EKO48Hi.ftTzGrW",
    "$2b$03$U56K5tMaI1mPGhLCTUX1g.kBBjIUknH4jn0mK8EKO48Hi.ftTzGrW", "$2b$32$U56K5tMaI1mPGhLCTUX1g.kBBjIUknH4jn0mK8EKO48Hi.ftTzGrW",
    "$2b$05$U56K5tMaI1mPGhLCTUX1g!kBBjIUknH4jn0mK8EKO48Hi.ftTzGrW",
    // 'z' in the last salt position would set bits past the sixteenth byte.
     "$2b$05$U56K5tMaI1mPGhLCTUX1gz.kBBjIUknH4jn0mK8EKO48Hi.ftTzGrW",
  ]
  for text in bad {
    assert_true(!found(@bcrypt.parse(text)))
    assert_true(!@bcrypt.verify(password, text))
  }
}

///|
/// The length limits the format imposes: seventy-two bytes is the most password
/// it can use, and sixteen bytes is the only salt it can store.
test "bcrypt enforces the format's limits" {
  let salt = unhex("43434343434343434343434343434343")
  let text = @bcrypt.encode(repeated(b'z', 72)[:], salt[:], cost=4)
  assert_eq(text, longest_password)
  assert_true(@bcrypt.verify(repeated(b'z', 72)[:], text))
  let mut too_long = false
  try {
    let _ = @bcrypt.hash(repeated(b'z', 73)[:], salt[:], cost=4)
  } catch {
    @spec.Broken::Size(want~, got~) => {
      assert_eq(want, @bcrypt.max_password)
      assert_eq(got, 73)
      too_long = true
    }
    _ => fail("expected a size error")
  }
  assert_true(too_long)
  let mut bad_salt = false
  try {
    let _ = @bcrypt.hash(b"password"[:], unhex("4343")[:], cost=4)
  } catch {
    @spec.Broken::Size(want~, got~) => {
      assert_eq(want, @bcrypt.salt_size)
      assert_eq(got, 2)
      bad_salt = true
    }
    _ => fail("expected a size error")
  }
  assert_true(bad_salt)
  assert_eq(@bcrypt.min_cost, 4)
  assert_eq(@bcrypt.max_cost, 31)
  assert_eq(@bcrypt.default_cost, 12)
}
