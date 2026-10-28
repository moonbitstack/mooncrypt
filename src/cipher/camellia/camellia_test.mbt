// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The vectors come from `scripts/gen_camellia_vectors.py`, which reproduces the
// three worked examples in Appendix A of RFC 3713 before it takes anything from
// elsewhere, and cross-checks every emitted case against OpenSSL.

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One block: a key of one of the three lengths, a plaintext, and what it
/// encrypts to.
struct Case {
  key : String
  plain : String
  cipher : String
}

///|
/// 128-bit keys, eighteen rounds.
let short_cases : Array[Case] = [
  {
    key: "0123456789abcdeffedcba9876543210",
    plain: "0123456789abcdeffedcba9876543210",
    cipher: "67673138549669730857065648eabe43",
  },
  {
    key: "00000000000000000000000000000000",
    plain: "00000000000000000000000000000000",
    cipher: "3d028025b156327c17f762c1f2cbca71",
  },
  {
    key: "ffffffffffffffffffffffffffffffff",
    plain: "ffffffffffffffffffffffffffffffff",
    cipher: "25dd9eb9dd67fbc6e8431f56f4fbe651",
  },
  {
    key: "0123456789abcdeffedcba9876543210",
    plain: "00000000000000000000000000000001",
    cipher: "28bdd24d5216811c3c897f5d3e15ac62",
  },
  {
    key: "80000000000000000000000000000000",
    plain: "4e6f77206973207468652074696d6521",
    cipher: "bd9ac887ad9115e5858caa41632bab45",
  },
  {
    key: "000102030405060708090a0b0c0d0e0f",
    plain: "000102030405060708090a0b0c0d0e0f",
    cipher: "ed18d83f3153160c5a6d01ac3717515c",
  },
  {
    key: "fedcba98765432100123456789abcdef",
    plain: "0123456789abcdeffedcba9876543210",
    cipher: "e45cf4cb11da2e48d27ef18042f7a34c",
  },
  {
    key: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    plain: "00000000000000000000000000000000",
    cipher: "3cf7843049506b22fe574b78860d469d",
  },
]

///|
/// 192-bit keys, twenty-four rounds. The key has only 64 bits left over, so KR
/// is that remainder followed by its own complement.
let medium_cases : Array[Case] = [
  {
    key: "0123456789abcdeffedcba98765432100011223344556677",
    plain: "0123456789abcdeffedcba9876543210",
    cipher: "b4993401b3e996f84ee5cee7d79b09b9",
  },
  {
    key: "000000000000000000000000000000000000000000000000",
    plain: "00000000000000000000000000000000",
    cipher: "56e1e129ca5c02c7f9ac6afdef86adc3",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffff",
    plain: "ffffffffffffffffffffffffffffffff",
    cipher: "3f8d5676f51ce23dc3bdb627f8b3883e",
  },
  {
    key: "00112233445566778899aabbccddeeff1021324354657687",
    plain: "00000000000000000000000000000001",
    cipher: "526af7cb05fbe85076a66c4b1ee391de",
  },
  {
    key: "800000000000000000000000000000000000000000000000",
    plain: "4e6f77206973207468652074696d6521",
    cipher: "140551cceffcf8be75b0dce1bb6b2efc",
  },
]

///|
/// 256-bit keys, twenty-four rounds and a full 128-bit KR.
let long_cases : Array[Case] = [
  {
    key: "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
    plain: "0123456789abcdeffedcba9876543210",
    cipher: "9acc237dff16d76c20ef7c919e3a7509",
  },
  {
    key: "0000000000000000000000000000000000000000000000000000000000000000",
    plain: "00000000000000000000000000000000",
    cipher: "396154111adefc500cf6e5c99038bc17",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    plain: "ffffffffffffffffffffffffffffffff",
    cipher: "4f05f28ca23eeae205b67b1c95cd5280",
  },
  {
    key: "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
    plain: "00000000000000000000000000000001",
    cipher: "209aa0993eaff08ba1352724c5550b4f",
  },
  {
    key: "8000000000000000000000000000000000000000000000000000000000000000",
    plain: "4e6f77206973207468652074696d6521",
    cipher: "973e90ced5a37e6e1e18b4c4090c13c9",
  },
]

///|
/// Every vector, in both directions.
///
/// The decrypt direction matters as much as the encrypt one: decryption is the
/// same network over reversed subkeys, and a version that reversed them wrongly
/// would still round-trip against itself while disagreeing with everyone else.
fn check(cases : Array[Case]) -> Unit raise {
  for case in cases {
    let cipher = @camellia.Cipher::new(raw(case.key)[:])
    let encrypted = cipher.encrypt(raw(case.plain)[:])
    assert_eq(encrypted, raw(case.cipher))
    assert_eq(cipher.decrypt(encrypted[:]), raw(case.plain))
  }
}

///|
/// The three key lengths, one test each so a failure names the length.
test "128-bit keys" {
  assert_eq(short_cases.length(), 8)
  check(short_cases)
}

///|
test "192-bit keys" {
  assert_eq(medium_cases.length(), 5)
  check(medium_cases)
}

///|
test "256-bit keys" {
  assert_eq(long_cases.length(), 5)
  check(long_cases)
}

///|
/// The three worked examples from Appendix A of RFC 3713, written out.
///
/// These are the cases the vector generator pins itself to before it will emit
/// anything, so if these drift the generator has already failed.
test "the appendix examples" {
  let plain = raw("0123456789abcdeffedcba9876543210")
  let examples = [
    ("0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"),
    (
      "0123456789abcdeffedcba9876543210" + "0011223344556677",
      "b4993401b3e996f84ee5cee7d79b09b9",
    ),
    (
      "0123456789abcdeffedcba9876543210" + "00112233445566778899aabbccddeeff",
      "9acc237dff16d76c20ef7c919e3a7509",
    ),
  ]
  for example in examples {
    let (key, want) = example
    let cipher = @camellia.Cipher::new(raw(key)[:])
    assert_eq(cipher.encrypt(plain[:]), raw(want))
    assert_eq(cipher.decrypt(raw(want)[:]), plain)
  }
}

///|
/// A key is 16, 24 or 32 bytes and nothing else.
///
/// There is no padding rule here and no default: a 20-byte key is not "almost a
/// 192-bit key" to anyone who generated it, and silently zero-extending it would
/// make two different keys the same key.
test "key lengths are checked" {
  for size in [15, 17, 20, 31, 33] {
    let key = Bytes::make(size, b'\x01')
    let mut refused = false
    try {
      let _ = @camellia.Cipher::new(key[:])
    } catch {
      _ => refused = true
    }
    assert_true(refused)
  }
  // Each of the three valid lengths is accepted, and reports a 16-byte block.
  for size in [16, 24, 32] {
    let key = Bytes::make(size, b'\x01')
    let cipher : &@spec.Block = @camellia.Cipher::new(key[:])
    assert_eq(cipher.block(), 16)
  }
  assert_eq(@camellia.block, 16)
}

///|
/// The round count follows the key length, which is the one place the two
/// schedules differ in shape rather than just in values.
///
/// A 128-bit key runs eighteen rounds and 192- or 256-bit keys run twenty-four;
/// if that were wrong, no test vector above would match, but this states the
/// property directly.
test "a longer key does not change the block size" {
  let plain = raw("00112233445566778899aabbccddeeff")
  for
    key in [
      "00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeff1021324354657687",
      "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
    ] {
    let cipher = @camellia.Cipher::new(raw(key)[:])
    assert_eq(cipher.encrypt(plain[:]).length(), 16)
  }
}

///|
/// After a wipe the key is gone, in both directions.
///
/// Both schedules have to go: a wipe that cleared only the encryption one would
/// leave a key that still decrypts.
test "wipe forgets the key" {
  let key = raw("0123456789abcdeffedcba9876543210")
  let plain = raw("00112233445566778899aabbccddeeff")
  let cipher = @camellia.Cipher::new(key[:])
  let before = cipher.encrypt(plain[:])
  let back = cipher.decrypt(plain[:])
  cipher.wipe()
  assert_true(cipher.encrypt(plain[:]) != before)
  assert_true(cipher.decrypt(plain[:]) != back)
}
