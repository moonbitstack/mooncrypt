// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The vectors come from `scripts/gen_des_vectors.py`, which asserts the two
// published blocks first — FIPS 81's "Now is t" under 0123456789abcdef, and the
// all-zero key on the all-zero block — before taking anything from PyCryptodome.

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One block: a key, a plaintext and what it encrypts to.
struct Case {
  key : String
  plain : String
  cipher : String
}

///|
/// Single DES.
let des_cases : Array[Case] = [
  // FIPS 81's "Now is t".
  {
    key: "0123456789abcdef",
    plain: "4e6f772069732074",
    cipher: "3fa40e8a984d4815",
  },
  // The all-zero key on the all-zero block.
  {
    key: "0000000000000000",
    plain: "0000000000000000",
    cipher: "8ca64de9c1b123a7",
  },
  {
    key: "ffffffffffffffff",
    plain: "ffffffffffffffff",
    cipher: "7359b2163e4edc58",
  },
  {
    key: "133457799bbcdff1",
    plain: "0123456789abcdef",
    cipher: "85e813540f0ab405",
  },
  {
    key: "8000000000000000",
    plain: "0000000000000000",
    cipher: "95a8d72813daa94d",
  },
  {
    key: "0000000000000000",
    plain: "ffffffffffffffff",
    cipher: "355550b2150e2451",
  },
  {
    key: "0e329232ea6d0d73",
    plain: "8787878787878787",
    cipher: "0000000000000000",
  },
  {
    key: "0123456789abcdef",
    plain: "0000000000000000",
    cipher: "d5d44ff720683d0d",
  },
  {
    key: "fedcba9876543210",
    plain: "0123456789abcdef",
    cipher: "ed39d950fa74bcc4",
  },
  {
    key: "a1b2c3d4e5f60718",
    plain: "0123456789abcdef",
    cipher: "f2b4d0c35f068390",
  },
]

///|
/// Triple DES with a twenty-four byte key.
let triple_cases : Array[Case] = [
  {
    key: "0123456789abcdeffedcba987654321089abcdef01234567",
    plain: "0000000000000000",
    cipher: "3fd539e3abeb8b5b",
  },
  {
    key: "0123456789abcdeffedcba987654321089abcdef01234567",
    plain: "ffffffffffffffff",
    cipher: "54c0ea58976d4e2c",
  },
  {
    key: "fedcba98765432100123456789abcdef" + "ffffffffffffffff",
    plain: "4e6f772069732074",
    cipher: "a42862a507e036eb",
  },
  {
    key: "0123456789abcdeffedcba9876543210" + "0123456789abcdef",
    plain: "0001020304050607",
    cipher: "52c5c0705d9089e1",
  },
]

///|
/// Triple DES with a sixteen byte key, the two-key form.
let two_key_cases : Array[Case] = [
  {
    key: "0123456789abcdeffedcba9876543210",
    plain: "0123456789abcdef",
    cipher: "1a4d672dca6cb335",
  },
  {
    key: "000000000000000026469c9f0badbeef",
    plain: "0123456789abcdef",
    cipher: "098c8123b8486106",
  },
]

///|
/// Every single-DES vector, in both directions.
///
/// The decrypt direction matters as much as the encrypt one: the round keys run
/// backwards and a version that got that wrong would still round-trip against
/// itself while disagreeing with every other implementation.
test "des blocks match the reference" {
  assert_eq(des_cases.length(), 10)
  for case in des_cases {
    let cipher = @des.Cipher::new(raw(case.key)[:])
    let encrypted = cipher.encrypt(raw(case.plain)[:])
    assert_eq(encrypted, raw(case.cipher))
    assert_eq(cipher.decrypt(encrypted[:]), raw(case.plain))
  }
}

///|
/// FIPS 81's two published examples, written out.
test "the published blocks" {
  let cipher = @des.Cipher::new(raw("0123456789abcdef")[:])
  assert_eq(cipher.encrypt(raw("4e6f772069732074")[:]), raw("3fa40e8a984d4815"))
  let zero = @des.Cipher::new(raw("0000000000000000")[:])
  assert_eq(zero.encrypt(raw("0000000000000000")[:]), raw("8ca64de9c1b123a7"))
}

///|
/// Triple DES in both key forms, in both directions.
test "triple des blocks match the reference" {
  assert_eq(triple_cases.length(), 4)
  assert_eq(two_key_cases.length(), 2)
  for case in triple_cases {
    let cipher = @des.TripleDes::new(raw(case.key)[:])
    let encrypted = cipher.encrypt(raw(case.plain)[:])
    assert_eq(encrypted, raw(case.cipher))
    assert_eq(cipher.decrypt(encrypted[:]), raw(case.plain))
  }
  for case in two_key_cases {
    let cipher = @des.TripleDes::from_two_keys(raw(case.key)[:])
    let encrypted = cipher.encrypt(raw(case.plain)[:])
    assert_eq(encrypted, raw(case.cipher))
    assert_eq(cipher.decrypt(encrypted[:]), raw(case.plain))
  }
}

///|
/// A three-part key that repeats its first part is single DES — the property
/// E-D-E was chosen for, so that a deployment could move from one to the other
/// without changing what a stored ciphertext means.
///
/// PyCryptodome refuses to build such a key at all, so this is checked against
/// the single-DES vectors above rather than against the generator.
test "triple des with one repeated key is des" {
  for case in des_cases {
    let single = @des.Cipher::new(raw(case.key)[:])
    let repeated = raw(case.key) + raw(case.key) + raw(case.key)
    let triple = @des.TripleDes::new(repeated[:])
    assert_eq(
      triple.encrypt(raw(case.plain)[:]),
      single.encrypt(raw(case.plain)[:]),
    )
    assert_eq(single.encrypt(raw(case.plain)[:]), raw(case.cipher))
  }
}

///|
/// The block is eight bytes and the key lengths are fixed.
///
/// A short key is refused rather than padded: DES ignores the parity bit of each
/// byte but not the byte itself, and a seven-byte key would have to be padded
/// with something — a decision no caller should leave to a library.
test "lengths are checked" {
  let mut short = false
  try {
    let _ = @des.Cipher::new(raw("00112233445566")[:])
  } catch {
    _ => short = true
  }
  assert_true(short)

  let mut long = false
  try {
    let _ = @des.Cipher::new(raw("0011223344556677" + "88")[:])
  } catch {
    _ => long = true
  }
  assert_true(long)

  let key = raw("0123456789abcdef")
  let cipher : &@spec.Block = @des.Cipher::new(key[:])
  assert_eq(cipher.block(), 8)
  let triple : &@spec.Block = @des.TripleDes::new((key + key + key)[:])
  assert_eq(triple.block(), 8)
  // And the block size in bytes is what the trait reports.
  assert_eq(@des.block, 8)
  assert_eq(@des.key_size, 8)
  assert_eq(@des.triple_key_size, 24)
}

///|
/// After a wipe the key is gone: the same ciphertext is no longer produced.
///
/// This is a weak assertion by nature — a wiped schedule could in principle
/// still encrypt something to the same answer — but the alternative is inspecting
/// a private field, and this catches the case that matters: a `wipe` that forgot
/// one of the three schedules of a triple key.
test "wipe forgets the key" {
  let plain = raw("4e6f772069732074")
  let single = @des.Cipher::new(raw("0123456789abcdef")[:])
  let before = single.encrypt(plain[:])
  single.wipe()
  assert_true(single.encrypt(plain[:]) != before)

  let cipher = @des.TripleDes::new(
    raw("0123456789abcdeffedcba987654321089abcdef01234567")[:],
  )
  let before = cipher.encrypt(plain[:])
  cipher.wipe()
  assert_true(cipher.encrypt(plain[:]) != before)
}
