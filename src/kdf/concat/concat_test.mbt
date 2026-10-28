// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The vectors come from `scripts/gen_concat_vectors.py`, which computes each one
// twice — once from the definition, once with `cryptography`'s ConcatKDFHash —
// and refuses to emit unless the two agree.

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// A hash factory for a named hash.
fn hash_of(name : String) -> () -> &@spec.Hash {
  match name {
    "sha1" => fn() -> &@spec.Hash { @sha1.Hasher::new() }
    "sha256" => fn() -> &@spec.Hash { @sha2.Hasher::new() }
    _ => fn() -> &@spec.Hash { @sha2.Hasher::new(kind=Sha512) }
  }
}

///|
/// One vector: a secret, whatever the protocol binds in, and the length asked for.
struct Case {
  hash : String
  z : String
  other : String
  len : Int32
  expected : String
} derive(Debug)

///|
/// Lengths are chosen to land on, just under and just over a block boundary for
/// each digest, and the last case asks for more than three blocks at once.
test "concat kdf matches the reference" {
  let cases : Array[Case] = [
    {
      hash: "sha256",
      z: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      other: "",
      len: 32,
      expected: "22b288a146b89e364069f6f367618a0ebeb5b83e5462685ab127b8edf8d2690a",
    },
    {
      hash: "sha256",
      z: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      other: "",
      len: 31,
      expected: "22b288a146b89e364069f6f367618a0ebeb5b83e5462685ab127b8edf8d269",
    },
    {
      hash: "sha256",
      z: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      other: "",
      len: 33,
      expected: "22b288a146b89e364069f6f367618a0ebeb5b83e5462685ab127b8edf8d2690a94",
    },
    {
      hash: "sha256",
      z: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      other: "0001020304050607",
      len: 16,
      expected: "a70e3b9787f2b2d1a4505c74715693a5",
    },
    {
      hash: "sha256",
      z: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      other: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      len: 96,
      expected: "0a236de3ead4d6b41dbe2e32be21e83f80239296c5cd0d9be30d023d9090fa19c25c9e92953014c525e0f1e1ce92d392f9a01906539ace1da38c2b3206376351bad105663ce77082e11917fa2099aa46dcfddcc53db4e0987929a8c3cf558521",
    },
    { hash: "sha256", z: "00", other: "", len: 1, expected: "06", },
    {
      hash: "sha1",
      z: "000102030405060708090a0b0c0d0e0f10111213",
      other: "",
      len: 20,
      expected: "5de0760743712793f903cb7c497010455c5b74ae",
    },
    {
      hash: "sha1",
      z: "000102030405060708090a0b0c0d0e0f10111213",
      other: "",
      len: 21,
      expected: "5de0760743712793f903cb7c497010455c5b74aeb7",
    },
    {
      hash: "sha1",
      z: "000102030405060708090a0b0c0d0e0f10111213",
      other: "000102030405060708090a0b",
      len: 40,
      expected: "9e52d6b0498f7fb93c9ee4bcbef9d7c843fe5b2da69fab9594b92cc07deac71395d576c0d47638bb",
    },
    {
      hash: "sha512",
      z: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      other: "",
      len: 64,
      expected: "ea743a7d7be24ccdff8f32ef7b2f0e0e3b943de044767c8a09e711f44e78e87d4c4414ab9281763e7cd47dbe5020089b8a45c09acd1d5e640f6cdeba21b4a1a2",
    },
    {
      hash: "sha512",
      z: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      other: "",
      len: 65,
      expected: "ea743a7d7be24ccdff8f32ef7b2f0e0e3b943de044767c8a09e711f44e78e87d4c4414ab9281763e7cd47dbe5020089b8a45c09acd1d5e640f6cdeba21b4a1a2a4",
    },
    {
      hash: "sha512",
      z: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      other: "0001020304",
      len: 200,
      expected: "480aa1d3b687ff3c7b8165ac0c142359425f0e4bc1f23688d678dec3fa3eae94531020f47b94707e5b754ddbad63c301ac03fd9ebb39f37557051c0f6b51bd6d997345141081ebf58ae8264110e5200ca47acc69b2cec152c211f6e04fe6ac03875c55fa84f85705a99b133404032caf4e7a26022a94ac85f231afe3be49d0c6ae0370a4e7264d22bfde331b161cabdf9ceac86e108fe7376373a30670944a0d97a5ac70614cc33d44ef64ddc88cf0fd047bd55fc9a251e8280e41afd268cd6cfd71803f79f1ca26",
    },
  ]
  for case in cases {
    let got = @concat.key(
      raw(case.z)[:],
      hash_of(case.hash),
      other_info=raw(case.other)[:],
      len=case.len,
    )
    assert_eq(got, raw(case.expected))
    assert_eq(got.length(), case.len)
  }
}

///|
/// Asking for one byte, or for a length that is one short of a block, gives the
/// prefix of the longer output — the counter only advances when a block is
/// finished, so every shorter request is a truncation of a longer one.
test "a short request is a prefix of a long one" {
  let z = raw("000102030405060708090a0b0c0d0e0f")
  let full = @concat.key(z[:], hash_of("sha256"), len=96)
  for len in [1, 31, 32, 33, 64, 95, 96] {
    let part = @concat.key(z[:], hash_of("sha256"), len~)
    assert_eq(part, full[0:len].to_owned())
  }
}

///|
/// The OtherInfo octets are part of the derivation: the same secret under two
/// different bindings gives two unrelated keys.
test "other info separates the outputs" {
  let z = raw("000102030405060708090a0b0c0d0e0f")
  let a = @concat.key(z[:], hash_of("sha256"), other_info=raw("01")[:], len=32)
  let b = @concat.key(z[:], hash_of("sha256"), other_info=raw("02")[:], len=32)
  assert_true(a != b)
  // And an absent OtherInfo is not the same as a one-byte zero one.
  let none = @concat.key(z[:], hash_of("sha256"), len=32)
  assert_true(none != a)
  assert_true(none != b)
}
