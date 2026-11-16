// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// RFC 4269 Appendix B: the four test vectors.
test "SEED matches RFC 4269's test vectors" {
  let cases = [
    (
      "00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "5ebac6e0054e166819aff1cc6d346cdb",
    ),
    (
      "000102030405060708090a0b0c0d0e0f", "00000000000000000000000000000000", "c11f22f20140505084483597e4370f43",
    ),
    (
      "4706480851e61be85d74bfb3fd956185", "83a2f8a288641fb9a4e9a5cc2f131c7d", "ee54d13ebcae706d226bc3142cd40d4a",
    ),
    (
      "28dbc3bc49ffd87dcfa509b11d422be7", "b41e6be2eba84a148e2eed84593c5ec7", "9b9b7bfcd1813cb95d0b3618f40f5122",
    ),
  ]
  for case in cases {
    let (key, plain, cipher) = case
    let c = @seed.Cipher::new(@base16.decode(key)[:])
    assert_eq(hex(c.encrypt(@base16.decode(plain)[:])), cipher)
    assert_eq(hex(c.decrypt(@base16.decode(cipher)[:])), plain)
  }
}

///|
/// Two blocks as OpenSSL's SEED encrypts them, a second implementation that shares no code with
/// this one (`scripts/gen_legacy_block_vectors.py`).
test "SEED agrees with OpenSSL block by block" {
  let c : &@spec.Block = @seed.Cipher::new(
    @base16.decode("65259aac581f0a388782f0b297301e46")[:],
  )
  let plain = "ce937d4ea23626554cb26406f2d7ae3039fdd26c9e09a92dd83417759be89ab6"
  let cipher = "0d1dc4d9ccbe19db899d5ea79915b20698e0b8ffa12c8e65fd109034c7b2d8f7"
  assert_eq(hex(c.encrypt_blocks(@base16.decode(plain)[:])), cipher)
  assert_eq(hex(c.decrypt_blocks(@base16.decode(cipher)[:])), plain)
}

///|
test "SEED refuses a key of another length, and forgets its schedule when wiped" {
  for size in [0, 15, 17, 24, 32] {
    let refused = try @seed.Cipher::new(Bytes::make(size, b'\x01')[:]) catch {
      Size(want=16, got~) => got == size
      _ => false
    } noraise {
      _ => false
    }
    assert_true(refused)
  }
  let c = @seed.Cipher::new(Bytes::make(16, b'\x07')[:])
  let zero = Bytes::make(16, b'\x00')
  let before = c.encrypt(zero[:])
  c.wipe()
  assert_true(c.encrypt(zero[:]) != before)
}
