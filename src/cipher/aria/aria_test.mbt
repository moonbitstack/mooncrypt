// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// RFC 5794 Appendix A: one block under each key length.
test "ARIA matches RFC 5794's example data" {
  let plain = @base16.decode("00112233445566778899aabbccddeeff")
  let cases = [
    ("000102030405060708090a0b0c0d0e0f", "d718fbd6ab644c739da95f3be6451778"),
    (
      "000102030405060708090a0b0c0d0e0f1011121314151617", "26449c1805dbe7aa25a468ce263a9e79",
    ),
    (
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "f92bd7c79fb72e2f2b8f80c1972d24fc",
    ),
  ]
  for case in cases {
    let (key, cipher) = case
    let c = @aria.Cipher::new(@base16.decode(key)[:])
    assert_eq(hex(c.encrypt(plain[:])), cipher)
    assert_eq(hex(c.decrypt(@base16.decode(cipher)[:])), hex(plain))
  }
}

///|
/// Two blocks under each key length as OpenSSL's ARIA encrypts them, a second implementation
/// that shares no code with this one (`scripts/gen_legacy_block_vectors.py`).
test "ARIA agrees with OpenSSL block by block" {
  let plain = @base16.decode(
    "8c11eef4eded10b20645b9730b869d9044354dc7d90e7a634a1e7133eb25af5d",
  )
  let cases = [
    (
      "d90ab3000f0ce57d3b6ef1eb4a647579", "d72ee1eb5390f754407aec423df23e78f835e3b3cd3a68180768f2fc84e9c81e",
    ),
    (
      "7fbcf43c568bd7a68cb5b54ea8de7c7bc400060af671be97", "01d47b09185b0a56811c799a35216d9ced512ab23b95b8a97ed0a476d22b0f36",
    ),
    (
      "86209d16f23cc67eb00561b58aa2f61ba973c520e665ffa93b8d9052e37f10b3", "d0ce93d9da5b18af8117db3a33ba7a8fc3f639decf158e8c6adbbd5574c430cb",
    ),
  ]
  for case in cases {
    let (key, cipher) = case
    let c : &@spec.Block = @aria.Cipher::new(@base16.decode(key)[:])
    assert_eq(hex(c.encrypt_blocks(plain[:])), cipher)
    assert_eq(hex(c.decrypt_blocks(@base16.decode(cipher)[:])), hex(plain))
  }
}

///|
test "ARIA refuses a key of another length" {
  for size in [0, 15, 17, 23, 31, 33] {
    let key = Bytes::make(size, b'\x01')
    let refused = try @aria.Cipher::new(key[:]) catch {
      Size(want=32, got~) => got == size
      _ => false
    } noraise {
      _ => false
    }
    assert_true(refused)
  }
}

///|
test "ARIA forgets its schedule when wiped" {
  let key = @base16.decode("000102030405060708090a0b0c0d0e0f")
  let c = @aria.Cipher::new(key[:])
  let block = Bytes::make(16, b'\x00')
  let before = c.encrypt(block[:])
  c.wipe()
  assert_true(c.encrypt(block[:]) != before)
  assert_eq(c.block(), @aria.block)
}
