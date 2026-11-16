// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// The example of the original paper, and blocks as OpenSSL's IDEA encrypts them: a second
/// implementation that shares no code with this one. The all-zero and all-one keys are the ones
/// whose subkeys hit the zero word that stands for 2^16 (`scripts/gen_legacy_block_vectors.py`).
test "IDEA matches the published example and OpenSSL" {
  let cases = [
    ("00010002000300040005000600070008", "0000000100020003", "11fbed2b01986de5"),
    (
      "fd1e9712bd06dc46f7fa1008b0c9cc6b", "4a880d7bf5991b11459e15d97a628bad75e4ccd558c0253e",
      "296ef4ad07466114bf7b5d1784840334210631ca69d725af",
    ),
    ("00000000000000000000000000000000", "0000000000000000", "0001000100000000"),
    ("ffffffffffffffffffffffffffffffff", "ffffffffffffffff", "cd1ab2c1211041fb"),
  ]
  for case in cases {
    let (key, plain, cipher) = case
    let c : &@spec.Block = @idea.Cipher::new(@base16.decode(key)[:])
    assert_eq(hex(c.encrypt_blocks(@base16.decode(plain)[:])), cipher)
    assert_eq(hex(c.decrypt_blocks(@base16.decode(cipher)[:])), plain)
  }
}

///|
test "IDEA refuses a key of another length, and forgets its schedule when wiped" {
  for size in [0, 8, 15, 17, 32] {
    let refused = try @idea.Cipher::new(Bytes::make(size, b'\x01')[:]) catch {
      Size(want=16, got~) => got == size
      _ => false
    } noraise {
      _ => false
    }
    assert_true(refused)
  }
  let c = @idea.Cipher::new(Bytes::make(16, b'\x07')[:])
  let block = Bytes::make(8, b'\x05')
  let before = c.encrypt(block[:])
  c.wipe()
  assert_true(c.encrypt(block[:]) != before)
  assert_eq(c.block(), 8)
}
