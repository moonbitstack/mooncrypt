// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// GB/T 32907 §A.1: one block, encrypted with its own value as the key.
test "SM4 matches the GB/T 32907 example" {
  let key = @base16.decode("0123456789abcdeffedcba9876543210")
  let c = @sm4.Cipher::new(key[:])
  let block = key
  assert_eq(hex(c.encrypt(block[:])), "681edf34d206965e86b3e94f536e4246")
  assert_eq(hex(c.decrypt(c.encrypt(block[:])[:])), hex(block))
}

///|
/// Every byte of the key and of the block matters: a single flipped bit in
/// either gives an unrelated answer.
test "SM4 diffuses a changed key or block" {
  let zero = Bytes::from_array(Array::make(16, b'\x00'))
  let one : Bytes = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01,
  ]
  let a = @sm4.Cipher::new(zero[:])
  let b = @sm4.Cipher::new(one[:])
  assert_true(hex(a.encrypt(zero[:])) != hex(b.encrypt(zero[:])))
  assert_true(hex(a.encrypt(zero[:])) != hex(a.encrypt(one[:])))
  assert_eq(a.block(), 16)
  assert_eq(@sm4.block, 16)
  assert_eq(@sm4.key_size, 16)
}

///|
/// The trait, so SM4 can be the block cipher under any mode.
test "SM4 satisfies the Block contract" {
  let key = @base16.decode("0123456789abcdeffedcba9876543210")
  let c = @sm4.Cipher::new(key[:])
  let as_block : &@spec.Block = c
  assert_eq(as_block.block(), 16)
  let block = Bytes::from_array(Array::make(16, b'\x07'))
  assert_eq(hex(as_block.decrypt(as_block.encrypt(block[:])[:])), hex(block))
}

///|
/// A key of the wrong length is named, not silently truncated.
test "SM4 refuses a key of the wrong length" {
  let short = Bytes::from_array(Array::make(15, b'\x00'))
  try @sm4.Cipher::new(short[:]) |> ignore catch {
    e => assert_eq(e, @spec.Size(want=16, got=15))
  } noraise {
    _ => fail("a fifteen-byte key was accepted")
  }
}
