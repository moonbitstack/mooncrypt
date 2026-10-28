// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// A byte string of `n` copies of one value, which the key-length tests need.
fn repeated(byte : Byte, n : Int32) -> Bytes {
  Bytes::from_array(FixedArray::make(n, byte))
}

///|
/// The first vectors in Eric Young's Blowfish test set: an all-zero and an
/// all-ones key against the matching plaintext.
///
/// They are worth keeping even though bcrypt would catch a broken core, because
/// they test the plain key schedule that bcrypt never runs — bcrypt only ever
/// uses the salted one.
test "blowfish encrypts the published known answers" {
  let zeros = repeated(b'\x00', 8)
  let ones = repeated(b'\xFF', 8)
  assert_eq(
    hex(@blowfish.Cipher::new(zeros[:]).encrypt(zeros[:])),
    "4ef997456198dd78",
  )
  assert_eq(
    hex(@blowfish.Cipher::new(ones[:]).encrypt(ones[:])),
    "51866fd5b85ecb8a",
  )
}

///|
/// Decryption undoes encryption, and the trait agrees with the inherent
/// methods.
test "blowfish round-trips a block" {
  let key = @base16.decode_lossy("0123456789abcdef")
  let cipher = @blowfish.Cipher::new(key[:])
  let plain = repeated(b'\x00', 8)
  let box = cipher.encrypt(plain[:])
  assert_eq(hex(cipher.decrypt(box[:])), hex(plain))
  assert_eq(hex(@spec.Block::encrypt(cipher, plain[:])), hex(box))
  assert_eq(hex(@spec.Block::decrypt(cipher, box[:])), hex(plain))
  assert_eq(@spec.Block::block(cipher), 8)
}

///|
/// The key must fall inside the range the specification names, and the error
/// says which bound was missed.
test "blowfish refuses keys it cannot take" {
  let mut short_refused = false
  try {
    let _ = @blowfish.Cipher::new(b"abc"[:])
  } catch {
    @spec.Broken::Size(want~, got~) => {
      assert_eq(want, @blowfish.min_key)
      assert_eq(got, 3)
      short_refused = true
    }
    _ => fail("expected a size error")
  }
  assert_true(short_refused)
  let mut long_refused = false
  try {
    let _ = @blowfish.Cipher::new(repeated(b'\x01', 57)[:])
  } catch {
    @spec.Broken::Size(want~, got~) => {
      assert_eq(want, @blowfish.max_key)
      assert_eq(got, 57)
      long_refused = true
    }
    _ => fail("expected a size error")
  }
  assert_true(long_refused)
}

///|
/// A wiped schedule is all zeroes, so it no longer encrypts the way the keyed
/// one did — which is the point of wiping it after a derivation.
test "blowfish forgets its schedule when wiped" {
  let key = @base16.decode_lossy("0123456789abcdef")
  let cipher = @blowfish.Cipher::new(key[:])
  let plain = repeated(b'\x00', 8)
  let before = hex(cipher.encrypt(plain[:]))
  cipher.wipe()
  assert_true(hex(cipher.encrypt(plain[:])) != before)
  assert_eq(@blowfish.block, 8)
  assert_eq(@blowfish.min_key, 4)
  assert_eq(@blowfish.max_key, 56)
}
