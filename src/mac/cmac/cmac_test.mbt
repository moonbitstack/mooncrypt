// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn unhex(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
fn hx(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// The SP 800-38B example key.
let key : String = "2b7e151628aed2a6abf7158809cf4f3c"

///|
/// A fresh AES-128 key object; a schedule is immutable, so one can be shared.
fn aes128() -> @aes.Cipher {
  try @aes.Cipher::new(unhex(key)[:]) catch {
    _ => abort("bad test key")
  } noraise {
    cipher => cipher
  }
}

///|
/// The examples from SP 800-38B appendix D: an empty message, one block, a
/// partial final block, and four blocks. Between them they cover the padded and
/// unpadded final block, which is the only branch CMAC has.
test "cmac matches the SP 800-38B examples" {
  assert_eq(hx(@cmac.mac(aes128(), b""[:])), "bb1d6929e95937287fa37d129b756746")
  assert_eq(
    hx(@cmac.mac(aes128(), unhex("6bc1bee22e409f96e93d7e117393172a")[:])),
    "070a16b46b4d4144f79bdd9dd04a287c",
  )
  assert_eq(
    hx(
      @cmac.mac(
        aes128(),
        unhex(
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46",
        )[:],
      ),
    ),
    "7adc9be85d15253a2beb45c1e4db4978",
  )
  assert_eq(
    hx(
      @cmac.mac(
        aes128(),
        unhex(
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        )[:],
      ),
    ),
    "51f0bebf7e3b9d92fc49741779363cfe",
  )
}

///|
/// Splitting the message across writes changes nothing: CMAC has to hold the
/// last block back for exactly this reason.
test "cmac is the same however the message is split" {
  let message = unhex(
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46",
  )
  let whole = hx(@cmac.mac(aes128(), message[:]))
  for cut in [0, 1, 15, 16, 17, 31, 32, 39, 40] {
    let state = @cmac.Cmac::new(aes128())
    state.write(message[0:cut])
    state.write(message[cut:])
    assert_eq(hx(state.finish()), whole)
  }
  // Feeding it a byte at a time, which is the worst case for the buffer.
  let slow = @cmac.Cmac::new(aes128())
  for i in 0..<message.length() {
    slow.write(message[i:i + 1])
  }
  assert_eq(hx(slow.finish()), whole)
}

///|
/// Reading the tag does not consume the message, so a running transcript can be
/// read as it goes and continue afterwards.
test "cmac can be read without being spent" {
  let state = @cmac.Cmac::new(aes128())
  state.write(b"header"[:])
  let first = hx(state.finish())
  assert_eq(hx(state.finish()), first)
  state.write(b"body"[:])
  assert_true(hx(state.finish()) != first)
  state.reset()
  assert_eq(hx(state.finish()), "bb1d6929e95937287fa37d129b756746")
}

///|
/// A tag shorter than the block is a prefix of the full one, which is what the
/// standard means by taking the leftmost bytes.
test "cmac truncates to the left" {
  let message = unhex("6bc1bee22e409f96e93d7e117393172a")
  let full = hx(@cmac.mac(aes128(), message[:]))
  for n in [1, 4, 8, 12, 16] {
    let short = hx(@cmac.mac(aes128(), message[:], tag=n))
    assert_true(@spec.eq(unhex(short)[:], unhex(full)[0:n]))
  }
  let mut refused = false
  try {
    let _ = @cmac.Cmac::new(aes128(), tag=17)
  } catch {
    @spec.Broken::Size(want~, got~) => {
      assert_eq(want, 16)
      assert_eq(got, 17)
      refused = true
    }
    _ => fail("expected a size error")
  }
  assert_true(refused)
}

///|
/// Over a 64-bit block cipher the reduction constant is different, so the mode
/// has to ask the cipher how wide it is rather than assume sixteen.
test "cmac works over a 64-bit block" {
  let blowfish = try @blowfish.Cipher::new(unhex("0123456789abcdef")[:]) catch {
    _ => abort("bad test key")
  } noraise {
    cipher => cipher
  }
  let tag = @cmac.mac(blowfish, b"message"[:], tag=8)
  assert_eq(tag.length(), 8)
  // The same message under the same key twice is the same tag; a changed byte
  // is not.
  assert_eq(hx(@cmac.mac(blowfish, b"message"[:], tag=8)), hx(tag))
  assert_true(hx(@cmac.mac(blowfish, b"messagf"[:], tag=8)) != hx(tag))
  let tweaked = @cmac.Cmac::new(blowfish, tag=8)
  tweaked.write(b"mess"[:])
  tweaked.write(b"age"[:])
  assert_eq(hx(tweaked.finish()), hx(tag))
  assert_eq(@spec.Mac::size(tweaked), 8)
}
