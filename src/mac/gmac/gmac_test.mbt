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
/// A fresh AES-128 key object.
fn aes128(k : String) -> @aes.Cipher {
  try @aes.Cipher::new(unhex(k)[:]) catch {
    _ => abort("bad test key")
  } noraise {
    cipher => cipher
  }
}

///|
/// The GHASH key from SP 800-38D's worked examples, with the twelve-byte nonce
/// the standard prefers and the associated data it uses.
test "gmac matches the GCM examples with no plaintext" {
  let key = "feffe9928665731c6d6a8f9467308308"
  assert_eq(
    hx(
      @gmac.mac(
        aes128(key),
        unhex("cafebabefacedbaddecaf888")[:],
        unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")[:],
      ),
    ),
    "346434fd51d5cd0c5887ec63e39b907a",
  )
  // No associated data at all: the tag is the encryption of GHASH over the
  // length block alone.
  assert_eq(
    hx(@gmac.mac(aes128(key), unhex("cafebabefacedbaddecaf888")[:], b""[:])),
    "3247184b3c4f69a44dbcd22887bbb418",
  )
  // A shorter nonce, which the standard permits with a derivation step.
  assert_eq(
    hx(
      @gmac.mac(
        aes128(key),
        unhex("cafebabefacedbad")[:],
        unhex("feedfacedeadbeef")[:],
      ),
    ),
    "fc58c63ba47c0f954a65e978c873f5ad",
  )
  // An all-zero key and nonce, which is the degenerate case worth pinning: a
  // broken GHASH that happens to work on nonzero input shows up here.
  assert_eq(
    hx(
      @gmac.mac(
        aes128("00000000000000000000000000000000"),
        unhex("000000000000000000000000")[:],
        b""[:],
      ),
    ),
    "58e2fccefa7e3061367f1d57a4e7455a",
  )
}

///|
/// Splitting the message across writes changes nothing, and the tag can be read
/// more than once without being spent.
test "gmac accumulates across writes" {
  let nonce = unhex("000102030405060708090a0b0c0d0e0f")
  let message = unhex("4d23f5ee2e6e1b6e2f0a4b9d0e6a5c1f")
  let key = aes128("2b7e151628aed2a6abf7158809cf4f3c")
  assert_eq(
    hx(@gmac.mac(key, nonce[:], message[:])),
    "3e6d4dd65ee243232ac9e0a8c9dd3503",
  )
  let state = @gmac.Gmac::new(key, nonce[:])
  for i in 0..<message.length() {
    state.write(message[i:i + 1])
  }
  let tag = hx(state.finish())
  assert_eq(tag, "3e6d4dd65ee243232ac9e0a8c9dd3503")
  assert_eq(hx(state.finish()), tag)
  assert_true(state.verify(unhex(tag)[:]))
  assert_true(!state.verify(unhex("00000000000000000000000000000000")[:]))
  state.reset()
  assert_eq(hx(state.finish()), hx(@gmac.mac(key, nonce[:], b""[:])))
}

///|
/// A shorter tag is the leftmost bytes of the full one, and a nonce that would
/// make the tag repeat is refused rather than quietly accepted.
test "gmac truncates and refuses an empty nonce" {
  let key = aes128("feffe9928665731c6d6a8f9467308308")
  let nonce = unhex("cafebabefacedbaddecaf888")
  let message = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let full = hx(@gmac.mac(key, nonce[:], message[:]))
  for n in [12, 13, 14, 15] {
    let short = hx(@gmac.mac(key, nonce[:], message[:], tag=n))
    assert_true(@spec.eq(unhex(short)[:], unhex(full)[0:n]))
  }
  let mut refused = false
  try {
    let _ = @gmac.Gmac::new(key, b""[:])
  } catch {
    @spec.Broken::Size(want~, got~) => {
      assert_eq(want, 12)
      assert_eq(got, 0)
      refused = true
    }
    _ => fail("expected a size error")
  }
  assert_true(refused)
  assert_eq(
    @spec.Mac::size(
      try @gmac.Gmac::new(key, nonce[:], tag=12) catch {
        _ => abort("bad tag")
      } noraise {
        state => state
      },
    ),
    12,
  )
}
