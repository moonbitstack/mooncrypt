// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn ascii(s : String) -> Bytes {
  @moonbase.ascii(s)
}

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// The four SHA-3 digests of the empty message and of "abc", from the NIST
/// example files (`SHA3_*ShortMsg.rsp`).
test "SHA-3 matches the NIST short-message vectors" {
  assert_eq(
    hex(@sha3.hash(b""[:], kind=Sha3_224)),
    "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
  )
  assert_eq(
    hex(@sha3.hash(b"abc"[:], kind=Sha3_224)),
    "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
  )
  assert_eq(
    hex(@sha3.hash(b""[:], kind=Sha3_256)),
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
  )
  assert_eq(
    hex(@sha3.hash(b"abc"[:], kind=Sha3_256)),
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
  )
  assert_eq(
    hex(@sha3.hash(b""[:], kind=Sha3_384)),
    "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
  )
  assert_eq(
    hex(@sha3.hash(b"abc"[:], kind=Sha3_384)),
    "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
  )
  assert_eq(
    hex(@sha3.hash(b""[:], kind=Sha3_512)),
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
  )
  assert_eq(
    hex(@sha3.hash(b"abc"[:], kind=Sha3_512)),
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
  )
}

///|
/// The message that fills a block exactly, where the padding has to spill into a
/// second block — the one boundary an implementation gets wrong.
test "SHA-3 pads a message that ends on the rate" {
  // 144 bytes is SHA3-224's rate, so the padding byte opens a second block.
  let long = Bytes::from_array(Array::make(144, b'a'))
  assert_eq(
    hex(@sha3.hash(long[:], kind=Sha3_224)),
    "f9019111996dcf160e284e320fd6d8825cabcd41a5ffdc4c5e9d64b6",
  )
  // 135 bytes is one short of SHA3-256's rate, so the suffix and the final bit
  // share the last byte of the block.
  let short = Bytes::from_array(Array::make(135, b'a'))
  assert_eq(
    hex(@sha3.hash(short[:], kind=Sha3_256)),
    "8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9",
  )
  let exact = Bytes::from_array(Array::make(136, b'a'))
  assert_eq(
    hex(@sha3.hash(exact[:], kind=Sha3_256)),
    "3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1",
  )
}

///|
/// A running hash sees the same message whether it arrives whole or in pieces.
test "SHA-3 streams and reads repeatedly" {
  let h = @sha3.Hasher::new(kind=Sha3_256)
  h.write(b"the quick "[:])
  h.write(b"brown fox"[:])
  let first = h.finish()
  assert_eq(
    hex(first),
    hex(@sha3.hash(b"the quick brown fox"[:], kind=Sha3_256)),
  )
  // Reading does not consume, so a second read answers the same.
  assert_eq(hex(h.finish()), hex(first))
  // Writing after a read continues the same message.
  h.write(b" jumps"[:])
  assert_eq(
    hex(h.finish()),
    hex(@sha3.hash(b"the quick brown fox jumps"[:], kind=Sha3_256)),
  )
  h.reset()
  assert_eq(hex(h.finish()), hex(@sha3.hash(b""[:], kind=Sha3_256)))
}

///|
test "SHA-3 reports its own sizes, and satisfies the Hash contract" {
  let h = @sha3.Hasher::new(kind=Sha3_384)
  let as_hash : &@spec.Hash = h
  assert_eq(as_hash.size(), 48)
  assert_eq(as_hash.block(), 104)
  assert_eq(as_hash.finish().length(), 48)
  assert_eq(@sha3.Hasher::new(kind=Shake256).block(), 136)
  assert_eq(@sha3.Hasher::new(kind=Shake128).block(), 168)
}

///|
/// SHAKE's own vectors: the empty message, read to 32 and to 64 bytes.
test "SHAKE reads the NIST vectors" {
  assert_eq(
    hex(@sha3.shake128(b""[:], 32)),
    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  )
  assert_eq(
    hex(@sha3.shake256(b""[:], 64)),
    "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
  )
  // Reading in two calls must equal reading in one.
  let x = @sha3.Xof::new(kind=Shake128)
  x.absorb(b"abc"[:])
  let head = x.squeeze(16)
  let tail = x.squeeze(16)
  let whole = @sha3.shake128(b"abc"[:], 32)
  assert_eq(hex(head), hex(whole[0:16]))
  assert_eq(hex(tail), hex(whole[16:32]))
}

///|
/// The worked examples in SP 800-185 §3.3, whose customization string is the
/// only thing setting them apart from plain SHAKE.
test "cSHAKE matches the SP 800-185 examples" {
  // Sample 1 and 3 of the NIST example file: X is four bytes, N is empty and
  // S names the application.
  let tag : Bytes = ascii("Email Signature")
  let four : Bytes = [0x00, 0x01, 0x02, 0x03]
  assert_eq(
    hex(@sha3.cshake128(four[:], 32, custom=tag[:])),
    "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
  )
  assert_eq(
    hex(@sha3.cshake256(four[:], 64, custom=tag[:])),
    "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c",
  )
  // The same message without the customisation is plain SHAKE, which is a
  // different function.
  assert_true(
    hex(@sha3.cshake128(four[:], 32, custom=tag[:])) !=
    hex(@sha3.shake128(four[:], 32)),
  )
}

///|
/// With both strings empty, cSHAKE is required to be SHAKE byte for byte
/// (SP 800-185 §3.3).
test "an unparameterised cSHAKE is SHAKE" {
  assert_eq(
    hex(@sha3.cshake128(b"abc"[:], 32)),
    hex(@sha3.shake128(b"abc"[:], 32)),
  )
  assert_eq(
    hex(@sha3.cshake256(b"abc"[:], 64)),
    hex(@sha3.shake256(b"abc"[:], 64)),
  )
}

///|
/// The three encodings, on the values the examples in SP 800-185 use.
test "the SP 800-185 encodings are big-endian with a length" {
  assert_eq(hex(@sha3.left_encode(0UL)), "0100")
  assert_eq(hex(@sha3.left_encode(1UL)), "0101")
  assert_eq(hex(@sha3.left_encode(256UL)), "020100")
  assert_eq(hex(@sha3.right_encode(0UL)), "0001")
  assert_eq(hex(@sha3.right_encode(256UL)), "010002")
  // encode_string adds the bit length, which is eight times the byte length.
  assert_eq(hex(@sha3.encode_string(b"abc"[:])), "0118" + "616263")
  // bytepad pads to a multiple of the width, counting the length byte itself.
  assert_eq(hex(@sha3.bytepad(b"abc"[:], 8)), "0108" + "616263" + "000000")
}
