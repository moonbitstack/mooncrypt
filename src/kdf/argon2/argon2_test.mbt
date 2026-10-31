// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
fn ascii(s : String) -> Bytes {
  @utf8.encode(s)
}

///|
/// The RFC's test vectors are written as `n` bytes of a single value, which is
/// not a string, so it needs its own helper.
fn fill(byte : Byte, n : Int32) -> Bytes {
  let out : Array[Byte] = []
  for _ in 0..<n {
    out.push(byte)
  }
  Bytes::from_array(out)
}

///|
/// RFC 9106 §5: all three variants over the same inputs — a 32-byte password of
/// 0x01, a 16-byte salt of 0x02, an 8-byte secret of 0x03, 12 bytes of
/// associated data of 0x04, four lanes, 32 KiB, three passes and a 32-byte tag.
///
/// These are the only published vectors for the full input set, and they are
/// what pins down the lane handling, the secret and associated-data fields, and
/// the XOR of the last column.
test "argon2 matches the RFC 9106 vectors" {
  let password = fill(b'\x01', 32)
  let salt = fill(b'\x02', 16)
  let secret = fill(b'\x03', 8)
  let ad = fill(b'\x04', 12)
  let params : @argon2.Params = { memory: 32, passes: 3, lanes: 4, }
  assert_eq(
    hex(
      @argon2.key(
        password[:],
        salt[:],
        secret=secret[:],
        ad=ad[:],
        kind=@argon2.Argon2d,
        params~,
      ),
    ),
    "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
  )
  assert_eq(
    hex(
      @argon2.key(
        password[:],
        salt[:],
        secret=secret[:],
        ad=ad[:],
        kind=@argon2.Argon2i,
        params~,
      ),
    ),
    "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
  )
  assert_eq(
    hex(
      @argon2.key(
        password[:],
        salt[:],
        secret=secret[:],
        ad=ad[:],
        kind=@argon2.Argon2id,
        params~,
      ),
    ),
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
  )
}

///|
/// The paths the RFC vectors do not reach: a 64-byte tag because it is exactly
/// the BLAKE2b output size, a 72-byte and a 128-byte tag because they are past
/// it and so go through H''s chaining, a memory size that is not a multiple of
/// `4 * lanes` because the rounding is part of the standard, and an empty
/// password.
test "argon2 covers the shapes the RFC vectors skip" {
  assert_eq(
    hex(
      @argon2.key(
        ascii("password")[:],
        ascii("somesalt")[:],
        params={ memory: 8, passes: 1, lanes: 1, },
        len=32,
      ),
    ),
    "f137f8e186a403a679ccd0606e5ab5dcdafe43c1640855ac8c6e33e9bd63eeb3",
  )
  assert_eq(
    hex(
      @argon2.key(
        ascii("password")[:],
        ascii("somesalt")[:],
        kind=@argon2.Argon2i,
        params={ memory: 64, passes: 2, lanes: 2, },
        len=64,
      ),
    ),
    "1904ebb97719641315e3c6657bdb03f1a6b72db09f8ba8718ee4c8e85797deb9d15faac2409d8d30ae1025589350380a62e0bb49f61deb066f2e8d48a8158c4b",
  )
  assert_eq(
    hex(
      @argon2.key(
        ascii("password")[:],
        ascii("somesalt")[:],
        kind=@argon2.Argon2d,
        params={ memory: 32, passes: 2, lanes: 1, },
        len=72,
      ),
    ),
    "48db3c08458af03f584fcf0830ab401c586f5654ce0b5b3ec140c1be409f67fa940b2f01b546e8774c62d27f01afd4fe2b88093acb5d4021d1275e8ff13ad1d1333635be6274c5b6",
  )
  assert_eq(
    hex(
      @argon2.key(
        ascii("password")[:],
        ascii("somesalt")[:],
        params={ memory: 25, passes: 2, lanes: 3, },
        len=32,
      ),
    ),
    "3be4ad883529d4e9ae0fa3d2dcc419a734504a9a7e82259837937529ae117282",
  )
  assert_eq(
    hex(
      @argon2.key(
        b""[:],
        ascii("somesalt")[:],
        params={ memory: 8, passes: 1, lanes: 1, },
        len=32,
      ),
    ),
    "65eeedf51f4006be43eb26d1214182a97d5087767e3487bfbc849dd328145651",
  )
  assert_eq(
    hex(
      @argon2.key(
        ascii("password")[:],
        ascii("somesalt")[:],
        params={ memory: 64, passes: 1, lanes: 4, },
        len=128,
      ),
    ),
    "759deee30aa0666ad1c61b194293f47fe13b70236438735b1daddc47f69efdd4267c3c9b1677734b010477d1fe646ad0f92d2ffe540e349f09eab0ad7df6d183360b95c33e5a0ea64cd61e2a0b604fb23b433855cadae30ca27dc27fc0536ea5229309b04401e6eb9d4b018f32bc5b70ac47786074c95dc4ee87d5358aebb115",
  )
}

///|
/// Every input is part of the answer: the same password and salt under a
/// different cost, variant, secret or associated data give a different tag, and
/// the same call twice gives the same one.
test "argon2 answers every input it is given" {
  let password = ascii("password")[:]
  let salt = ascii("somesalt")[:]
  let cheap : @argon2.Params = { memory: 8, passes: 1, lanes: 1, }
  let base = hex(@argon2.key(password, salt, params=cheap, len=32))
  assert_eq(hex(@argon2.key(password, salt, params=cheap, len=32)), base)
  assert_true(
    hex(@argon2.key(password, salt, kind=@argon2.Argon2d, params=cheap, len=32)) !=
    base,
  )
  assert_true(
    hex(@argon2.key(password, salt, kind=@argon2.Argon2i, params=cheap, len=32)) !=
    base,
  )
  assert_true(
    hex(
      @argon2.key(
        password,
        salt,
        secret=ascii("pepper")[:],
        params=cheap,
        len=32,
      ),
    ) !=
    base,
  )
  assert_true(
    hex(
      @argon2.key(password, salt, ad=ascii("context")[:], params=cheap, len=32),
    ) !=
    base,
  )
  assert_true(
    hex(
      @argon2.key(
        password,
        salt,
        params={ memory: 16, passes: 1, lanes: 1, },
        len=32,
      ),
    ) !=
    base,
  )
  assert_true(
    hex(
      @argon2.key(
        password,
        salt,
        params={ memory: 8, passes: 2, lanes: 1, },
        len=32,
      ),
    ) !=
    base,
  )
  assert_eq(@argon2.key(password, salt, params=cheap, len=16).length(), 16)
}

///|
/// The presets are the ones RFC 9106 §4 names, and the memory a derivation
/// takes is the requested size rounded down to whole blocks, not the number
/// asked for.
test "argon2 names its presets and reports what it will allocate" {
  assert_eq(@argon2.recommended.memory, 2097152)
  assert_eq(@argon2.recommended.passes, 1)
  assert_eq(@argon2.recommended.lanes, 4)
  assert_eq(@argon2.interactive.memory, 65536)
  assert_eq(@argon2.interactive.passes, 3)
  assert_eq(@argon2.minimum.memory, 8)
  assert_eq(@argon2.minimum.lanes, 1)
  assert_eq(@argon2.interactive.memory_bytes(), 65536 * 1024)
  // 25 KiB across three lanes is 24 KiB once four blocks per lane are kept.
  let odd = @argon2.Params::new(memory=25, passes=2, lanes=3)
  assert_eq(odd.memory, 25)
  assert_eq(odd.memory_bytes(), 24 * 1024)
  assert_eq(@argon2.Argon2d.code(), 0)
  assert_eq(@argon2.Argon2i.code(), 1)
  assert_eq(@argon2.Argon2id.code(), 2)
  assert_eq(@argon2.Argon2id.name(), "Argon2id")
}
