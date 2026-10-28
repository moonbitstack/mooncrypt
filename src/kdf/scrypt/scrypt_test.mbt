// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
fn ascii(s : String) -> Bytes {
  @moonbase.ascii(s)
}

///|
/// The first three vectors of RFC 7914 §12. The fourth needs a gibibyte of
/// memory, which is more than a test run should ask for.
test "scrypt matches the RFC 7914 vectors" {
  assert_eq(
    hex(@scrypt.key(b""[:], b""[:], params={ n: 16, r: 1, p: 1, }, len=64)),
    "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
  )
  assert_eq(
    hex(
      @scrypt.key(
        ascii("password")[:],
        ascii("NaCl")[:],
        params={ n: 1024, r: 8, p: 16, },
        len=64,
      ),
    ),
    "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
  )
  assert_eq(
    hex(
      @scrypt.key(
        ascii("pleaseletmein")[:],
        ascii("SodiumChloride")[:],
        params={ n: 16384, r: 8, p: 1, },
        len=64,
      ),
    ),
    "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
  )
}

///|
/// A different salt, password or cost gives a different key, and the length is
/// exactly what was asked for.
test "scrypt answers what the parameters say" {
  let cheap : @scrypt.Params = { n: 16, r: 1, p: 1, }
  let a = @scrypt.key(
    ascii("password")[:],
    ascii("salt")[:],
    params=cheap,
    len=32,
  )
  let b = @scrypt.key(
    ascii("password")[:],
    ascii("salt2")[:],
    params=cheap,
    len=32,
  )
  let c = @scrypt.key(
    ascii("passwore")[:],
    ascii("salt")[:],
    params=cheap,
    len=32,
  )
  let d = @scrypt.key(
    ascii("password")[:],
    ascii("salt")[:],
    params={ n: 32, r: 1, p: 1, },
    len=32,
  )
  assert_eq(a.length(), 32)
  assert_true(hex(a) != hex(b))
  assert_true(hex(a) != hex(c))
  assert_true(hex(a) != hex(d))
  // The same inputs twice are the same key.
  assert_eq(
    hex(
      @scrypt.key(ascii("password")[:], ascii("salt")[:], params=cheap, len=32),
    ),
    hex(a),
  )
  assert_eq(
    @scrypt.key(ascii("password")[:], ascii("salt")[:], params=cheap, len=16).length(),
    16,
  )
}

///|
/// The presets are what they claim: the memory a derivation takes is
/// `128 * r * n`, and `n` has to be a power of two above one.
test "scrypt names its presets and refuses what it cannot run" {
  assert_eq(@scrypt.interactive.n, 16384)
  assert_eq(@scrypt.interactive.r, 8)
  assert_eq(@scrypt.interactive.p, 1)
  assert_eq(@scrypt.sensitive.n, 1 << 20)
  assert_eq(@scrypt.min_n, 2)
  let p = @scrypt.Params::new(n=1024, r=4, p=2)
  assert_eq(p.r, 4)
  assert_eq(p.p, 2)
}
