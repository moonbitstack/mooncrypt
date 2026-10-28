// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The vectors come from `scripts/gen_rc4_vectors.py`, which reproduces the
// textbook "Key"/"Plaintext" pair and then takes every case from PyCryptodome.
// The offsets are the ones RFC 6229 samples.

///|
fn raw(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// One sample: a key, where in the keystream to look, and what should be there.
///
/// RC4's early bytes are biased, so an implementation can be wrong only after the
/// first few hundred and still pass a test that looks at offset zero alone.
struct Case {
  key : String
  offset : Int32
  expected : String
}

///|
let cases : Array[Case] = [
  {
    key: "0102030405",
    offset: 0,
    expected: "b2396305f03dc027ccc3524a0a1118a8",
  },
  {
    key: "0102030405",
    offset: 16,
    expected: "6982944f18fc82d589c403a47a0d0919",
  },
  {
    key: "0102030405",
    offset: 240,
    expected: "28cb1132c96ce286421dcaadb8b69eae",
  },
  {
    key: "0102030405",
    offset: 256,
    expected: "1cfcf62b03eddb641d77dfcf7f8d8c93",
  },
  {
    key: "0102030405",
    offset: 496,
    expected: "42b7d0cdd918a8a33dd51781c81f4041",
  },
  {
    key: "0102030405",
    offset: 512,
    expected: "6459844432a7da923cfb3eb4980661f6",
  },
  {
    key: "0102030405",
    offset: 752,
    expected: "ec10327bde2beefd18f9277680457e22",
  },
  {
    key: "0102030405",
    offset: 768,
    expected: "eb62638d4f0ba1fe9fca20e05bf8ff2b",
  },
  {
    key: "0102030405",
    offset: 1008,
    expected: "45129048e6a0ed0b56b490338f078da5",
  },
  {
    key: "0102030405",
    offset: 1024,
    expected: "30abbcc7c20b01609f23ee2d5f6bb7df",
  },
  {
    key: "01020304050607",
    offset: 0,
    expected: "293f02d47f37c9b633f2af5285feb46b",
  },
  {
    key: "01020304050607",
    offset: 16,
    expected: "e620f1390d19bd84e2e0fd752031afc1",
  },
  {
    key: "01020304050607",
    offset: 240,
    expected: "914f02531c9218810df60f67e338154c",
  },
  {
    key: "01020304050607",
    offset: 256,
    expected: "d0fdb583073ce85ab83917740ec011d5",
  },
  {
    key: "01020304050607",
    offset: 496,
    expected: "75f81411e871cffa70b90c74c592e454",
  },
  {
    key: "01020304050607",
    offset: 512,
    expected: "0bb87202938dad609e87a5a1b079e5e4",
  },
  {
    key: "01020304050607",
    offset: 752,
    expected: "c2911246b612e7e7b903dfeda1dad866",
  },
  {
    key: "01020304050607",
    offset: 768,
    expected: "32828f91502b6291368de8081de36fc2",
  },
  {
    key: "01020304050607",
    offset: 1008,
    expected: "f3b9a7e3b297bf9ad804512f9063eff1",
  },
  {
    key: "01020304050607",
    offset: 1024,
    expected: "8ecb67a9ba1f55a5a067e2b026a3676f",
  },
  {
    key: "0102030405060708",
    offset: 0,
    expected: "97ab8a1bf0afb96132f2f67258da15a8",
  },
  {
    key: "0102030405060708",
    offset: 16,
    expected: "8263efdb45c4a18684ef87e6b19e5b09",
  },
  {
    key: "0102030405060708",
    offset: 240,
    expected: "9636ebc9841926f4f7d1f362bddf6e18",
  },
  {
    key: "0102030405060708",
    offset: 256,
    expected: "d0a990ff2c05fef5b90373c9ff4b870a",
  },
  {
    key: "0102030405060708",
    offset: 496,
    expected: "73239f1db7f41d80b643c0c52518ec63",
  },
  {
    key: "0102030405060708",
    offset: 512,
    expected: "163b319923a6bdb4527c626126703c0f",
  },
  {
    key: "0102030405060708",
    offset: 752,
    expected: "49d6c8af0f97144a87df21d91472f966",
  },
  {
    key: "0102030405060708",
    offset: 768,
    expected: "44173a103b6616c5d5ad1cee40c863d0",
  },
  {
    key: "0102030405060708",
    offset: 1008,
    expected: "273c9c4b27f322e4e716ef53a47de7a4",
  },
  {
    key: "0102030405060708",
    offset: 1024,
    expected: "c6d0e7b226259fa9023490b26167ad1d",
  },
  {
    key: "0102030405060708090a",
    offset: 0,
    expected: "ede3b04643e586cc907dc21851709902",
  },
  {
    key: "0102030405060708090a",
    offset: 16,
    expected: "03516ba78f413beb223aa5d4d2df6711",
  },
  {
    key: "0102030405060708090a",
    offset: 240,
    expected: "3cfd6cb58ee0fdde640176ad0000044d",
  },
  {
    key: "0102030405060708090a",
    offset: 256,
    expected: "48532b21fb6079c9114c0ffd9c04a1ad",
  },
  {
    key: "0102030405060708090a",
    offset: 496,
    expected: "3e8cea98017109979084b1ef92f99d86",
  },
  {
    key: "0102030405060708090a",
    offset: 512,
    expected: "e20fb49bdb337ee48b8d8dc0f4afeffe",
  },
  {
    key: "0102030405060708090a",
    offset: 752,
    expected: "5c2521eacd7966f15e056544bea0d315",
  },
  {
    key: "0102030405060708090a",
    offset: 768,
    expected: "e067a7031931a246a6c3875d2f678acb",
  },
  {
    key: "0102030405060708090a",
    offset: 1008,
    expected: "a64f70af88ae56b6f87581c0e23e6b08",
  },
  {
    key: "0102030405060708090a",
    offset: 1024,
    expected: "f449031de312814ec6f319291f4a0516",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 0,
    expected: "9ac7cc9a609d1ef7b2932899cde41b97",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 16,
    expected: "5248c4959014126a6e8a84f11d1a9e1c",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 240,
    expected: "065902e4b620f6cc36c8589f66432f2b",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 256,
    expected: "d39d566bc6bce3010768151549f3873f",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 496,
    expected: "b6d1e6c4a5e4771cad79538df295fb11",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 512,
    expected: "c68c1d5c559a974123df1dbc52a43b89",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 752,
    expected: "c5ecf88de897fd57fed301701b82a259",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 768,
    expected: "eccbe13de1fcc91c11a0b26c0bc8fa4d",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 1008,
    expected: "e7a72574f8782ae26aabcf9ebcd66065",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f10",
    offset: 1024,
    expected: "bdf0324e6083dcc6d3cedd3ca8c53c16",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 0,
    expected: "0595e57fe5f0bb3c706edac8a4b2db11",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 16,
    expected: "dfde31344a1af769c74f070aee9e2326",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 240,
    expected: "b06b9b1e195d13d8f4a7995c4553ac05",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 256,
    expected: "6bd2378ec341c9a42f37ba79f88a32ff",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 496,
    expected: "e70bce1df7645adb5d2c4130215c3522",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 512,
    expected: "9a5730c7fcb4c9af51ffda89c7f1ad22",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 752,
    expected: "0485055fd4f6f0d963ef5ab9a5476982",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 768,
    expected: "591fc66bcda10e452b03d4551f6b62ac",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 1008,
    expected: "2753cc83988afa3e1688a1d3b42c9a02",
  },
  {
    key: "0102030405060708090a0b0c0d0e0f101112131415161718",
    offset: 1024,
    expected: "93610d523d1d3f0062b3c2a3bbc7c7f0",
  },
  { key: "00", offset: 0, expected: "de188941a3375d3a8a061e67576e926d", },
  { key: "00", offset: 16, expected: "c71a7fa3f0cceb97452b4d3227965f9e", },
  { key: "00", offset: 240, expected: "63c3e45174ac644d4702473f97d19d62", },
  { key: "00", offset: 256, expected: "3b3fa83fd355e24627e71154c453ca45", },
  { key: "00", offset: 496, expected: "1d8f44e60656e947c3367d382a2cafd6", },
  { key: "00", offset: 512, expected: "e17aedf9370bf12665d4a1f30e575cc8", },
  { key: "00", offset: 752, expected: "ace33bbb3e24ec4275d8c99693876178", },
  { key: "00", offset: 768, expected: "c7ef25c72676b33044564a64abfd6d96", },
  { key: "00", offset: 1008, expected: "26f26f2e5b44acb097de89f3bdbdfc20", },
  { key: "00", offset: 1024, expected: "9a8898ebed25895336ae119ae503cad6", },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 0,
    expected: "6d252f2470531bb0394b93b4c46fdd9c",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 16,
    expected: "e8bcf0f16edbbbd3ed4573ec5198b8e6",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 240,
    expected: "3b79a05002e2b6ca59e34bfb55753862",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 256,
    expected: "4442a6780599e55a4bc7debe1f652fb7",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 496,
    expected: "86754398141ba90e2125df142fc2c03f",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 512,
    expected: "37105727b2b64728260108afafdb2000",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 752,
    expected: "e747bf47f94de4f85b6e49855797ddd1",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 768,
    expected: "564bb765bda7ba0e8cc43dad9248dc7c",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 1008,
    expected: "f5c6c11064ef06d7470d3a87f61ac2d3",
  },
  {
    key: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    offset: 1024,
    expected: "c945f486626884c833713d4526a7c27b",
  },
]

///|
/// Every sample, after skipping to its offset.
test "rc4 keystream matches rfc 6229" {
  assert_eq(cases.length(), 80)
  for case in cases {
    let cipher = @rc4.Cipher::new(raw(case.key)[:])
    let _ = cipher.keystream(case.offset)
    assert_eq(cipher.keystream(16), raw(case.expected))
  }
}

///|
/// The pair every description of RC4 starts with.
test "the textbook pair" {
  let key = @utf8.encode("Key")
  let encrypted = @rc4.rc4(key[:], @utf8.encode("Plaintext")[:])
  assert_eq(encrypted, raw("bbf316e8d940af0ad3"))
  // And it is its own inverse.
  assert_eq(@rc4.rc4(key[:], encrypted[:]), @utf8.encode("Plaintext"))
}

///|
/// The state carries across calls: encrypting in pieces gives the same bytes as
/// encrypting at once, which is the property a stream cipher has and a block
/// cipher does not.
test "the state carries across calls" {
  let key = raw("0102030405060708")
  let whole = @rc4.rc4(key[:], raw("000102030405060708090a0b0c0d0e0f10")[:])
  let cipher = @rc4.Cipher::new(key[:])
  let a = cipher.xor(raw("0001020304050607")[:])
  let b = cipher.xor(raw("08090a0b0c0d0e0f10")[:])
  assert_eq(a + b, whole)
  // The third call gets different keystream from the first, because the state
  // has moved on — which is exactly why one key must never encrypt two messages.
  let third = cipher.xor(raw("0001020304050607")[:])
  assert_true(third != a)
  // A fresh cipher starts over and reproduces the first call.
  let again = @rc4.Cipher::new(key[:])
  assert_eq(again.xor(raw("0001020304050607")[:]), a)
  // The two halves are the same bytes as the first and second half of the whole.
  assert_eq(a, whole[0:8].to_owned())
  assert_eq(b, whole[8:17].to_owned())
}
