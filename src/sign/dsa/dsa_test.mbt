// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A tiny, obviously-insecure domain used only to exercise the arithmetic in a
/// test: p = 47, q = 23, g = 4.
let tiny : @dsa.Domain = @dsa.Domain::new(b"\x2F", b"\x17", b"\x04")

///|
test "DSA signs and verifies a round trip" {
  let key = @dsa.PrivateKey::generate(
    @moonseed.Replay::new(b"\x09"),
    domain=tiny,
  )
  let msg = @utf8.encode("hello, world")
  let sig = key.sign(msg[:])
  assert_true(key.public().verify(msg[:], sig[:]))
}

///|
test "DSA rejects a tampered message" {
  let key = @dsa.PrivateKey::generate(
    @moonseed.Replay::new(b"\x09"),
    domain=tiny,
  )
  let msg = @utf8.encode("hello, world")
  let sig = key.sign(msg[:])
  let tampered = @utf8.encode("hello, worle")
  assert_false(key.public().verify(tampered[:], sig[:]))
}

///|
test "DSA rejects a wrong-length signature" {
  let key = @dsa.PrivateKey::generate(
    @moonseed.Replay::new(b"\x09"),
    domain=tiny,
  )
  let msg = @utf8.encode("hello, world")
  let sig = key.sign(msg[:])
  assert_false(key.public().verify(msg[:], sig[:sig.length() - 1]))
}

///|
fn unhex(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// The vector below was produced by an independent implementation of the DSA
/// algorithm (FIPS 186-4) over a 1024/160 domain, so a match here means the
/// arithmetic agrees with the standard and not merely with itself. `y` is
/// `g^x mod p`, `r ∥ s` is the signature over "hello, world" with SHA-256.
test "DSA verifies a signature from an independent implementation" {
  let p = unhex(
    "b15d6a974c0d3a860d3e7335459c3986c33b5d6bf2424d04d17a45e96309d5de" +
    "d01dcd0fe8ec8bcd3a35602c08585732bc40a88f9aa84806d5c65e14994530bb" +
    "316dc305bee4fedf13c187e4fe06d5d55f565a74a0909e4d33ecb90d12b57f25" +
    "973ecda9c18bd6468e7d23dcaf271b1e2113fa514cb4cdbb6833cdb4a4579d37",
  )
  let q = unhex("e237129421abb0cba5e96cd8dda3bd7946266e9d")
  let g = unhex(
    "9575b4cc46d2e5343a4547794298ebc8679d0846acfe453e0ba77ec0a671aaaf" +
    "923b9295446085ed9ee508164253df045bbd7872b6b397b15842af1f841ee18e" +
    "8a39696cced60d95c631a2b1457e4c2458778cfdb3772b749f4744b3ce6d8bc3" +
    "ebf828ac11616bcb4c8d032ec15db8750fe8a0581e94780ad425235c6f3857ab",
  )
  let y = unhex(
    "4c49eb7909214f732484c167697b7b87b4ca5158e2c03854759c8d5304b8a289" +
    "0221569eceb10c08e46050f02d0ee992f4b5821a4f762c541e05717942d6ea24" +
    "cb41d8bd1b915a89d2f63d35f0add8a6f9a2d963dae401e17007c23bbff19cea" +
    "075d1d4ba37414e6b6bb3e0d4d8db87a048850dda98883ac99551fb254b3e4ae",
  )
  let sig = unhex(
    "9d97b76b6485e01a9f2db6657bcc8aa21934eda4" +
    "6167ac3f667cc5e5a75f296e4a47e306724fb64a",
  )
  let domain = @dsa.Domain::new(p[:], q[:], g[:])
  let pk = @dsa.PublicKey::new(y[:], domain~) catch {
    _ => abort("dsa test: the public key must parse")
  }
  let msg = @utf8.encode("hello, world")
  assert_true(pk.verify(msg[:], sig[:]))
}
