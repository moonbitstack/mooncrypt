// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn seed_entropy() -> Bytes {
  @base16.decode_lossy(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
}

///|
fn seed_nonce() -> Bytes {
  @base16.decode_lossy("000102030405060708090a0b0c0d0e0f")
}

///|
test "CTR-DRBG is a deterministic function of its seed" {
  let a = @drbg.CtrDrbg::new(
    entropy=seed_entropy()[:],
    nonce=seed_nonce()[:],
    personalization=b""[:],
  )
  let b = @drbg.CtrDrbg::new(
    entropy=seed_entropy()[:],
    nonce=seed_nonce()[:],
    personalization=b""[:],
  )
  let oa = a.generate(64)
  let ob = b.generate(64)
  assert_eq(oa.length(), 64)
  assert_eq(@base16.encode(oa[:]), @base16.encode(ob[:]))
}

///|
test "CTR-DRBG diverges with a different personalization" {
  let a = @drbg.CtrDrbg::new(
    entropy=seed_entropy()[:],
    nonce=seed_nonce()[:],
    personalization=b"one"[:],
  )
  let b = @drbg.CtrDrbg::new(
    entropy=seed_entropy()[:],
    nonce=seed_nonce()[:],
    personalization=b"two"[:],
  )
  let oa = @base16.encode(a.generate(32)[:])
  let ob = @base16.encode(b.generate(32)[:])
  assert_eq(oa == ob, false)
}

///|
test "CTR-DRBG reseed changes the stream" {
  let d = @drbg.CtrDrbg::new(
    entropy=seed_entropy()[:],
    nonce=seed_nonce()[:],
    personalization=b""[:],
  )
  let before = @base16.encode(d.generate(32)[:])
  d.reseed(entropy=seed_entropy()[:], additional=b"fresh"[:])
  let after = @base16.encode(d.generate(32)[:])
  assert_eq(before == after, false)
}

///|
test "CTR-DRBG fills a Source buffer" {
  let d = @drbg.CtrDrbg::new(
    entropy=seed_entropy()[:],
    nonce=seed_nonce()[:],
    personalization=b""[:],
  )
  let out = @moonseed.bytes(48, d) catch {
    _ => abort("ctr-drbg: a generator must never exhaust")
  }
  assert_eq(out.length(), 48)
}

///|
test "the reseed counter counts generate calls and starts again at a reseed" {
  // SP 800-90A: one after instantiating, one more per request, one after a reseed.
  // A caller watches this to reseed before the interval is spent.
  let ctr = @drbg.CtrDrbg::new(
    entropy=seed_entropy()[:],
    nonce=seed_nonce()[:],
    personalization=b""[:],
  )
  assert_eq(ctr.reseed_counter(), 1UL)
  ignore(ctr.generate(16))
  ignore(ctr.generate(16))
  assert_eq(ctr.reseed_counter(), 3UL)
  ctr.reseed(entropy=seed_entropy()[:], additional=b""[:])
  assert_eq(ctr.reseed_counter(), 1UL)
}
