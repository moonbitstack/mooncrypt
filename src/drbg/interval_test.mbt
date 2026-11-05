// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// SP 800-90A §10 caps the number of requests a generator serves between
// reseeds, and every table there writes the cap into the state as
// `reseed_interval`. These tests drive each generator to a small cap and check
// that it refuses to go past it — and that a reseed puts it back in service.

///|
fn interval_entropy() -> Bytes {
  @base16.decode_lossy(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
}

///|
fn interval_nonce() -> Bytes {
  @base16.decode_lossy("000102030405060708090a0b0c0d0e0f")
}

///|
fn interval_sha() -> &@spec.Hash {
  @sha2.Hasher::new()
}

///|
/// An interval of `limit` serves exactly `limit` requests and then refuses.
fn refuses_past_its_interval(
  draw : () -> Bytes raise @drbg.Refused,
  limit : UInt64,
) -> Unit raise {
  // The counter starts at one, so a limit of three covers three requests.
  for _ in 0..<limit.to_int() {
    assert_eq(draw().length(), 16)
  }
  let refused = try {
    let _ = draw()
    false
  } catch {
    @drbg.Reseed(limit=given) => given == limit
  }
  assert_true(refused)
}

///|
test "the CTR generator refuses to draw past its reseed interval" {
  let ctr = @drbg.CtrDrbg::new(
    entropy=interval_entropy()[:],
    nonce=interval_nonce()[:],
    personalization=b""[:],
    interval=3UL,
  )
  refuses_past_its_interval(fn() raise @drbg.Refused { ctr.generate(16) }, 3UL)
}

///|
test "the hash generator refuses to draw past its reseed interval" {
  let hash = @drbg.HashDrbg::new(
    interval_sha,
    entropy=interval_entropy()[:],
    nonce=interval_nonce()[:],
    personalization=b""[:],
    interval=2UL,
  )
  refuses_past_its_interval(fn() raise @drbg.Refused { hash.generate(16) }, 2UL)
}

///|
test "the HMAC generator refuses to draw past its reseed interval" {
  let hmac = @drbg.HmacDrbg::new(
    interval_sha,
    entropy=interval_entropy()[:],
    nonce=interval_nonce()[:],
    personalization=b""[:],
    interval=5UL,
  )
  refuses_past_its_interval(fn() raise @drbg.Refused { hmac.generate(16) }, 5UL)
}

///|
test "a reseed puts the generator back in service" {
  let ctr = @drbg.CtrDrbg::new(
    entropy=interval_entropy()[:],
    nonce=interval_nonce()[:],
    personalization=b""[:],
    interval=2UL,
  )
  for _ in 0..<2 {
    let _ = ctr.generate(16)
  }
  assert_eq(ctr.reseed_counter(), 3UL)
  ctr.reseed(entropy=interval_entropy()[:], additional=b"more"[:])
  assert_eq(ctr.reseed_counter(), 1UL)
  // The counter is back to one, so the whole interval is available again.
  for _ in 0..<2 {
    assert_eq(ctr.generate(16).length(), 16)
  }
  let refused = try {
    let _ = ctr.generate(16)
    false
  } catch {
    @drbg.Reseed(_) => true
  }
  assert_true(refused)
}

///|
test "the interval is a parameter, and its preset is the standard's cap" {
  // SP 800-90A §10.1.1 and §10.2.1 cap the interval at 2^48 requests.
  assert_eq(@drbg.reseed_limit, 281474976710656UL)
  let ctr = @drbg.CtrDrbg::new(
    entropy=interval_entropy()[:],
    nonce=interval_nonce()[:],
    personalization=b""[:],
  )
  assert_eq(ctr.interval(), @drbg.reseed_limit)
  let given = @drbg.CtrDrbg::new(
    entropy=interval_entropy()[:],
    nonce=interval_nonce()[:],
    personalization=b""[:],
    interval=10UL,
  )
  assert_eq(given.interval(), 10UL)
  assert_eq(given.reseed_counter(), 1UL)
  // A draw moves the counter, and the interval does not move with it.
  let _ = given.generate(16)
  assert_eq(given.reseed_counter(), 2UL)
  assert_eq(given.interval(), 10UL)
}

///|
test "a spent generator reports itself to a Source caller as exhausted" {
  let hmac = @drbg.HmacDrbg::new(
    interval_sha,
    entropy=interval_entropy()[:],
    nonce=interval_nonce()[:],
    personalization=b""[:],
    interval=1UL,
  )
  let buf = FixedArray::make(16, b'\x00')
  // The one request the interval allows goes through.
  hmac.fill(buf)
  let refused = try {
    hmac.fill(buf)
    false
  } catch {
    @moonseed.Unavailable::Exhausted => true
    _ => false
  }
  assert_true(refused)
}
