// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// HMAC-DRBG (NIST SP 800-90A §10.1.2): a deterministic bit generator keyed by
/// an entropy input, a nonce and an optional personalization string.
///
/// The state is a pair of fixed-width buffers, `Key` and `V`, that the hash
/// mixes forward on every call. Because it is a [`Source`] it drops into a key
/// generator wherever the platform's entropy would; because it is deterministic
/// once seeded, a test can reproduce its output from a known seed.
struct HmacDrbg {
  hash : () -> &@spec.Hash
  key : FixedArray[Byte]
  v : FixedArray[Byte]
  mut reseed_counter : UInt64
}

///|
/// Seed the generator from an entropy input, a nonce and a personalization
/// string (SP 800-90A §10.1.2.3). The three identify the instance; the entropy
/// input carries the strength, and a caller with none of its own should draw it
/// from the platform's [`@moonseed.Source`].
pub fn HmacDrbg::new(
  hash : () -> &@spec.Hash,
  entropy~ : BytesView,
  nonce~ : BytesView,
  personalization~ : BytesView,
) -> HmacDrbg {
  let outlen = hash().size()
  let drbg : HmacDrbg = {
    hash,
    key: FixedArray::make(outlen, b'\x00'),
    v: FixedArray::make(outlen, b'\x01'),
    reseed_counter: 1,
  }
  drbg.update(join([entropy, nonce, personalization]))
  drbg
}

///|
/// Reseed, folding fresh entropy back in (SP 800-90A §10.1.2.4). A long-lived
/// generator outlives the strength it was seeded with, so a caller that has
/// more entropy mixes it rather than starting over and losing the output
/// already drawn.
pub fn HmacDrbg::reseed(
  self : HmacDrbg,
  entropy~ : BytesView,
  additional~ : BytesView,
) -> Unit {
  self.update(join([entropy, additional]))
  self.reseed_counter = 1
}

///|
/// How many bytes have been drawn since the last instantiation or reseed; a
/// caller that watches this can reseed before the interval is spent.
pub fn HmacDrbg::reseed_counter(self : HmacDrbg) -> UInt64 {
  self.reseed_counter
}

///|
/// Draw `n` bytes with no additional input.
pub fn HmacDrbg::generate(self : HmacDrbg, n : Int32) -> Bytes {
  self.next(n, b""[:])
}

///|
/// Draw `n` bytes with an additional input folded in (SP 800-90A §10.1.2.5).
/// The additional input binds this call to its context without changing the
/// seed, so two calls with different context strings diverge.
pub fn HmacDrbg::generate_with(
  self : HmacDrbg,
  n : Int32,
  additional~ : BytesView,
) -> Bytes {
  self.next(n, additional)
}

///|
/// Erase the state. See [`@spec.wipe`] for what that is worth.
pub fn HmacDrbg::wipe(self : HmacDrbg) -> Unit {
  @spec.wipe(self.key)
  @spec.wipe(self.v)
}

///|
/// The Generate step (§10.1.2.5): update with any additional input, drain `V`
/// into the result, then update again so the state moves on.
fn HmacDrbg::next(self : HmacDrbg, n : Int32, additional : BytesView) -> Bytes {
  if additional.length() > 0 {
    self.update(additional)
  }
  let out = Array::make(n, b'\x00')
  let width = self.v.length()
  let mut filled = 0
  while filled < n {
    let nv = @hmac.mac(
      self.key.unsafe_reinterpret_as_bytes()[:],
      self.v.unsafe_reinterpret_as_bytes()[:],
      self.hash,
    )
    for i in 0..<width {
      self.v[i] = nv[i]
    }
    let take = if n - filled < width { n - filled } else { width }
    for i in 0..<take {
      out[filled + i] = self.v[i]
    }
    filled += take
  }
  self.update(additional)
  self.reseed_counter = self.reseed_counter + 1
  Bytes::from_array(out)
}

///|
/// The Update step (§10.1.2.2): mix `provided_data` into `Key` and `V`, with the
/// second half applied only when there is data to bind.
fn HmacDrbg::update(self : HmacDrbg, provided : BytesView) -> Unit {
  let first = @hmac.mac(
    self.key.unsafe_reinterpret_as_bytes()[:],
    join([self.v.unsafe_reinterpret_as_bytes()[:], b"\x00"[:], provided]),
    self.hash,
  )
  for i in 0..<self.key.length() {
    self.key[i] = first[i]
  }
  let v2 = @hmac.mac(
    self.key.unsafe_reinterpret_as_bytes()[:],
    self.v.unsafe_reinterpret_as_bytes()[:],
    self.hash,
  )
  for i in 0..<self.v.length() {
    self.v[i] = v2[i]
  }
  if provided.length() > 0 {
    let second = @hmac.mac(
      self.key.unsafe_reinterpret_as_bytes()[:],
      join([self.v.unsafe_reinterpret_as_bytes()[:], b"\x01"[:], provided]),
      self.hash,
    )
    for i in 0..<self.key.length() {
      self.key[i] = second[i]
    }
    let v3 = @hmac.mac(
      self.key.unsafe_reinterpret_as_bytes()[:],
      self.v.unsafe_reinterpret_as_bytes()[:],
      self.hash,
    )
    for i in 0..<self.v.length() {
      self.v[i] = v3[i]
    }
  }
}

///|
pub extend HmacDrbg with @moonseed.Source::{fill}

///|
/// Fill `buf` from the generator, which is the [`Source`] contract. There is no
/// entropy to run out of — the generator refills itself — so this never raises.
pub impl @moonseed.Source for HmacDrbg with fn fill(
  self : HmacDrbg,
  buf : FixedArray[Byte],
) -> Unit {
  let out = self.next(buf.length(), b""[:])
  for i in 0..<buf.length() {
    buf[i] = out[i]
  }
}

///|
/// Concatenate byte slices into one view; the seed and the update input are
/// several pieces joined without a separator.
fn join(parts : Array[BytesView]) -> BytesView {
  let out : Array[Byte] = []
  for part in parts {
    for b in part {
      out.push(b)
    }
  }
  Bytes::from_array(out)[:]
}
