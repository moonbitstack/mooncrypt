// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The seed length in bytes for Hash-DRBG (SP 800-90A Table 2): 440 bits for a
/// 256-bit-or-narrower hash, 888 bits for a wider one.
fn seedlen(hash : () -> &@spec.Hash) -> Int32 {
  if hash().size() <= 32 {
    55
  } else {
    111
  }
}

///|
fn to_fixed(b : Bytes) -> FixedArray[Byte] {
  let r = FixedArray::make(b.length(), b'\x00')
  for i in 0..<b.length() {
    r[i] = b[i]
  }
  r
}

///|
/// Hash_df (§10.3.1): enough hash blocks to fill `bits`, each prefixed by a
/// one-byte counter and the four-byte big-endian bit count.
fn hash_df(
  hash : () -> &@spec.Hash,
  input : BytesView,
  bits : Int32,
) -> FixedArray[Byte] {
  let nbytes = (bits + 7) / 8
  let be = FixedArray::make(4, b'\x00')
  be[0] = ((bits >> 24) & 0xFF).to_byte()
  be[1] = ((bits >> 16) & 0xFF).to_byte()
  be[2] = ((bits >> 8) & 0xFF).to_byte()
  be[3] = (bits & 0xFF).to_byte()
  let out : Array[Byte] = []
  let mut counter = 0
  while out.length() < nbytes {
    counter = counter + 1
    let cb = FixedArray::make(1, counter.to_byte())
    let d = @spec.digest(
      hash(),
      join([
        cb.unsafe_reinterpret_as_bytes()[:],
        be.unsafe_reinterpret_as_bytes()[:],
        input,
      ]),
    )
    for b in d {
      out.push(b)
    }
  }
  let r = FixedArray::make(nbytes, b'\x00')
  for i in 0..<nbytes {
    r[i] = out[i]
  }
  r
}

///|
/// `(v + h + c + w) mod 2^(8·len(v))`, big-endian, as wide as `v`. `w` may be
/// empty, which adds nothing.
fn add_mod(
  v : FixedArray[Byte],
  h : FixedArray[Byte],
  c : FixedArray[Byte],
  w : FixedArray[Byte],
) -> FixedArray[Byte] {
  let vb = BigInt::from_octets(v.unsafe_reinterpret_as_bytes()[:])
  let hb = BigInt::from_octets(h.unsafe_reinterpret_as_bytes()[:])
  let cb = BigInt::from_octets(c.unsafe_reinterpret_as_bytes()[:])
  let wb = if w.length() == 0 {
    (0 : BigInt)
  } else {
    BigInt::from_octets(w.unsafe_reinterpret_as_bytes()[:])
  }
  let sum = (vb + hb + cb + wb).to_octets()
  // Keeping only the low len(v) bytes is the reduction modulo 2^(8·len(v)).
  let width = v.length()
  let r = FixedArray::make(width, b'\x00')
  let n = sum.length()
  for i in 0..<width {
    let src = n - width + i
    if src >= 0 {
      r[i] = sum[src]
    }
  }
  r
}

///|
/// Hash-DRBG (SP 800-90A §10.1.1): a deterministic generator whose state is a
/// seed `V` and a constant `C`, advanced by adding hash outputs into `V`.
pub struct HashDrbg {
  hash : () -> &@spec.Hash
  mut v : FixedArray[Byte]
  mut c : FixedArray[Byte]
  mut reseed_counter : UInt64
  interval : UInt64
}

///|
/// Seed the generator from an entropy input, a nonce and a personalization
/// string (§10.1.1.2). `V` starts from the seed and `C` from `0x00 ∥ V`.
pub fn HashDrbg::new(
  hash : () -> &@spec.Hash,
  entropy~ : BytesView,
  nonce~ : BytesView,
  personalization~ : BytesView,
  interval~ : UInt64 = reseed_limit,
) -> HashDrbg {
  let bits = seedlen(hash) * 8
  let seed = hash_df(hash, join([entropy, nonce, personalization]), bits)
  let v = seed
  let c = hash_df(
    hash,
    join([b"\x00"[:], v.unsafe_reinterpret_as_bytes()[:]]),
    bits,
  )
  { hash, v, c, reseed_counter: 1, interval, }
}

///|
/// Reseed from fresh entropy (§10.1.1.3): re-derive `V` and `C` from
/// `0x01 ∥ V ∥ entropy ∥ additional` and reset the counter.
pub fn HashDrbg::reseed(
  self : HashDrbg,
  entropy~ : BytesView,
  additional~ : BytesView,
) -> Unit {
  let bits = seedlen(self.hash) * 8
  let seed = hash_df(
    self.hash,
    join([
      b"\x01"[:],
      self.v.unsafe_reinterpret_as_bytes()[:],
      entropy,
      additional,
    ]),
    bits,
  )
  self.v = seed
  self.c = hash_df(
    self.hash,
    join([b"\x00"[:], self.v.unsafe_reinterpret_as_bytes()[:]]),
    bits,
  )
  self.reseed_counter = 1
}

///|
/// Draw `n` bytes with no additional input.
pub fn HashDrbg::generate(self : HashDrbg, n : Int32) -> Bytes raise Refused {
  self.generate_with(n, additional=b""[:])
}

///|
/// Draw `n` bytes with an additional input bound to this call (§10.1.1.5).
pub fn HashDrbg::generate_with(
  self : HashDrbg,
  n : Int32,
  additional~ : BytesView,
) -> Bytes raise Refused {
  if self.reseed_counter > self.interval {
    raise Reseed(limit=self.interval)
  }
  let w = if additional.length() > 0 {
    to_fixed(
      @spec.digest(
        (self.hash)(),
        join([b"\x02"[:], self.v.unsafe_reinterpret_as_bytes()[:], additional]),
      ),
    )
  } else {
    FixedArray::make(0, b'\x00')
  }
  let h0 = @spec.digest(
    (self.hash)(),
    join([b"\x03"[:], self.v.unsafe_reinterpret_as_bytes()[:]]),
  )
  self.v = add_mod(self.v, to_fixed(h0), self.c, w)
  let out : Array[Byte] = []
  while out.length() < n {
    let h = @spec.digest(
      (self.hash)(),
      join([b"\x03"[:], self.v.unsafe_reinterpret_as_bytes()[:]]),
    )
    for b in h {
      out.push(b)
    }
    self.v = add_mod(self.v, to_fixed(h), self.c, w)
  }
  let r = Array::make(n, b'\x00')
  for i in 0..<n {
    r[i] = out[i]
  }
  self.reseed_counter = self.reseed_counter + 1UL
  Bytes::from_array(r)
}

///|
/// How many requests have been served since the last instantiation or reseed.
pub fn HashDrbg::reseed_counter(self : HashDrbg) -> UInt64 {
  self.reseed_counter
}

///|
/// The number of requests this generator will serve between reseeds.
pub fn HashDrbg::interval(self : HashDrbg) -> UInt64 {
  self.interval
}

///|
pub extend HashDrbg with @moonseed.Source::{fill}

///|
pub impl @moonseed.Source for HashDrbg with fn fill(
  self : HashDrbg,
  buf : FixedArray[Byte],
) -> Unit raise @moonseed.Unavailable {
  let out = self.generate_with(buf.length(), additional=b""[:]) catch {
    Reseed(_) => raise @moonseed.Unavailable::Exhausted
  }
  for i in 0..<buf.length() {
    buf[i] = out[i]
  }
}
