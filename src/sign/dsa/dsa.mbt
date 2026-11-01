// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A DSA domain: the primes `p` and `q` (with `q` dividing `p - 1`) and the
/// generator `g = h^{(p - 1)/q} mod p`. The bit length of `q` sets the work
/// factor and the signature size; FIPS 186-4 approves `q` at 160, 224 or 256
/// bits over a `p` of 1024, 2048 or 3072.
struct Domain {
  p : BigInt
  q : BigInt
  g : BigInt
}

///|
/// Build a domain from the three values, each fixed-width big-endian.
pub fn Domain::new(p : BytesView, q : BytesView, g : BytesView) -> Domain {
  {
    p: BigInt::from_octets(p),
    q: BigInt::from_octets(q),
    g: BigInt::from_octets(g),
  }
}

///|
/// Build a domain from values already read as integers.
pub fn Domain::raw(p : BigInt, q : BigInt, g : BigInt) -> Domain {
  { p, q, g, }
}

///|
pub fn Domain::p(self : Domain) -> BigInt {
  self.p
}

///|
pub fn Domain::q(self : Domain) -> BigInt {
  self.q
}

///|
pub fn Domain::g(self : Domain) -> BigInt {
  self.g
}

///|
/// The signature length in bytes: `r` and `s`, each as wide as `q`.
pub fn Domain::size(self : Domain) -> Int32 {
  (@ec.bits(self.q) + 7) / 8
}

///|
/// The width of a value modulo `p` — the public key `y` and the generator `g`
/// — which is wider than a signature.
pub fn Domain::modulus_size(self : Domain) -> Int32 {
  (@ec.bits(self.p) + 7) / 8
}

///|
/// A DSA verification key: `y = g^x mod p`.
struct PublicKey {
  domain : Domain
  hash : () -> &@spec.Hash
  y : BigInt
}

///|
/// A DSA signing key: a scalar `x` in `[1, q - 1]`.
struct PrivateKey {
  domain : Domain
  hash : () -> &@spec.Hash
  x : BigInt
}

///|
/// Convert a digest to an integer, keeping only the leftmost bits of the group
/// order (FIPS 186-4 §4.6). A digest wider than `q` is cut, never reduced modulo
/// it — reducing would let a long digest wrap into a small `e` and weaken the
/// signature.
fn truncate(h : BytesView, order : BigInt) -> BigInt {
  let e = BigInt::from_octets(h)
  let extra = h.length() * 8 - @ec.bits(order)
  if extra > 0 {
    e >> extra
  } else {
    e
  }
}

///|
/// `a^{-1} mod m` by Fermat's little theorem, which needs a prime modulus — `q`
/// is prime.
fn inv(a : BigInt, m : BigInt) -> BigInt {
  a.pow(m - (2 : BigInt), modulus=m)
}

///|
/// Read a public key from `y`, fixed-width big-endian and as wide as `p`,
/// paired with SHA-256.
pub fn PublicKey::new(
  y : BytesView,
  domain~ : Domain,
) -> PublicKey raise @spec.Broken {
  PublicKey::with_hash(y, fn() { @sha2.Hasher::new() }, domain~)
}

///|
/// Read a public key from `y` against a digest of the caller's choosing.
pub fn PublicKey::with_hash(
  y : BytesView,
  hash : () -> &@spec.Hash,
  domain~ : Domain,
) -> PublicKey raise @spec.Broken {
  let size = domain.modulus_size()
  guard y.length() == size else { raise @spec.Size(want=size, got=y.length()) }
  { domain, hash, y: BigInt::from_octets(y), }
}

///|
/// The key as `y`, fixed-width big-endian and as wide as `p`.
pub fn PublicKey::bytes(self : PublicKey) -> Bytes {
  self.y.to_octets(length=self.domain.modulus_size())
}

///|
/// Which domain this key is on.
pub fn PublicKey::domain(self : PublicKey) -> Domain {
  self.domain
}

///|
/// Read a signing key from its scalar `x`, fixed-width big-endian, paired with
/// SHA-256.
pub fn PrivateKey::new(
  scalar : BytesView,
  domain~ : Domain,
) -> PrivateKey raise @spec.Broken {
  PrivateKey::with_hash(scalar, fn() { @sha2.Hasher::new() }, domain~)
}

///|
/// Read a signing key from its scalar `x` against a digest of the caller's
/// choosing.
pub fn PrivateKey::with_hash(
  scalar : BytesView,
  hash : () -> &@spec.Hash,
  domain~ : Domain,
) -> PrivateKey raise @spec.Broken {
  let size = domain.size()
  guard scalar.length() == size else {
    raise @spec.Size(want=size, got=scalar.length())
  }
  let x = BigInt::from_octets(scalar)
  guard x >= (1 : BigInt) && x < domain.q else { raise @spec.Tag }
  { domain, hash, x, }
}

///|
/// The scalar written as fixed-width big-endian.
pub fn PrivateKey::bytes(self : PrivateKey) -> Bytes {
  self.x.to_octets(length=self.domain.size())
}

///|
/// Which domain this key is on.
pub fn PrivateKey::domain(self : PrivateKey) -> Domain {
  self.domain
}

///|
/// The verification key that matches this signing key: `y = g^x mod p`.
pub fn PrivateKey::public(self : PrivateKey) -> PublicKey {
  let y = self.domain.g.pow(self.x, modulus=self.domain.p)
  { domain: self.domain, hash: self.hash, y, }
}

///|
/// A fresh signing key, its scalar drawn uniformly from `[1, q - 1]` as FIPS
/// 186-5 A.2.2 draws it. The key is paired with SHA-256; use
/// [`PrivateKey::generate_with`] for another digest.
pub fn[S : @moonseed.Source] PrivateKey::generate(
  source : S,
  domain~ : Domain,
) -> PrivateKey raise @moonseed.Unavailable {
  PrivateKey::generate_with(source, fn() { @sha2.Hasher::new() }, domain~)
}

///|
/// A fresh signing key paired with a digest of the caller's choosing.
pub fn[S : @moonseed.Source] PrivateKey::generate_with(
  source : S,
  hash : () -> &@spec.Hash,
  domain~ : Domain,
) -> PrivateKey raise @moonseed.Unavailable {
  let order = domain.q.to_octets(length=domain.size())
  let x = BigInt::from_octets(@moonseed.scalar(order, source))
  { domain, hash, x, }
}

///|
pub extend PrivateKey with @spec.Signer::{sign}

///|
/// Sign a message (FIPS 186-4 §4.7), returning `r ∥ s` — two fixed-width
/// big-endian integers. The nonce is the deterministic RFC 6979 value, so a
/// signature is reproducible and needs no entropy source; a repeated or guessed
/// nonce leaks the private key, which is why it is derived rather than drawn.
pub impl @spec.Signer for PrivateKey with fn sign(
  self : PrivateKey,
  msg : BytesView,
) -> Bytes {
  let size = self.domain.size()
  let h1 = @spec.digest((self.hash)(), msg)
  let e = truncate(h1[:], self.domain.q)
  let mut k = rfc6979(self, h1)
  // A zero `r` or `s` is vanishingly unlikely and would be a signature that
  // verifies for anything, so it is re-derived rather than emitted.
  for _ in 0..<64 {
    let r = self.domain.g.pow(k, modulus=self.domain.p) % self.domain.q
    let s = inv(k, self.domain.q) * (e + self.x * r) % self.domain.q
    if r != (0 : BigInt) && s != (0 : BigInt) {
      let out : Array[Byte] = []
      for b in r.to_octets(length=size) {
        out.push(b)
      }
      for b in s.to_octets(length=size) {
        out.push(b)
      }
      return Bytes::from_array(out)
    }
    k = k + (1 : BigInt)
  }
  abort("dsa: no usable nonce after 64 attempts, which cannot happen")
}

///|
pub extend PublicKey with @spec.Verifier::{verify}

///|
/// Check an `r ∥ s` signature (FIPS 186-4 §4.8).
pub impl @spec.Verifier for PublicKey with fn verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  let size = self.domain.size()
  if sig.length() != 2 * size {
    return false
  }
  let r = BigInt::from_octets(sig[0:size])
  let s = BigInt::from_octets(sig[size:])
  if r < (1 : BigInt) ||
    r >= self.domain.q ||
    s < (1 : BigInt) ||
    s >= self.domain.q {
    return false
  }
  let e = truncate(@spec.digest((self.hash)(), msg)[:], self.domain.q)
  let w = inv(s, self.domain.q)
  let u1 = e * w % self.domain.q
  let u2 = r * w % self.domain.q
  let gu1 = self.domain.g.pow(u1, modulus=self.domain.p)
  let yu2 = self.y.pow(u2, modulus=self.domain.p)
  let v = gu1 * yu2 % self.domain.p % self.domain.q
  v == r
}

///|
/// The deterministic nonce of RFC 6979 §3.2: an HMAC-DRBG seeded with the
/// private key and the message digest, drained until it yields a scalar in
/// `[1, q - 1]`.
fn rfc6979(key : PrivateKey, h1 : Bytes) -> BigInt {
  let order = key.domain.q
  let size = key.domain.size()
  let hlen = (key.hash)().size()
  let x = key.x.to_octets(length=size)
  let e = truncate(h1[:], order).to_octets(length=size)
  let mut v = Bytes::make(hlen, b'\x01')
  let mut k = Bytes::make(hlen, b'\x00')
  k = @hmac.mac(k[:], join([v[:], b"\x00"[:], x[:], e[:]]), key.hash)
  v = @hmac.mac(k[:], v[:], key.hash)
  k = @hmac.mac(k[:], join([v[:], b"\x01"[:], x[:], e[:]]), key.hash)
  v = @hmac.mac(k[:], v[:], key.hash)
  for _ in 0..<1000 {
    // The order can be wider than one digest — P-521 needs two — so the
    // candidate is filled a digest at a time before it is read as an integer.
    let t : Array[Byte] = []
    while t.length() < size {
      v = @hmac.mac(k[:], v[:], key.hash)
      for b in v {
        t.push(b)
      }
    }
    let candidate = truncate(Bytes::from_array(t)[0:size], order)
    if candidate >= (1 : BigInt) && candidate < order {
      return candidate
    }
    k = @hmac.mac(k[:], join([v[:], b"\x00"[:]]), key.hash)
    v = @hmac.mac(k[:], v[:], key.hash)
  }
  abort("dsa: the RFC 6979 generator did not produce a scalar in range")
}

///|
/// Concatenate byte slices into one view; the HMAC-DRBG seed is several pieces
/// joined without a separator.
fn join(parts : Array[BytesView]) -> BytesView {
  let out : Array[Byte] = []
  for part in parts {
    for b in part {
      out.push(b)
    }
  }
  Bytes::from_array(out)[:]
}
