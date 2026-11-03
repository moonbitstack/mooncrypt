// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which ML-KEM parameter set.
///
/// The three differ in the rank of the module — 2, 3 and 4 rows, so 800, 1184
/// and 1568 bytes of encapsulation key — and in the noise width of the first
/// error term. Everything else, the modulus, the degree and the compression
/// widths, is shared, which is why they are one type and not three packages.
#derive(Eq, Debug)
pub(all) enum Kind {
  K512
  K768
  K1024
}

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The module rank `k`: the number of polynomials in a key, and the reason the
/// three key lengths are not multiples of one another.
fn Kind::k(self : Kind) -> Int32 {
  match self {
    K512 => 2
    K768 => 3
    K1024 => 4
  }
}

///|
/// The noise width `eta_1`: 3 for the smallest set, 2 for the two larger ones.
fn Kind::eta1(self : Kind) -> Int32 {
  match self {
    K512 => 3
    _ => 2
  }
}

///|
/// The compression width of the `u` component: 11 bits for the largest set,
/// 10 for the other two, which is what keeps its ciphertext from growing with
/// the square of the rank.
fn Kind::du(self : Kind) -> Int32 {
  match self {
    K1024 => 11
    _ => 10
  }
}

///|
/// The compression width of the `v` component: one bit more than `u`'s, for the
/// same reason.
fn Kind::dv(self : Kind) -> Int32 {
  match self {
    K1024 => 5
    _ => 4
  }
}

///|
/// The encapsulation-key length: `384 k + 32` bytes, the encoded vector `t`
/// plus the seed the matrix expands from.
pub fn Kind::encapsulation(self : Kind) -> Int32 {
  384 * self.k() + 32
}

///|
/// The decapsulation-key length: `768 k + 96` bytes — the encoded secret, a
/// copy of the encapsulation key, its hash, and the rejection seed.
pub fn Kind::decapsulation(self : Kind) -> Int32 {
  768 * self.k() + 96
}

///|
/// The ciphertext length: `32 (10 k + 4)` bytes.
pub fn Kind::ciphertext(self : Kind) -> Int32 {
  32 * (self.du() * self.k() + self.dv())
}

///|
/// The length of a shared secret, which is 32 bytes for every set.
pub fn Kind::shared(self : Kind) -> Int32 {
  ignore(self)
  32
}

///|
/// The length of the seed a key is derived from: the 32-byte `d` followed by
/// the 32-byte `z` that implicit rejection draws on.
pub fn Kind::seeds(self : Kind) -> Int32 {
  ignore(self)
  64
}

///|
pub impl @spec.Kem for Kind with fn shared(self : Kind) -> Int32 {
  self.shared()
}

///|
pub impl @spec.Kem for Kind with fn encapsulation(self : Kind) -> Int32 {
  self.encapsulation()
}

///|
pub impl @spec.Kem for Kind with fn ciphertext(self : Kind) -> Int32 {
  self.ciphertext()
}

///|
/// An ML-KEM encapsulation key: the public half, which anyone may hold.
pub struct PublicKey {
  kind : Kind
  raw : Bytes
}

///|
/// An ML-KEM decapsulation key.
///
/// The bytes are the standard's own layout, 768 k + 96 of them, so a key file
/// written by another implementation reads here without translation. The
/// encapsulation key is kept alongside because decapsulation re-encrypts, and
/// recovering it from the blob on every operation would mean hashing it again
/// to check the copy.
pub struct PrivateKey {
  kind : Kind
  dk : Bytes
  ek : Bytes
}

///|
/// A shared secret and the ciphertext that carries it to the holder of the
/// private key.
pub(all) struct Encapsulated {
  /// The 32-byte secret both sides now hold.
  secret : Bytes
  /// The ciphertext to send. Its length is [`Kind::ciphertext`].
  ciphertext : Bytes
}

///|
/// Read an encapsulation key.
///
/// The bytes are checked the way FIPS 203 §7.2 requires: the length, and every
/// 12-bit coefficient below `q`. A key that is not the canonical encoding of
/// the polynomial it claims to be is refused rather than reduced, because two
/// different byte strings that behave as one key would let a peer pick which
/// one a signature over the key commits to.
pub fn PublicKey::new(
  kind~ : Kind,
  raw : BytesView,
) -> PublicKey raise @spec.Broken {
  guard raw.length() == kind.encapsulation() else {
    raise @spec.Size(want=kind.encapsulation(), got=raw.length())
  }
  check_encoded(raw[0:384 * kind.k()])
  { kind, raw: raw.to_owned(), }
}

///|
/// Every 12-bit field of an encoded vector must be below `q`.
fn check_encoded(b : BytesView) -> Unit raise @spec.Broken {
  let mut i = 0
  while i + 3 <= b.length() {
    let a0 = b[i].to_int() | ((b[i + 1].to_int() & 0x0F) << 8)
    let a1 = (b[i + 1].to_int() >> 4) | (b[i + 2].to_int() << 4)
    if a0 >= q || a1 >= q {
      raise @spec.Weak
    }
    i += 3
  }
}

///|
/// The bytes this key is written as.
pub fn PublicKey::bytes(self : PublicKey) -> Bytes {
  self.raw
}

///|
/// Which parameter set the key belongs to.
pub fn PublicKey::kind(self : PublicKey) -> Kind {
  self.kind
}

///|
/// Encapsulate: draw a fresh secret, and seal it to this key.
///
/// The ciphertext is what the peer receives; the secret is what both sides end
/// up holding. Nothing here can fail except the source running dry, because the
/// key was checked when it was read.
pub fn[S : @moonseed.Source] PublicKey::encapsulate(
  self : PublicKey,
  source : S,
) -> Encapsulated raise @moonseed.Unavailable {
  let m = @moonseed.bytes(32, source)
  let (secret, ciphertext) = encapsulate_internal(self.kind, self.raw, m)
  { secret, ciphertext, }
}

///|
/// Encapsulate against a given 32-byte message, which FIPS 203 calls `m`.
///
/// Exposed because the standard's own test vectors are stated this way, and
/// because a protocol that has to make encapsulation reproducible — a key
/// exchange with a recorded transcript, a deterministic test — needs the same
/// door. A caller that passes the same `m` twice gets the same ciphertext and
/// the same secret, which is exactly what must not happen in production.
pub fn PublicKey::encapsulate_with(
  self : PublicKey,
  m : BytesView,
) -> Encapsulated raise @spec.Broken {
  guard m.length() == 32 else { raise @spec.Size(want=32, got=m.length()) }
  let (secret, ciphertext) = encapsulate_internal(self.kind, self.raw, m)
  { secret, ciphertext, }
}

///|
/// Derive a key pair from its seed.
///
/// The seed is the 32-byte `d` and the 32-byte `z` of FIPS 203 §7.1, in that
/// order. This is how a key is stored compactly, and how two implementations
/// agree on a key without exchanging one.
pub fn PrivateKey::from_seed(
  kind~ : Kind,
  seed : BytesView,
) -> PrivateKey raise @spec.Broken {
  guard seed.length() == kind.seeds() else {
    raise @spec.Size(want=kind.seeds(), got=seed.length())
  }
  let (ek, dk) = keygen_internal(kind, seed[0:32], seed[32:64])
  { kind, dk, ek, }
}

///|
/// A fresh key pair from `source`, 64 bytes of it.
///
/// `K768` is the set the hybrid TLS group uses, and the one to default to when
/// a caller has no reason to pick.
pub fn[S : @moonseed.Source] PrivateKey::generate(
  source : S,
  kind~ : Kind = K768,
) -> PrivateKey raise @moonseed.Unavailable {
  let seed = @moonseed.bytes(kind.seeds(), source)
  let (ek, dk) = keygen_internal(kind, seed[0:32], seed[32:64])
  { kind, dk, ek, }
}

///|
/// Read a decapsulation key from the standard's own byte layout.
///
/// The embedded copy of the encapsulation key and its hash are checked, as
/// FIPS 203 §7.3 requires: the hash is what binds the two halves, and a key
/// whose halves do not agree would decapsulate to a secret the peer never
/// computed.
pub fn PrivateKey::new(
  kind~ : Kind,
  raw : BytesView,
) -> PrivateKey raise @spec.Broken {
  guard raw.length() == kind.decapsulation() else {
    raise @spec.Size(want=kind.decapsulation(), got=raw.length())
  }
  let at = 384 * kind.k()
  let ek = raw[at:at + kind.encapsulation()]
  guard @spec.eq(
    @sha3.hash(ek, kind=@sha3.Sha3_256),
    raw[at + kind.encapsulation():at + kind.encapsulation() + 32],
  ) else {
    raise @spec.Weak
  }
  check_encoded(ek[0:384 * kind.k()])
  { kind, dk: raw.to_owned(), ek: ek.to_owned(), }
}

///|
/// The bytes this key is written as: the full decapsulation key.
pub fn PrivateKey::bytes(self : PrivateKey) -> Bytes {
  self.dk
}

///|
/// Which parameter set the key belongs to.
pub fn PrivateKey::kind(self : PrivateKey) -> Kind {
  self.kind
}

///|
/// The public half, which may be handed to anyone.
pub fn PrivateKey::encapsulation_key(self : PrivateKey) -> PublicKey {
  { kind: self.kind, raw: self.ek, }
}

///|
/// Recover the secret that [`PublicKey::encapsulate`] chose.
///
/// A ciphertext of the wrong length raises. A ciphertext of the right length
/// that does not decrypt to what it re-encrypts to does *not* raise: FIPS 203
/// replaces the secret with one derived from the rejection seed, so the answer
/// is wrong rather than absent and an attacker learns nothing from the
/// difference.
pub fn PrivateKey::decapsulate(
  self : PrivateKey,
  ciphertext : BytesView,
) -> Bytes raise @spec.Broken {
  guard ciphertext.length() == self.kind.ciphertext() else {
    raise @spec.Size(want=self.kind.ciphertext(), got=ciphertext.length())
  }
  decapsulate_internal(self.kind, self.dk, ciphertext)
}

// --------------------------------------------------------------- the scheme

///|
/// ML-KEM.KeyGen (FIPS 203 Algorithm 16), returning `(ek, dk)`.
fn keygen_internal(kind : Kind, d : BytesView, z : BytesView) -> (Bytes, Bytes) {
  let (t, s, rho) = pke_keygen(kind, d)
  let ek : Array[BytesView] = []
  for i in 0..<kind.k() {
    ek.push(encode12(t[i]))
  }
  ek.push(rho)
  let ek = concat(ek)
  let dk : Array[BytesView] = []
  for i in 0..<kind.k() {
    dk.push(encode12(s[i]))
  }
  dk.push(ek)
  dk.push(@sha3.hash(ek, kind=@sha3.Sha3_256))
  dk.push(z)
  (ek, concat(dk))
}

///|
/// ML-KEM.Encaps (FIPS 203 Algorithm 17), on a fixed `m`. Returns
/// `(secret, ciphertext)`.
fn encapsulate_internal(
  kind : Kind,
  ek : BytesView,
  m : BytesView,
) -> (Bytes, Bytes) {
  // (K, r) = G(m || H(ek)): the hash of the key binds the secret to the key the
  // sender actually holds, so a substituted key yields a secret the real owner
  // cannot compute.
  let seed = @sha3.hash(
    concat([m, @sha3.hash(ek, kind=@sha3.Sha3_256)]),
    kind=@sha3.Sha3_512,
  )
  (seed[0:32].to_owned(), pke_encrypt(kind, ek, m, seed[32:64]))
}

///|
/// ML-KEM.Decaps (FIPS 203 Algorithm 18).
fn decapsulate_internal(kind : Kind, dk : BytesView, c : BytesView) -> Bytes {
  let k = kind.k()
  let secret = 384 * k
  let at = secret + kind.encapsulation()
  let m = pke_decrypt(kind, dk[0:secret], c)
  let h = dk[at:at + 32]
  let seed = @sha3.hash(concat([m, h]), kind=@sha3.Sha3_512)
  let k1 = seed[0:32]
  let re = pke_encrypt(kind, dk[secret:at], m, seed[32:64])
  // The rejection secret is J(z || c), computed whether or not it is used: the
  // branch that chooses between the two is on a comparison that must not be
  // visible in the timing.
  let reject = @sha3.shake256(concat([dk[at + 32:at + 64], c]), 32)
  if @spec.eq(re, c) {
    k1.to_owned()
  } else {
    reject
  }
}
