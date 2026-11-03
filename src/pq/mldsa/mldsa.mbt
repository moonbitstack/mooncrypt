// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which ML-DSA parameter set.
///
/// The three move together: more rows in the matrix, more noise in the secret,
/// a wider masking range and a challenge with more non-zero coefficients. They
/// are one type because every one of those is a table entry, not a different
/// algorithm.
#derive(Eq, Debug)
pub(all) enum Kind {
  D44
  D65
  D87
}

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The number of rows of the public matrix, which is also the length of `t`.
fn Kind::k(self : Kind) -> Int32 {
  match self {
    D44 => 4
    D65 => 6
    D87 => 8
  }
}

///|
/// The number of columns, which is also the length of `s1` and of the mask.
fn Kind::l(self : Kind) -> Int32 {
  match self {
    D44 => 4
    D65 => 5
    D87 => 7
  }
}

///|
/// The noise width: coefficients of the secret lie in `[-eta, eta]`.
fn Kind::eta(self : Kind) -> Int32 {
  match self {
    D44 | D87 => 2
    D65 => 4
  }
}

///|
/// The number of `±1` entries in the challenge.
fn Kind::tau(self : Kind) -> Int32 {
  match self {
    D44 => 39
    D65 => 49
    D87 => 60
  }
}

///|
/// The masking range: `y` is drawn from `(-gamma1, gamma1]`.
fn Kind::gamma1(self : Kind) -> Int32 {
  match self {
    D44 => 1 << 17
    _ => 1 << 19
  }
}

///|
/// The decomposition range: how coarse the published high bits of `w` are.
fn Kind::gamma2(self : Kind) -> Int32 {
  match self {
    D44 => (q - 1) / 88
    _ => (q - 1) / 32
  }
}

///|
/// The rejection bound, `tau * eta`: how far `z` may drift from `y` before the
/// challenge has leaked something about the secret.
fn Kind::beta(self : Kind) -> Int32 {
  self.tau() * self.eta()
}

///|
/// The largest number of `1`s a hint may contain.
fn Kind::omega(self : Kind) -> Int32 {
  match self {
    D44 => 80
    D65 => 55
    D87 => 75
  }
}

///|
/// The width of the challenge hash: `lambda / 4` bytes.
fn Kind::challenge(self : Kind) -> Int32 {
  match self {
    D44 => 32
    D65 => 48
    D87 => 64
  }
}

///|
/// The number of bits the high half of `w` is packed in: 4 when there are 16
/// possible values, 6 when there are 44.
fn Kind::high_bits_width(self : Kind) -> Int32 {
  if self.gamma2() == (q - 1) / 32 {
    4
  } else {
    6
  }
}

///|
/// The bytes one polynomial of the secret takes: 96 when `eta` is 2, 128 when
/// it is 4.
fn Kind::secret_width(self : Kind) -> Int32 {
  if self.eta() == 2 {
    96
  } else {
    128
  }
}

///|
/// The public-key length: `32 + 320 k` bytes.
pub fn Kind::public_key(self : Kind) -> Int32 {
  32 + 320 * self.k()
}

///|
/// The private-key length: the two seeds, the public-key hash, and the packed
/// `s1`, `s2` and `t0`.
pub fn Kind::private_key(self : Kind) -> Int32 {
  let w = self.secret_width()
  128 + self.l() * w + self.k() * w + self.k() * 416
}

///|
/// The signature length: the challenge hash, the packed `z`, and the hint.
pub fn Kind::signature(self : Kind) -> Int32 {
  self.challenge() + self.l() * 32 * mask_bits(self) + self.omega() + self.k()
}

///|
/// The seed length, which is 32 bytes for every set.
pub fn Kind::seeds(self : Kind) -> Int32 {
  ignore(self)
  32
}

///|
/// The longest context string a signature may carry, in bytes.
pub let context_size : Int32 = 255

///|
/// An ML-DSA verification key.
pub struct PublicKey {
  kind : Kind
  raw : Bytes
}

///|
/// An ML-DSA signing key.
///
/// The components the rejection loop multiplies by are expanded once, here, and
/// kept in the transform domain: every attempt needs them, and re-deriving them
/// per attempt would cost more than the attempt itself. The public key is kept
/// alongside because it is not part of the private key's bytes and computing it
/// on demand would mean running the key generation again.
pub struct PrivateKey {
  kind : Kind
  raw : Bytes
  public : Bytes
  rho : Bytes
  key : Bytes
  tr : Bytes
  s1 : Array[Poly]
  s2 : Array[Poly]
  t0 : Array[Poly]
}

///|
/// Read a verification key. Only the length is checked: the ten-bit fields of
/// `t1` cannot name anything outside the range they are decoded into.
pub fn PublicKey::new(
  kind~ : Kind,
  raw : BytesView,
) -> PublicKey raise @spec.Broken {
  guard raw.length() == kind.public_key() else {
    raise @spec.Size(want=kind.public_key(), got=raw.length())
  }
  { kind, raw: raw.to_owned(), }
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
/// Derive a key pair from its 32-byte seed, as FIPS 204 §7.1 does.
pub fn PrivateKey::from_seed(
  kind~ : Kind,
  seed : BytesView,
) -> PrivateKey raise @spec.Broken {
  guard seed.length() == kind.seeds() else {
    raise @spec.Size(want=kind.seeds(), got=seed.length())
  }
  let (pk, sk) = keygen_internal(kind, seed)
  key_of(kind, sk, pk)
}

///|
/// A fresh key pair from `source`.
///
/// `D65` is the set TLS and the deployed profiles use, and the one to default
/// to when a caller has no reason to pick.
pub fn[S : @moonseed.Source] PrivateKey::generate(
  source : S,
  kind~ : Kind = D65,
) -> PrivateKey raise @moonseed.Unavailable {
  let (pk, sk) = keygen_internal(kind, @moonseed.bytes(kind.seeds(), source))
  key_of(kind, sk, pk)
}

///|
/// Read a signing key from the standard's byte layout.
///
/// The public key is not stored in it, so it is recomputed — one matrix product
/// at load, after which signing costs what it costs.
pub fn PrivateKey::new(
  kind~ : Kind,
  raw : BytesView,
) -> PrivateKey raise @spec.Broken {
  guard raw.length() == kind.private_key() else {
    raise @spec.Size(want=kind.private_key(), got=raw.length())
  }
  let (_, public) = public_of_private(kind, raw)
  key_of(kind, raw.to_owned(), public)
}

///|
/// The bytes this key is written as.
pub fn PrivateKey::bytes(self : PrivateKey) -> Bytes {
  self.raw
}

///|
/// Which parameter set the key belongs to.
pub fn PrivateKey::kind(self : PrivateKey) -> Kind {
  self.kind
}

///|
/// The public half.
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  { kind: self.kind, raw: self.public, }
}

///|
/// Sign a message.
///
/// This is the deterministic variant of FIPS 204 §5.2: a given key and message
/// always produce the same signature, which is what `@spec.Signer` promises.
/// [`sign_randomized`] is the hedged variant, and the one to prefer where a
/// source of randomness is available and a fault attack is a concern.
///
/// `context` is the domain separator of FIPS 204 §5.2, at most
/// [`context_size`] bytes: it distinguishes one use of a key from another and
/// is not secret. A longer one is a programming error — a context is a protocol
/// constant, never something a peer supplies — and stops the process rather
/// than producing a signature that cannot be verified.
///
/// `prehash` switches to HashML-DSA (§5.4): the message is digested by that
/// function and its object identifier is signed in front of the digest, so a
/// signature over a pre-hash cannot be read as one over the message.
pub fn PrivateKey::sign(
  self : PrivateKey,
  msg : BytesView,
  context~ : BytesView = b""[:],
  prehash? : PreHash,
) -> Bytes {
  sign_at(self, msg, context, prehash)
}

///|
/// Sign a message with fresh randomness, the hedged variant of FIPS 204 §5.2.
///
/// Hedging makes the signature depend on 32 bytes drawn at signing time, so a
/// fault in one run does not repeat across the others. It is the variant
/// FIPS 204 recommends whenever a source is available.
pub fn[S : @moonseed.Source] PrivateKey::sign_randomized(
  self : PrivateKey,
  msg : BytesView,
  source : S,
  context~ : BytesView = b""[:],
  prehash? : PreHash,
) -> Bytes raise @moonseed.Unavailable {
  let mu = message_representative(self.tr, context, msg, prehash)
  sign_inner(self, mu, @moonseed.bytes(32, source))
}

///|
/// Check a signature.
///
/// A signature that does not verify is a `false`, not an error: a bad signature
/// is an expected answer from a peer, and raising here invites a caller to
/// swallow it.
pub fn PublicKey::verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
  context~ : BytesView = b""[:],
  prehash? : PreHash,
) -> Bool {
  if context.length() > context_size || sig.length() != self.kind.signature() {
    return false
  }
  verify_at(self, msg, sig, context, prehash)
}

///|
/// A hash function usable as the pre-hash of [`PrivateKey::sign`], which is
/// the twelve FIPS 204 §5.4 allows.
///
/// The list is the identity of the algorithm as well as its name: the object
/// identifier that goes in front of the digest is `2.16.840.1.101.3.4.2.x`
/// with `x` the position of the variant here, so the two cannot drift apart.
#derive(Eq, Debug)
pub(all) enum PreHash {
  Sha2_224
  Sha2_256
  Sha2_384
  Sha2_512
  Sha2_512_224
  Sha2_512_256
  Sha3_224
  Sha3_256
  Sha3_384
  Sha3_512
  Shake128
  Shake256
}

///|
pub extend PreHash with Eq::{equal, not_equal}

///|
pub extend PreHash with Debug::{to_repr}

///|
/// The last arc of the object identifier.
fn PreHash::code(self : PreHash) -> Int32 {
  match self {
    Sha2_256 => 1
    Sha2_384 => 2
    Sha2_512 => 3
    Sha2_224 => 4
    Sha2_512_224 => 5
    Sha2_512_256 => 6
    Sha3_224 => 7
    Sha3_256 => 8
    Sha3_384 => 9
    Sha3_512 => 10
    Shake128 => 11
    Shake256 => 12
  }
}

///|
/// The DER encoding of the hash function's object identifier (FIPS 204 §5.4):
/// tag `06`, length, then the arcs of `2.16.840.1.101.3.4.2.x`.
fn PreHash::oid(self : PreHash) -> Bytes {
  Bytes::from_array([
    b'\x06',
    b'\x09',
    b'\x60',
    b'\x86',
    b'\x48',
    b'\x01',
    b'\x65',
    b'\x03',
    b'\x04',
    b'\x02',
    self.code().to_byte(),
  ])
}

///|
/// The digest the pre-hash produces.
fn PreHash::digest(self : PreHash, msg : BytesView) -> Bytes {
  match self {
    Sha2_224 => @sha2.hash(msg, kind=@sha2.Sha224)
    Sha2_256 => @sha2.hash(msg, kind=@sha2.Sha256)
    Sha2_384 => @sha2.hash(msg, kind=@sha2.Sha384)
    Sha2_512 => @sha2.hash(msg, kind=@sha2.Sha512)
    Sha2_512_224 => @sha2.hash(msg, kind=@sha2.Sha512_224)
    Sha2_512_256 => @sha2.hash(msg, kind=@sha2.Sha512_256)
    Sha3_224 => @sha3.hash(msg, kind=@sha3.Sha3_224)
    Sha3_256 => @sha3.hash(msg, kind=@sha3.Sha3_256)
    Sha3_384 => @sha3.hash(msg, kind=@sha3.Sha3_384)
    Sha3_512 => @sha3.hash(msg, kind=@sha3.Sha3_512)
    Shake128 => @sha3.shake128(msg, 32)
    Shake256 => @sha3.shake256(msg, 64)
  }
}

///|
/// The message representative `mu` (FIPS 204 Algorithm 2 and §5.2): the hash of
/// the public-key hash and the framed message.
///
/// The frame is a domain byte, the context length, the context and then the
/// message. The domain byte is 1 for a pre-hashed signature and 0 for a plain
/// one, which is what stops the two from ever covering the same bytes; the
/// length keeps two different splits of the same bytes from colliding.
fn message_representative(
  tr : BytesView,
  context : BytesView,
  msg : BytesView,
  prehash : PreHash?,
) -> Bytes {
  let (domain, body) = match prehash {
    None => (b'\x00', msg)
    Some(p) => (b'\x01', concat([p.oid(), p.digest(msg)]))
  }
  guard context.length() <= context_size else {
    abort(
      "mldsa: a context string is at most \{context_size} bytes, not \{context.length()}",
    )
  }
  @sha3.shake256(
    concat([
      tr,
      Bytes::from_array([domain, context.length().to_byte()]),
      context,
      body,
    ]),
    64,
  )
}

///|
/// Sign without the context-length check, which the callers have made.
fn sign_at(
  key : PrivateKey,
  msg : BytesView,
  context : BytesView,
  prehash : PreHash?,
) -> Bytes {
  sign_mu(key, message_representative(key.tr, context, msg, prehash))
}

///|
/// Verify without the length checks, which the callers have made.
fn verify_at(
  key : PublicKey,
  msg : BytesView,
  sig : BytesView,
  context : BytesView,
  prehash : PreHash?,
) -> Bool {
  verify_inner(key, msg, sig, context, prehash) catch {
    _ => false
  }
}

///|
pub impl @spec.Signer for PrivateKey with fn sign(
  self : PrivateKey,
  msg : BytesView,
) -> Bytes {
  sign_at(self, msg, b""[:], None)
}

///|
pub impl @spec.Verifier for PublicKey with fn verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  verify_at(self, msg, sig, b""[:], None)
}
