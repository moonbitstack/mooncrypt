// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which SLH-DSA parameter set.
///
/// A set is a hash family, a block width `n`, and five numbers: the height of
/// the hypertree, how many layers it is split into, how many bits of the
/// message digest a FORS tree covers, how many of them there are, and how big
/// a hash is allowed to be. The names carry the trade they make — `s` for small
/// signatures and slow signing, `f` for fast signing and larger signatures.
pub(all) enum Kind {
  Sha2_128s
  Sha2_128f
  Sha2_192s
  Sha2_192f
  Sha2_256s
  Sha2_256f
  Shake_128s
  Shake_128f
  Shake_192s
  Shake_192f
  Shake_256s
  Shake_256f
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
fn Kind::family(self : Kind) -> Family {
  match self {
    Sha2_128s | Sha2_128f | Sha2_192s | Sha2_192f | Sha2_256s | Sha2_256f =>
      Sha2
    _ => Shake
  }
}

///|
/// The width of every value the scheme handles: a hash, a node, a signature
/// element. 16, 24 or 32 bytes, giving the second-preimage strength the name
/// advertises.
fn Kind::n(self : Kind) -> Int32 {
  match self {
    Sha2_128s | Sha2_128f | Shake_128s | Shake_128f => 16
    Sha2_192s | Sha2_192f | Shake_192s | Shake_192f => 24
    _ => 32
  }
}

///|
/// The total height of the hypertree.
fn Kind::h(self : Kind) -> Int32 {
  match self {
    Sha2_128s | Shake_128s => 63
    Sha2_128f | Shake_128f => 66
    Sha2_192s | Shake_192s => 63
    Sha2_192f | Shake_192f => 66
    Sha2_256s | Shake_256s => 64
    _ => 68
  }
}

///|
/// How many layers the tree is split into. Signing touches `d` trees of height
/// `h / d`, so a larger `d` trades signature size for signing time.
fn Kind::d(self : Kind) -> Int32 {
  match self {
    Sha2_128s | Shake_128s => 7
    Sha2_128f | Shake_128f => 22
    Sha2_192s | Shake_192s => 7
    Sha2_192f | Shake_192f => 22
    Sha2_256s | Shake_256s => 8
    _ => 17
  }
}

///|
/// The height of one layer, `h / d`.
fn Kind::hp(self : Kind) -> Int32 {
  self.h() / self.d()
}

///|
/// How many bits of the digest each FORS tree covers.
fn Kind::a(self : Kind) -> Int32 {
  match self {
    Sha2_128s | Shake_128s => 12
    Sha2_128f | Shake_128f => 6
    Sha2_192s | Shake_192s => 14
    Sha2_192f | Shake_192f => 8
    Sha2_256s | Shake_256s => 14
    _ => 9
  }
}

///|
/// How many FORS trees there are.
fn Kind::k(self : Kind) -> Int32 {
  match self {
    Sha2_128s | Shake_128s => 14
    Sha2_128f | Shake_128f => 33
    Sha2_192s | Shake_192s => 17
    Sha2_192f | Shake_192f => 33
    Sha2_256s | Shake_256s => 22
    _ => 35
  }
}

///|
/// The length of the message digest `H_msg` produces.
fn Kind::m(self : Kind) -> Int32 {
  match self {
    Sha2_128s | Shake_128s => 30
    Sha2_128f | Shake_128f => 34
    Sha2_192s | Shake_192s => 39
    Sha2_192f | Shake_192f => 42
    Sha2_256s | Shake_256s => 47
    _ => 49
  }
}

///|
/// How many `n`-byte chains a WOTS+ key has: `2n + 3` at `w = 16`, the two
/// checksum chains included.
fn Kind::len(self : Kind) -> Int32 {
  2 * self.n() + 3
}

///|
/// The public-key length: two `n`-byte values.
pub fn Kind::public_key(self : Kind) -> Int32 {
  2 * self.n()
}

///|
/// The private-key length: the two seeds, the public seed and the public root.
pub fn Kind::private_key(self : Kind) -> Int32 {
  4 * self.n()
}

///|
/// The signature length: `R`, the FORS signature and the hypertree signature.
pub fn Kind::signature(self : Kind) -> Int32 {
  let n = self.n()
  n + self.k() * (self.a() + 1) * n + (self.h() + self.d() * self.len()) * n
}

///|
/// The seed a key is derived from: `SK.seed`, `SK.prf` and `PK.seed`, three
/// `n`-byte values.
pub fn Kind::seeds(self : Kind) -> Int32 {
  3 * self.n()
}

///|
/// A SLH-DSA verification key: the public seed and the root of the top tree.
pub struct PublicKey {
  kind : Kind
  raw : Bytes
}

///|
/// A SLH-DSA signing key.
///
/// The four parts are the signature's two secrets, the public seed and the
/// public root; the last two are repeated in the verification key because a
/// signer needs them and a key file should be one file.
pub struct PrivateKey {
  kind : Kind
  raw : Bytes
}

///|
fn concat(parts : Array[BytesView]) -> Bytes {
  let out : Array[Byte] = []
  for part in parts {
    for i in 0..<part.length() {
      out.push(part[i])
    }
  }
  Bytes::from_array(out)
}

///|
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
pub fn PublicKey::bytes(self : PublicKey) -> Bytes {
  self.raw
}

///|
pub fn PublicKey::kind(self : PublicKey) -> Kind {
  self.kind
}

///|
/// Derive a key pair from its `3n`-byte seed: `SK.seed`, `SK.prf`, `PK.seed`.
///
/// The root has to be computed, which means one full tree of height `h / d` —
/// the same work as signing into the top layer.
pub fn PrivateKey::from_seed(
  kind~ : Kind,
  seed : BytesView,
) -> PrivateKey raise @spec.Broken {
  let n = kind.n()
  guard seed.length() == kind.seeds() else {
    raise @spec.Size(want=kind.seeds(), got=seed.length())
  }
  let hs = hashing(kind)
  let pk_seed = seed[2 * n:3 * n]
  let root = compute_root(kind, hs, seed[0:n], pk_seed)
  { kind, raw: concat([seed, root]), }
}

///|
/// A fresh key pair from `source`.
pub fn[S : @moonseed.Source] PrivateKey::generate(
  source : S,
  kind~ : Kind = Shake_128f,
) -> PrivateKey raise @moonseed.Unavailable {
  let seed = @moonseed.bytes(kind.seeds(), source)
  let n = kind.n()
  let hs = hashing(kind)
  let root = compute_root(kind, hs, seed[0:n], seed[2 * n:3 * n])
  { kind, raw: concat([seed, root]), }
}

///|
pub fn PrivateKey::new(
  kind~ : Kind,
  raw : BytesView,
) -> PrivateKey raise @spec.Broken {
  guard raw.length() == kind.private_key() else {
    raise @spec.Size(want=kind.private_key(), got=raw.length())
  }
  { kind, raw: raw.to_owned(), }
}

///|
pub fn PrivateKey::bytes(self : PrivateKey) -> Bytes {
  self.raw
}

///|
pub fn PrivateKey::kind(self : PrivateKey) -> Kind {
  self.kind
}

///|
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  let n = self.kind.n()
  { kind: self.kind, raw: self.raw[2 * n:4 * n].to_owned(), }
}

///|
/// The longest context string a signature may carry, in bytes.
pub let context_size : Int32 = 255

///|
/// A hash function usable as the pre-hash of [`PrivateKey::sign`].
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
} derive(Eq, Debug)

///|
pub extend PreHash with Eq::{equal, not_equal}

///|
pub extend PreHash with Debug::{to_repr}

///|
/// The last arc of the object identifier, `2.16.840.1.101.3.4.2.x`.
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
/// The message as the signature covers it: a domain byte, the context and its
/// length, then the message — or its pre-hash behind an object identifier.
fn framed(context : BytesView, msg : BytesView, prehash : PreHash?) -> Bytes {
  guard context.length() <= context_size else {
    abort(
      "slhdsa: a context string is at most \{context_size} bytes, not \{context.length()}",
    )
  }
  let (domain, body) = match prehash {
    None => (b'\x00', msg)
    Some(p) => (b'\x01', concat([p.oid(), p.digest(msg)]))
  }
  concat([
    Bytes::from_array([domain, context.length().to_byte()]),
    context,
    body,
  ])
}

///|
pub fn PrivateKey::sign(
  self : PrivateKey,
  msg : BytesView,
  context~ : BytesView = b""[:],
  prehash? : PreHash,
) -> Bytes {
  sign_inner(self, framed(context, msg, prehash), None)
}

///|
pub fn[S : @moonseed.Source] PrivateKey::sign_randomized(
  self : PrivateKey,
  msg : BytesView,
  source : S,
  context~ : BytesView = b""[:],
  prehash? : PreHash,
) -> Bytes raise @moonseed.Unavailable {
  let opt_rand = @moonseed.bytes(self.kind.n(), source)
  sign_inner(self, framed(context, msg, prehash), Some(opt_rand))
}

///|
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
  verify_inner(self, framed(context, msg, prehash), sig)
}

///|
pub impl @spec.Signer for PrivateKey with fn sign(
  self : PrivateKey,
  msg : BytesView,
) -> Bytes {
  sign_inner(self, framed(b""[:], msg, None), None)
}

///|
pub impl @spec.Verifier for PublicKey with fn verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  verify_inner(self, framed(b""[:], msg, None), sig)
}
