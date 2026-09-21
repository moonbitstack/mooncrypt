// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which digest a signature is taken over.
///
/// PKCS#1 v1.5 embeds an ASN.1 algorithm identifier in the block it signs, so
/// the scheme cannot be written over an arbitrary hash the way HMAC can: only a
/// digest with a registered identifier is signable. That constraint is this
/// enum.
pub(all) enum Digest {
  Sha1
  Sha224
  Sha256
  Sha384
  Sha512
} derive(Eq, Debug)

///|
pub extend Digest with Eq::{equal, not_equal}

///|
pub extend Digest with Debug::{to_repr}

///|
/// Which padding a signature uses.
///
/// `Pkcs1` is the deterministic block of RFC 8017 §9.2, which JOSE calls RS256
/// and almost every certificate in existence carries. `Pss` is the probabilistic
/// scheme of §9.1, which JOSE calls PS256 and which new designs should prefer —
/// its security rests on a proof rather than on the absence of a known attack.
pub(all) enum Scheme {
  Pkcs1
  /// The salt length in bytes. RFC 8017 recommends the digest's own length;
  /// zero is permitted and makes the signature deterministic.
  Pss(salt~ : Int)
} derive(Eq, Debug)

///|
pub extend Scheme with Eq::{equal, not_equal}

///|
pub extend Scheme with Debug::{to_repr}

///|
/// An RSA verification key: modulus and public exponent.
struct PublicKey {
  n : BigInt
  e : BigInt
  size : Int
  digest : Digest
  scheme : Scheme
}

///|
/// An RSA signing key: modulus, public exponent and private exponent.
///
/// The CRT factors speed signing up fourfold and are not carried, because a key
/// read from its three numbers is the shape every JWK and every hand-written
/// test gives — and because a CRT implementation without fault countermeasures
/// leaks the factorisation to a single bit-flip.
struct PrivateKey {
  n : BigInt
  e : BigInt
  d : BigInt
  size : Int
  digest : Digest
  scheme : Scheme
}

///|
/// Read a verification key from its modulus and exponent, big-endian.
pub fn PublicKey::new(
  modulus : BytesView,
  exponent : BytesView,
  digest? : Digest = Sha256,
  scheme? : Scheme = Pkcs1,
) -> PublicKey raise @spec.Broken {
  let n = BigInt::from_octets(modulus)
  guard n > (0 : BigInt) else { raise @spec.Size(want=1, got=0) }
  { n, e: BigInt::from_octets(exponent), size: octets(n), digest, scheme, }
}

///|
/// Read a signing key from its modulus and its two exponents, big-endian.
pub fn PrivateKey::new(
  modulus : BytesView,
  exponent : BytesView,
  private_exponent : BytesView,
  digest? : Digest = Sha256,
  scheme? : Scheme = Pkcs1,
) -> PrivateKey raise @spec.Broken {
  let n = BigInt::from_octets(modulus)
  guard n > (0 : BigInt) else { raise @spec.Size(want=1, got=0) }
  {
    n,
    e: BigInt::from_octets(exponent),
    d: BigInt::from_octets(private_exponent),
    size: octets(n),
    digest,
    scheme,
  }
}

///|
/// The public half of a signing key — what verifies what it signs.
pub fn PrivateKey::public(self : PrivateKey) -> PublicKey {
  {
    n: self.n,
    e: self.e,
    size: self.size,
    digest: self.digest,
    scheme: self.scheme,
  }
}

///|
/// The modulus width in bytes, which is also the signature width.
pub fn PublicKey::size(self : PublicKey) -> Int {
  self.size
}

///|
/// The modulus width in bytes, which is also the signature width.
pub fn PrivateKey::size(self : PrivateKey) -> Int {
  self.size
}

///|
/// The modulus, big-endian and fixed-width.
pub fn PublicKey::modulus(self : PublicKey) -> Bytes {
  self.n.to_octets(length=self.size)
}

///|
/// The public exponent, big-endian with no leading zeroes.
pub fn PublicKey::exponent(self : PublicKey) -> Bytes {
  self.e.to_octets()
}

///|
pub extend PrivateKey with @spec.Signer::{sign}

///|
/// Sign a message, returning a signature exactly as wide as the modulus.
pub impl @spec.Signer for PrivateKey with fn sign(
  self : PrivateKey,
  msg : BytesView,
) -> Bytes {
  let em = match self.scheme {
    Pkcs1 => pkcs1_encode(self.digest, msg, self.size)
    Pss(salt~) => pss_encode(self.digest, msg, self.size, salt, self.d)
  }
  BigInt::from_octets(em[:])
  .pow(self.d, modulus=self.n)
  .to_octets(length=self.size)
}

///|
pub extend PublicKey with @spec.Verifier::{verify}

///|
/// Check a signature.
///
/// For PKCS#1 the recovered block is compared with the one the message would
/// produce, rather than parsed — parsing is where the Bleichenbacher forgeries
/// of 2006 and 2016 got in, because a parser that ignores trailing bytes accepts
/// a forged signature under a small exponent.
pub impl @spec.Verifier for PublicKey with fn verify(
  self : PublicKey,
  msg : BytesView,
  sig : BytesView,
) -> Bool {
  if sig.length() != self.size {
    return false
  }
  let s = BigInt::from_octets(sig)
  if s >= self.n {
    return false
  }
  let em = s.pow(self.e, modulus=self.n).to_octets(length=self.size)
  match self.scheme {
    Pkcs1 => @spec.eq(em[:], pkcs1_encode(self.digest, msg, self.size)[:])
    Pss(salt~) => pss_check(self.digest, msg, em, salt)
  }
}

// ------------------------------------------------------------------- encoding

///|
/// How many octets the modulus occupies — the width of every signature under it.
fn octets(n : BigInt) -> Int {
  let mut bits = 0
  let mut rest = n
  while rest > (0 : BigInt) {
    bits += 1
    rest = rest >> 1
  }
  (bits + 7) / 8
}

///|
fn hasher(d : Digest) -> &@spec.Hash {
  match d {
    Sha1 => return @sha1.Hasher::new()
    Sha224 => return @sha2.Hasher::new(kind=Sha224)
    Sha256 => return @sha2.Hasher::new()
    Sha384 => return @sha2.Hasher::new(kind=Sha384)
    Sha512 => return @sha2.Hasher::new(kind=Sha512)
  }
}

///|
/// The DER `DigestInfo` header for each digest (RFC 8017 §9.2, note 1): an
/// `AlgorithmIdentifier` with a NULL parameter, then the `OCTET STRING` header.
fn prefix(d : Digest) -> Bytes {
  match d {
    Sha1 => b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
    Sha224 =>
      b"\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c"
    Sha256 =>
      b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
    Sha384 =>
      b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"
    Sha512 =>
      b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
  }
}

///|
/// EMSA-PKCS1-v1_5 (RFC 8017 §9.2): `00 01 FF…FF 00 ∥ DigestInfo(H(m))`.
fn pkcs1_encode(d : Digest, msg : BytesView, size : Int) -> Bytes {
  let tail = prefix(d)
  let h = @spec.digest(hasher(d), msg)
  let fill = size - tail.length() - h.length() - 3
  guard fill >= 8 else {
    abort("rsa: a \{size}-byte modulus is too small for this digest")
  }
  let em : Array[Byte] = [b'\x00', b'\x01']
  for _ in 0..<fill {
    em.push(b'\xFF')
  }
  em.push(b'\x00')
  for b in tail {
    em.push(b)
  }
  for b in h {
    em.push(b)
  }
  Bytes::from_array(em)
}

///|
/// MGF1 (RFC 8017 §B.2.1): a digest run as a counter mode to any length.
fn mgf1(d : Digest, seed : BytesView, len : Int) -> Bytes {
  let out : Array[Byte] = []
  let h = hasher(d)
  let mut counter = 0
  while out.length() < len {
    h.reset()
    h.write(seed)
    h.write(
      Bytes::from_array([
        (counter >> 24).to_byte(),
        (counter >> 16).to_byte(),
        (counter >> 8).to_byte(),
        counter.to_byte(),
      ])[:],
    )
    for b in h.finish() {
      out.push(b)
    }
    counter += 1
  }
  Bytes::from_array(out[0:len].to_owned())
}

///|
/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1).
///
/// The salt is derived from the private exponent and the message rather than
/// drawn at random. Any salt gives a valid signature — a length of zero is
/// explicitly permitted — so deriving it keeps signing reproducible and removes
/// the entropy source, exactly as RFC 6979 does for ECDSA.
fn pss_encode(
  d : Digest,
  msg : BytesView,
  size : Int,
  salt_len : Int,
  secret : BigInt,
) -> Bytes {
  let h = hasher(d)
  let hlen = h.size()
  let m_hash = @spec.digest(h, msg)
  guard size >= hlen + salt_len + 2 else {
    abort("rsa: a \{size}-byte modulus cannot carry a \{salt_len}-byte salt")
  }
  let salt = if salt_len == 0 {
    b""
  } else {
    let seed = @hmac.mac(secret.to_octets()[:], m_hash[:], fn() { hasher(d) })
    mgf1(d, seed[:], salt_len)
  }
  // M' = eight zero octets ∥ mHash ∥ salt
  let primed : Array[Byte] = []
  for _ in 0..<8 {
    primed.push(b'\x00')
  }
  for b in m_hash {
    primed.push(b)
  }
  for b in salt {
    primed.push(b)
  }
  let digest = @spec.digest(hasher(d), Bytes::from_array(primed)[:])
  let db_len = size - hlen - 1
  let db : Array[Byte] = []
  for _ in 0..<(db_len - salt_len - 1) {
    db.push(b'\x00')
  }
  db.push(b'\x01')
  for b in salt {
    db.push(b)
  }
  let mask = mgf1(d, digest[:], db_len)
  let em : Array[Byte] = []
  for i in 0..<db_len {
    em.push((db[i].to_int() ^ mask[i].to_int()).to_byte())
  }
  // The leading bits above the modulus width must be zero (§9.1.1 step 11).
  em[0] = (em[0].to_int() & 0x7F).to_byte()
  for b in digest {
    em.push(b)
  }
  em.push(b'\xBC')
  Bytes::from_array(em)
}

///|
/// EMSA-PSS-VERIFY (RFC 8017 §9.1.2).
///
/// The salt length is read back out of the block rather than assumed, so a
/// signature made with any salt length verifies — which is what interoperating
/// with other implementations requires.
fn pss_check(d : Digest, msg : BytesView, em : Bytes, _salt_len : Int) -> Bool {
  let hlen = hasher(d).size()
  let size = em.length()
  if size < hlen + 2 || em[size - 1] != b'\xBC' {
    return false
  }
  if (em[0].to_int() & 0x80) != 0 {
    return false
  }
  let db_len = size - hlen - 1
  let digest = em[db_len:size - 1]
  let mask = mgf1(d, digest, db_len)
  let db : Array[Byte] = []
  for i in 0..<db_len {
    db.push((em[i].to_int() ^ mask[i].to_int()).to_byte())
  }
  db[0] = (db[0].to_int() & 0x7F).to_byte()
  let mut at = 0
  while at < db_len && db[at] == b'\x00' {
    at += 1
  }
  if at >= db_len || db[at] != b'\x01' {
    return false
  }
  let salt = db[at + 1:]
  let m_hash = @spec.digest(hasher(d), msg)
  let primed : Array[Byte] = []
  for _ in 0..<8 {
    primed.push(b'\x00')
  }
  for b in m_hash {
    primed.push(b)
  }
  for b in salt {
    primed.push(b)
  }
  @spec.eq(@spec.digest(hasher(d), Bytes::from_array(primed)[:])[:], digest)
}
