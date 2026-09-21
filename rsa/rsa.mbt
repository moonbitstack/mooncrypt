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

// ----------------------------------------------------------------- encryption

///|
/// Encrypt under RSAES-OAEP (RFC 8017 §7.1.1), returning a block exactly as
/// wide as the modulus.
///
/// `seed` is the `hLen` random octets OAEP masks with, and it is a required
/// parameter rather than something drawn here: this library holds no entropy
/// source, and the seed is what makes the same message encrypt differently
/// twice. Go's `rsa.EncryptOAEP` and Rust's `rsa` crate take the randomness the
/// same way. **Reusing a seed across messages destroys OAEP's security** — draw
/// it fresh from the platform's CSPRNG for every call.
///
/// `digest` is the hash OAEP runs, and `mgf` the one MGF1 masks with; leaving
/// `mgf` out uses `digest`, which is what Go and Node do, while Python and Java
/// let the two differ, which is why it is a parameter here.
///
/// `digest` defaults to SHA-1: it is RFC 8017's own default, and what OpenSSL,
/// Java's `OAEPParameterSpec.DEFAULT` and Node all take. OAEP does not rest on
/// the hash's collision resistance, so this is not the choice it would be for a
/// signature — but Go and Python require the caller to name it, and a new
/// design should pass `digest=Sha256`.
///
/// The key's own `digest` and `scheme` govern signatures and are not consulted
/// here; encryption and signing are separate schemes over the same key.
pub fn PublicKey::encrypt(
  self : PublicKey,
  plain : BytesView,
  seed~ : BytesView,
  digest? : Digest = Sha1,
  mgf? : Digest,
  label? : BytesView = b""[:],
) -> Bytes raise @spec.Broken {
  let mgf = match mgf {
    Some(m) => m
    None => digest
  }
  let l_hash = digest_of(digest, label)
  let hlen = l_hash.length()
  let k = self.size
  let most = k - 2 * hlen - 2
  guard most >= 0 && plain.length() <= most else {
    raise @spec.Size(want=if most < 0 { 0 } else { most }, got=plain.length())
  }
  guard seed.length() == hlen else {
    raise @spec.Size(want=hlen, got=seed.length())
  }
  // DB = lHash || PS || 0x01 || M, padded to k - hLen - 1 octets.
  let db : Array[Byte] = []
  for b in l_hash {
    db.push(b)
  }
  for _ in 0..<(most - plain.length()) {
    db.push(0)
  }
  db.push(1)
  for b in plain {
    db.push(b)
  }
  let masked_db = xor(db, mgf1(mgf, seed, k - hlen - 1))
  let masked_seed = xor(
    seed.to_owned().to_array(),
    mgf1(mgf, Bytes::from_array(masked_db)[:], hlen),
  )
  // EM = 0x00 || maskedSeed || maskedDB
  let em : Array[Byte] = [0]
  for b in masked_seed {
    em.push(b)
  }
  for b in masked_db {
    em.push(b)
  }
  BigInt::from_octets(Bytes::from_array(em)[:])
  .pow(self.e, modulus=self.n)
  .to_octets(length=k)
}

///|
/// Decrypt an RSAES-OAEP block (RFC 8017 §7.1.2).
///
/// Every way the block can be wrong reports the same [`@spec.Tag`], and the
/// checks all run before any of them is acted on: which check failed is exactly
/// what Manger's 2001 attack reads off, so it is not told apart here.
///
/// `digest`, `mgf` and `label` mean what they do in [`PublicKey::encrypt`] and
/// must match what encrypted the block.
pub fn PrivateKey::decrypt(
  self : PrivateKey,
  cipher : BytesView,
  digest? : Digest = Sha1,
  mgf? : Digest,
  label? : BytesView = b""[:],
) -> Bytes raise @spec.Broken {
  let mgf = match mgf {
    Some(m) => m
    None => digest
  }
  let l_hash = digest_of(digest, label)
  let hlen = l_hash.length()
  let k = self.size
  guard cipher.length() == k && k >= 2 * hlen + 2 else {
    raise @spec.Size(want=k, got=cipher.length())
  }
  let c = BigInt::from_octets(cipher)
  guard c < self.n else { raise @spec.Tag }
  let em = c.pow(self.d, modulus=self.n).to_octets(length=k)
  let masked_seed = em[1:1 + hlen].to_owned().to_array()
  let masked_db = em[1 + hlen:k].to_owned().to_array()
  let seed = xor(masked_seed, mgf1(mgf, Bytes::from_array(masked_db)[:], hlen))
  let db = xor(masked_db, mgf1(mgf, Bytes::from_array(seed)[:], k - hlen - 1))
  // DB = lHash' || PS || 0x01 || M: the leading octet must be zero, the hash
  // must match, and the padding must end in a single 0x01.
  let mut bad = em[0] != (0 : Byte)
  if !@spec.eq(l_hash[:], Bytes::from_array(db[0:hlen].to_owned())[:]) {
    bad = true
  }
  let mut at = -1
  for i in hlen..<db.length() {
    if db[i] == (1 : Byte) && at < 0 {
      at = i
    } else if db[i] != (0 : Byte) && at < 0 {
      bad = true
    }
  }
  if at < 0 {
    bad = true
  }
  guard !bad else { raise @spec.Tag }
  Bytes::from_array(db[at + 1:].to_owned())
}

///|
/// The digest of one message, for the label hash both directions need.
fn digest_of(d : Digest, msg : BytesView) -> Bytes {
  let h = hasher(d)
  h.write(msg)
  h.finish()
}

///|
/// `a` masked with `b`, which must be at least as long.
fn xor(a : Array[Byte], b : Bytes) -> Array[Byte] {
  let out : Array[Byte] = []
  for i in 0..<a.length() {
    out.push((a[i].to_int() ^ b[i].to_int()).to_byte())
  }
  out
}
