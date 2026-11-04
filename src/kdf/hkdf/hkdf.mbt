// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A pseudorandom key: what [`extract`] returns and the only thing [`expand`]
/// accepts.
///
/// It carries the digest it was extracted with, so the two halves of RFC 5869
/// cannot be paired with different algorithms. A bare `Bytes` could not say
/// which hash produced it, and expanding it under another one runs without
/// complaint and yields garbage — the RFC pairs the two steps by construction,
/// so the type does too.
struct Prk {
  key : Bytes
  hash : () -> &@spec.Hash
}

///|
/// A key that did not come out of [`extract`] here. TLS 1.3 expands from the output of an earlier
/// expansion, and a session ticket brings a stored key back, and both are pseudorandom keys in the
/// sense of RFC 5869 §2.3, which asks only for one at least as long as the digest.
pub fn Prk::new(key : BytesView, hash : () -> &@spec.Hash) -> Prk {
  { key: key.to_owned(), hash, }
}

///|
/// The extracted key itself, for a caller that has to store it — a TLS session
/// ticket, for instance, keeps the resumption secret between connections.
pub fn Prk::bytes(self : Prk) -> Bytes {
  self.key
}

///|
/// The digest size the key was extracted with, which is also its length.
pub fn Prk::size(self : Prk) -> Int32 {
  self.key.length()
}

///|
/// Extract-then-expand in one call: turn input keying material into `len` bytes
/// of key.
///
/// `info` separates the uses of one secret — two derivations with different
/// `info` are independent keys, which is how one handshake secret yields a
/// separate key for each direction. `salt` need not be secret and need not be
/// present; when it is, the extraction is stronger against a non-uniform input.
pub fn key(
  ikm : BytesView,
  hash : () -> &@spec.Hash,
  salt~ : BytesView = b""[:],
  info~ : BytesView = b""[:],
  len~ : Int32,
) -> Bytes {
  expand(extract(ikm, hash, salt~), info~, len~)
}

///|
/// The extract step (RFC 5869 §2.2): concentrate whatever entropy the input has
/// into one uniform pseudorandom key of the hash's own length.
///
/// An absent salt is a string of zeroes as long as the digest, which is what the
/// RFC specifies — not a special case.
pub fn extract(
  ikm : BytesView,
  hash : () -> &@spec.Hash,
  salt~ : BytesView = b""[:],
) -> Prk {
  let key = if salt.length() == 0 {
    Bytes::from_array(Array::make(hash().size(), b'\x00'))
  } else {
    salt.to_owned()
  }
  { key: @hmac.mac(key[:], ikm, hash), hash, }
}

///|
/// The expand step (RFC 5869 §2.3): stretch a pseudorandom key to `len` bytes.
///
/// The counter is one byte, so no more than 255 digests can be produced from one
/// key; asking for more is a programming error, not a runtime condition.
pub fn expand(prk : Prk, info~ : BytesView = b""[:], len~ : Int32) -> Bytes {
  let hash = prk.hash
  let size = hash().size()
  let rounds = (len + size - 1) / size
  guard rounds <= 255 else {
    abort("hkdf: \{len} bytes is more than 255 digests of \{size} bytes")
  }
  let out : Array[Byte] = []
  let mut prev : Bytes = b""
  let m = @hmac.Hmac::new(prk.key[:], hash)
  for i in 1..<=rounds {
    m.reset()
    m.write(prev[:])
    m.write(info)
    m.write(Bytes::from_array([i.to_byte()])[:])
    prev = m.finish()
    for b in prev {
      out.push(b)
    }
  }
  Bytes::from_array(out[0:len].to_owned())
}
