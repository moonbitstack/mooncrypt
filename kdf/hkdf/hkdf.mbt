// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

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
  salt? : BytesView = b""[:],
  info? : BytesView = b""[:],
  len~ : Int,
) -> Bytes {
  expand(extract(ikm, hash, salt~)[:], hash, info~, len~)
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
  salt? : BytesView = b""[:],
) -> Bytes {
  let key = if salt.length() == 0 {
    Bytes::from_array(Array::make(hash().size(), b'\x00'))
  } else {
    salt.to_owned()
  }
  @hmac.mac(key[:], ikm, hash)
}

///|
/// The expand step (RFC 5869 §2.3): stretch a pseudorandom key to `len` bytes.
///
/// The counter is one byte, so no more than 255 digests can be produced from one
/// key; asking for more is a programming error, not a runtime condition.
pub fn expand(
  prk : BytesView,
  hash : () -> &@spec.Hash,
  info? : BytesView = b""[:],
  len~ : Int,
) -> Bytes {
  let size = hash().size()
  let rounds = (len + size - 1) / size
  guard rounds <= 255 else {
    abort("hkdf: \{len} bytes is more than 255 digests of \{size} bytes")
  }
  let out : Array[Byte] = []
  let mut prev : Bytes = b""
  let m = @hmac.Hmac::new(prk, hash)
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
