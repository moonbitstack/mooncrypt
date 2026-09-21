// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Stretch a password into `len` bytes of key by iterating an HMAC `rounds`
/// times (RFC 8018 §5.2).
///
/// The whole security argument is the iteration count: it costs the defender one
/// derivation and the attacker one per guess. Pick it from what the deployment
/// can afford today, not from a number copied out of an old document — SCRAM
/// servers name their own count on the wire, and for password storage the
/// memory-hard KDFs are the better answer where they are available.
///
/// `rounds` and `len` have no defaults, which is itself the mainstream choice:
/// Python's `hashlib.pbkdf2_hmac`, Go's `pbkdf2.Key` and Node's `crypto.pbkdf2`
/// all require both. A default iteration count is a number that goes out of date
/// silently, and this is the one place where being made to type it is the point.
///
/// A count below one and a negative length abort rather than raise. Neither can
/// come from input: they are the calling code saying something it cannot mean.
pub fn key(
  password : BytesView,
  salt : BytesView,
  hash : () -> &@spec.Hash,
  rounds~ : Int,
  len~ : Int,
) -> Bytes {
  guard rounds >= 1 else {
    abort("pbkdf2: \{rounds} rounds is not a derivation")
  }
  guard len >= 0 else { abort("pbkdf2: a key cannot be \{len} bytes long") }
  let m = @hmac.Hmac::new(password, hash)
  let size = m.size()
  let out : Array[Byte] = []
  let blocks = (len + size - 1) / size
  for i in 1..<=blocks {
    // The block index goes in as four big-endian bytes, which is what makes
    // every block of the key a different derivation.
    let counter = Bytes::from_array([
      (i >> 24).to_byte(),
      (i >> 16).to_byte(),
      (i >> 8).to_byte(),
      i.to_byte(),
    ])
    m.reset()
    m.write(salt)
    m.write(counter[:])
    let mut u = m.finish()
    let acc : Array[Byte] = u.to_array()
    for _ in 1..<rounds {
      m.reset()
      m.write(u[:])
      u = m.finish()
      for j in 0..<size {
        acc[j] = (acc[j].to_int() ^ u[j].to_int()).to_byte()
      }
    }
    for b in acc {
      out.push(b)
    }
  }
  Bytes::from_array(out[0:len].to_owned())
}
