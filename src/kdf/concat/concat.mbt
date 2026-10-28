// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Derive `len` bytes of key from a shared secret.
///
/// `z` is the secret the key exchange agreed on; `other_info` is everything the
/// protocol wants bound into the derivation — the algorithm identifiers, the two
/// parties' key info, the length of the key being made. SP 800-56A §5.8.1 spells
/// that structure out as a DER `OtherInfo` and calls it optional; the octets are
/// taken as given here, because a protocol that defines its own layout (TLS 1.3,
/// CMS, S/MIME each do) has to pass its own.
///
/// The counter starts at one, and a call longer than one digest concatenates as
/// many blocks as it needs, each counted from one upwards.
pub fn key(
  z : BytesView,
  hash : () -> &@spec.Hash,
  other_info~ : BytesView = b""[:],
  len~ : Int32,
) -> Bytes {
  guard len > 0 else { abort("concat kdf: \{len} is not a positive length") }
  let size = hash().size()
  let rounds = (len + size - 1) / size
  let h = hash()
  let out : Array[Byte] = []
  for i in 1..<=rounds {
    h.reset()
    h.write(counter(i))
    h.write(z)
    h.write(other_info)
    let block = h.finish()
    for j in 0..<block.length() {
      out.push(block[j])
    }
  }
  // The last block is almost always a partial one, and the excess is dropped:
  // the output is exactly as long as it was asked to be.
  Bytes::from_array(out[0:len])
}

///|
/// The four-byte big-endian block counter.
///
/// Big-endian and starting at one, neither of which is a choice: a little-endian
/// counter or a zero-based one produces a different key from the one every other
/// implementation of this standard produces.
fn counter(i : Int32) -> Bytes {
  Bytes::from_array([
    ((i >> 24) & 0xFF).to_byte(),
    ((i >> 16) & 0xFF).to_byte(),
    ((i >> 8) & 0xFF).to_byte(),
    (i & 0xFF).to_byte(),
  ])
}
