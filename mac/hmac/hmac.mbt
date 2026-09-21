// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A keyed MAC over any hash.
///
/// The construction is `H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ message))`, and the only
/// things it needs to know about the hash are its block size and how to start a
/// fresh one — which is why it takes a factory rather than a digest function,
/// and why a third-party hash works here the day it implements
/// `mooncrypt/spec`'s `Hash`.
struct Hmac {
  make : () -> &@spec.Hash
  inner : &@spec.Hash
  ipad : Bytes
  opad : Bytes
}

///|
/// Key an HMAC with `hash` as its digest.
///
/// A key longer than the hash's block is replaced by its digest and a shorter
/// one is zero-padded, both per RFC 2104 §2 — so a 100-byte key and the 20-byte
/// digest of that key authenticate identically, which is a property of the
/// standard and not a defect here.
pub fn Hmac::new(key : BytesView, hash : () -> &@spec.Hash) -> Hmac {
  let probe = hash()
  let block = probe.block()
  let short = if key.length() > block {
    @spec.digest(probe, key)
  } else {
    key.to_owned()
  }
  let ipad : Array[Byte] = []
  let opad : Array[Byte] = []
  for i in 0..<block {
    let k = if i < short.length() { short[i].to_int() } else { 0 }
    ipad.push((k ^ 0x36).to_byte())
    opad.push((k ^ 0x5C).to_byte())
  }
  let mac = {
    make: hash,
    inner: hash(),
    ipad: Bytes::from_array(ipad),
    opad: Bytes::from_array(opad),
  }
  mac.reset()
  mac
}

///|
/// Authenticate one whole message.
pub fn mac(key : BytesView, msg : BytesView, hash : () -> &@spec.Hash) -> Bytes {
  let m = Hmac::new(key, hash)
  m.write(msg)
  m.finish()
}

///|
/// Start over on the same key, so one keyed state can authenticate a stream of
/// messages without re-deriving the pads.
pub fn Hmac::reset(self : Hmac) -> Unit {
  self.inner.reset()
  self.inner.write(self.ipad[:])
}

///|
pub extend Hmac with @spec.Mac::{finish, size, write}

///|
pub impl @spec.Mac for Hmac with fn write(self : Hmac, msg : BytesView) -> Unit {
  self.inner.write(msg)
}

///|
pub impl @spec.Mac for Hmac with fn finish(self : Hmac) -> Bytes {
  let outer = (self.make)()
  outer.write(self.opad[:])
  outer.write(self.inner.finish()[:])
  outer.finish()
}

///|
pub impl @spec.Mac for Hmac with fn size(self : Hmac) -> Int {
  self.inner.size()
}
