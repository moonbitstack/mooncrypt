// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// GMAC: the authentication half of GCM, with the message authenticated instead
/// of encrypted.
///
/// The nonce makes it a MAC rather than a hash. It must never repeat under one
/// key: two tags under the same nonce give away the hash subkey, and from there
/// every tag under that key is forgeable. Twelve bytes is the length the
/// standard prefers, because it skips a derivation step and so is both faster
/// and easier to reason about.
pub struct Gmac {
  ///
  /// The GCM machinery, which does the GHASH.
  mode : @gcm.Gcm
  ///
  /// The nonce, kept so [`finish`](#finish) can be called more than once.
  nonce : Bytes
  ///
  /// The message accumulated so far. GHASH is a hash: it cannot be read until
  /// the length block closes it, so the bytes have to be kept rather than folded
  /// as they arrive.
  aad : Array[Byte]
}

///|
/// Start a GMAC context.
///
/// `tag` is the tag length in bytes; the same values GCM allows are allowed
/// here, and the default is the full sixteen.
pub fn Gmac::new(
  cipher : &@spec.Block,
  nonce : BytesView,
  tag~ : Int32 = 16,
) -> Gmac raise @spec.Broken {
  guard nonce.length() > 0 else { raise @spec.Broken::Size(want=12, got=0) }
  let mode = @gcm.Gcm::new(cipher, tag~)
  let kept : FixedArray[Byte] = FixedArray::make(nonce.length(), b'\x00')
  for i in 0..<nonce.length() {
    kept[i] = nonce[i]
  }
  { mode, nonce: Bytes::from_array(kept), aad: [], }
}

///|
/// Feed more of the message.
pub fn Gmac::write(self : Gmac, data : BytesView) -> Unit {
  for i in 0..<data.length() {
    self.aad.push(data[i])
  }
}

///|
/// The tag for everything written so far. Reading it does not consume the
/// message, so a transcript can be tagged as it goes and continue afterwards.
pub fn Gmac::finish(self : Gmac) -> Bytes {
  let bytes = Bytes::from_array(self.aad)
  self.mode.seal(nonce=self.nonce[:], plain=b""[:], aad=bytes[:])
}

///|
/// Throw away the message, keeping the nonce, so the context can tag another
/// transcript. Only useful when the same nonce is meant to be reused, which for
/// a MAC means the two transcripts must be compared, never both trusted.
pub fn Gmac::reset(self : Gmac) -> Unit {
  while self.aad.length() > 0 {
    let _ = self.aad.pop()
  }
}

///|
/// The tag length in bytes.
pub fn Gmac::size(self : Gmac) -> Int32 {
  self.mode.size()
}

///|
/// The tag of a message, in one call.
pub fn mac(
  cipher : &@spec.Block,
  nonce : BytesView,
  message : BytesView,
  tag~ : Int32 = 16,
) -> Bytes raise @spec.Broken {
  let state = Gmac::new(cipher, nonce, tag~)
  state.write(message)
  state.finish()
}

///|
/// Compare a tag with what this context would produce, in constant time.
pub fn Gmac::verify(self : Gmac, tag : BytesView) -> Bool {
  let expected = self.finish()
  @spec.eq(expected[:], tag)
}

///|
pub impl @spec.Mac for Gmac with fn write(self, data) {
  self.write(data)
}

///|
pub impl @spec.Mac for Gmac with fn finish(self) {
  self.finish()
}

///|
pub impl @spec.Mac for Gmac with fn size(self) {
  self.size()
}
