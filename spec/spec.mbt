// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A cryptographic hash, as a state you feed and then read.
///
/// Five methods and no more, because everything mooncrypt builds on top of a
/// hash needs exactly these: HMAC needs [`block`] to size its pads, HKDF and
/// PBKDF2 need [`size`] to count output blocks, and every one-shot needs
/// [`write`] then [`finish`]. A third-party digest becomes usable throughout
/// the library the moment it implements this.
///
/// [`finish`] does not consume the state, so a caller may keep writing and read
/// again; [`reset`] returns it to the initial vector, which is how HMAC reuses
/// one allocation for both passes.
pub(open) trait Hash {
  /// Absorb more message.
  fn write(Self, BytesView) -> Unit
  /// The digest of everything written so far.
  fn finish(Self) -> Bytes
  /// Forget everything written, as if newly constructed.
  fn reset(Self) -> Unit
  /// The digest length in bytes.
  fn size(Self) -> Int
  /// The compression block length in bytes — what HMAC pads its key to.
  fn block(Self) -> Int
}

///|
/// A message authentication code: a hash that a key has been mixed into.
///
/// It is deliberately not a [`Hash`] — a MAC has no block size worth exposing
/// and must never be used where an unkeyed digest is expected.
pub(open) trait Mac {
  fn write(Self, BytesView) -> Unit
  fn finish(Self) -> Bytes
  fn size(Self) -> Int
}

///|
/// A block cipher: a keyed permutation of a fixed-size block.
///
/// It is the thing a mode of operation is built on, which is why it is a
/// contract rather than a concrete type — GCM is defined for any 128-bit block
/// cipher, so it takes one of these and SM4-GCM costs nothing more than an SM4
/// that implements it.
///
/// Both directions are here although a counter mode needs only [`encrypt`]: a
/// permutation that cannot be inverted is not a block cipher, and a mode such as
/// CBC needs the inverse.
pub(open) trait Block {
  /// The block length in bytes.
  fn block(Self) -> Int
  /// Encrypt one block. The input must be exactly [`block`] bytes.
  fn encrypt(Self, BytesView) -> Bytes
  /// Decrypt one block. The input must be exactly [`block`] bytes.
  fn decrypt(Self, BytesView) -> Bytes
}

///|
/// Authenticated encryption with associated data.
///
/// [`open`] raises rather than returning an option, because "the tag did not
/// match" is the one outcome a caller must not silently treat as empty
/// plaintext. `cipher~` is the ciphertext with its tag appended, the layout
/// every AEAD construction in use writes.
pub(open) trait Aead {
  fn seal(Self, nonce~ : BytesView, plain~ : BytesView, aad~ : BytesView) -> Bytes
  fn open(Self, nonce~ : BytesView, cipher~ : BytesView, aad~ : BytesView) -> Bytes raise Broken
}

///|
/// Something that holds a private key and can sign with it.
pub(open) trait Signer {
  fn sign(Self, BytesView) -> Bytes
}

///|
/// Something that holds a public key and can check a signature.
///
/// It answers `Bool` and never raises: a bad signature is an expected answer,
/// not an exceptional one, and raising here invites a caller to swallow the
/// error and carry on.
pub(open) trait Verifier {
  fn verify(Self, BytesView, BytesView) -> Bool
}

///|
/// A ciphertext that did not authenticate, or a key that cannot be used.
pub(all) suberror Broken {
  /// The authentication tag does not match: the ciphertext, the associated
  /// data, the key or the nonce is not what sealed it.
  Tag
  /// A nonce, key or ciphertext of the wrong length, with what was expected.
  Size(want~ : Int, got~ : Int)
  /// The right number of bytes, but a value the algorithm must refuse: a
  /// low-order Curve25519 point, whose shared secret is all zeroes and so was
  /// chosen by the peer rather than agreed with it.
  Weak
} derive(Eq, Debug)

///|
pub extend Broken with Eq::{equal, not_equal}

///|
pub extend Broken with Debug::{to_repr}

///|
/// Compare two byte strings in time that does not depend on their contents.
///
/// The obvious loop returns at the first differing byte, and the time it took
/// tells an attacker how long a prefix they guessed right — enough to recover a
/// tag or a token byte by byte across many requests. This one reads both
/// strings to the end and folds the differences together.
///
/// Length is not treated as a secret: unequal lengths answer immediately, which
/// is what every library does, because the length is visible on the wire anyway.
///
/// This is the only comparison mooncrypt offers. Use it for tags, digests and
/// anything else derived from a key.
pub fn eq(a : BytesView, b : BytesView) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i in 0..<a.length() {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

///|
/// Overwrite a buffer with zeroes.
///
/// Key material lives longer than the code that used it: a scratch array stays
/// in whatever memory the runtime hands out next until something else writes
/// over it. Erasing at the end of the operation shortens that window. Under a
/// garbage collector it is a best-effort measure, not a guarantee — a copy the
/// collector moved is out of reach — which is why keys are held in
/// [`FixedArray`] here rather than in [`Bytes`], where they could not be erased
/// at all.
pub fn wipe(buf : FixedArray[Byte]) -> Unit {
  for i in 0..<buf.length() {
    buf[i] = 0
  }
}

///|
/// One whole message through a hash, in one call.
///
/// It resets first, so passing a state that has already been used is not a
/// silent corruption of the result.
pub fn digest(h : &Hash, msg : BytesView) -> Bytes {
  h.reset()
  h.write(msg)
  h.finish()
}
