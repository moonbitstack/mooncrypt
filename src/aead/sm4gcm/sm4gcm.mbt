// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The tag length in bytes.
pub let tag : Int32 = 16

///|
/// The key length in bytes.
pub let key_size : Int32 = 16

///|
/// A GCM instance keyed with SM4, ready to seal and open.
pub fn new(key : BytesView) -> @gcm.Gcm raise @spec.Broken {
  @gcm.Gcm::new(@sm4.Cipher::new(key), tag~)
}

///|
/// Seal one message in one call.
pub fn seal(
  key : BytesView,
  nonce~ : BytesView,
  plain~ : BytesView,
  aad~ : BytesView = b""[:],
) -> Bytes raise @spec.Broken {
  new(key).seal(nonce~, plain~, aad~)
}

///|
/// Open one message in one call, raising [`@spec.Broken`] if it does not
/// authenticate.
pub fn open(
  key : BytesView,
  nonce~ : BytesView,
  cipher~ : BytesView,
  aad~ : BytesView = b""[:],
) -> Bytes raise @spec.Broken {
  new(key).open(nonce~, cipher~, aad~)
}
