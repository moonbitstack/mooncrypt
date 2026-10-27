// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The tag length in bytes.
pub let tag : Int32 = 16

///|
/// ChaCha20-Poly1305 under one 32-byte key. Nonces are 12 bytes and must never
/// repeat under the same key.
pub struct ChaChaPoly {
  priv cipher : @chacha20.Cipher
}

///|
pub fn ChaChaPoly::new(key : BytesView) -> ChaChaPoly raise @spec.Broken {
  { cipher: @chacha20.Cipher::new(key), }
}

///|
fn le64(n : Int32) -> Bytes {
  let v = n.to_int64()
  Bytes::makei(8, i => (v >> (8 * i)).to_byte())
}

///|
/// The tag over `aad` and `body` (RFC 8439 §2.8): each padded to 16 bytes, then
/// both lengths, under the one-time key from block 0.
fn ChaChaPoly::authenticate(
  self : ChaChaPoly,
  nonce : BytesView,
  aad : BytesView,
  body : BytesView,
) -> Bytes raise @spec.Broken {
  let otk = self.cipher.block(0, nonce)
  let p = @poly1305.Poly1305::new(otk[0:32])
  let zeros = Bytes::make(16, b'\x00')
  p.write(aad)
  p.write(zeros[0:(16 - aad.length() % 16) % 16])
  p.write(body)
  p.write(zeros[0:(16 - body.length() % 16) % 16])
  p.write(le64(aad.length())[:])
  p.write(le64(body.length())[:])
  p.finish()
}

///|
/// The ciphertext of `plain` followed by its tag. A nonce that is not 12 bytes
/// is a programming error and aborts: `seal` has no error to return.
pub fn ChaChaPoly::seal(
  self : ChaChaPoly,
  nonce~ : BytesView,
  plain~ : BytesView,
  aad~ : BytesView = b"",
) -> Bytes {
  let body = self.cipher.xor(nonce~, plain, counter=1) catch {
    _ => abort("a ChaCha20-Poly1305 nonce is 12 bytes")
  }
  let mac = self.authenticate(nonce, aad, body[:]) catch {
    _ => abort("a ChaCha20-Poly1305 nonce is 12 bytes")
  }
  body + mac
}

///|
/// The plaintext of `cipher` (ciphertext then tag), checked before anything is
/// decrypted. Every failure is the same `Tag`, so a caller learns nothing about
/// which part was wrong.
pub fn ChaChaPoly::open(
  self : ChaChaPoly,
  nonce~ : BytesView,
  cipher~ : BytesView,
  aad~ : BytesView = b"",
) -> Bytes raise @spec.Broken {
  guard cipher.length() >= tag && nonce.length() == @chacha20.nonce_size else {
    raise Tag
  }
  let body = cipher[0:cipher.length() - tag]
  let want = self.authenticate(nonce, aad, body)
  guard @spec.eq(want[:], cipher[cipher.length() - tag:]) else { raise Tag }
  self.cipher.xor(nonce~, body, counter=1)
}

///|
pub fn ChaChaPoly::size(_ : ChaChaPoly) -> Int32 {
  tag
}

///|
pub impl @spec.Aead for ChaChaPoly with fn seal(self, nonce~, plain~, aad~) {
  ChaChaPoly::seal(self, nonce~, plain~, aad~)
}

///|
pub impl @spec.Aead for ChaChaPoly with fn open(self, nonce~, cipher~, aad~) {
  ChaChaPoly::open(self, nonce~, cipher~, aad~)
}
