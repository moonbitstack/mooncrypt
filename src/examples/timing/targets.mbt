// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The five operations the constant-time claim rests on, each built once and
// handed back as a function the timing harness can call with a secret of its
// own.
//
// A leak here is not a wrong answer: every one of these computes the right
// thing. It is the running time following the secret, which over enough
// signatures hands the secret over.

///|
/// AES-128 block encryption with a fixed key. The core is bit-sliced and reads
/// its state whole, so a leak here would mean the state is written unevenly
/// rather than looked up.
pub fn aes_target() -> (BytesView) -> Bytes {
  let key = Bytes::make(16, b'\x2b')
  let cipher = @aes.Cipher::new(key) catch {
    _ => abort("a sixteen-byte key was refused")
  }
  fn(input) { cipher.encrypt(cut(input, 16)) }
}

///|
/// A P-256 multiplication of the generator: what a signature spends its time
/// on, and the fixed-base path every curve shares.
pub fn p256_target() -> (BytesView) -> Bytes {
  fn(input) {
    let scalar = BigInt::from_octets(cut(input, 32)[:])
    @ec.encode(P256, @ec.mul_g(P256, scalar))
  }
}

///|
/// A secp256k1 multiplication of a base point that is not the generator: the
/// route through the endomorphism split, where the scalar is halved.
pub fn secp256k1_target() -> (BytesView) -> Bytes {
  let base = @ec.generator(Secp256k1)
  fn(input) {
    let scalar = BigInt::from_octets(cut(input, 32)[:])
    @ec.encode(Secp256k1, @ec.mul(Secp256k1, scalar, base))
  }
}

///|
/// The Curve25519 diffie-hellman against a fixed peer key: a Montgomery ladder
/// over a clamped scalar.
pub fn curve25519_target() -> (BytesView) -> Bytes {
  let peer = Bytes::make(32, b'\x09')
  fn(input) {
    @x25519.shared(cut(input, 32), peer) catch {
      _ => abort("a clamped scalar and a low-order point were refused")
    }
  }
}

///|
/// The raw RSA private-key operation on a fixed-size input: the modular
/// exponentiation a decryption or a signature spends its time on.
pub fn rsa_target() -> (BytesView) -> Bytes {
  let key = rsa_key()
  fn(input) {
    key.rsadp(cut(input, key.size())) catch {
      _ => abort("an input under the modulus was refused")
    }
  }
}

///|
/// The first `n` bytes of a view, zero-padded, so an operation that wants a fixed
/// width always gets one.
fn cut(view : BytesView, n : Int32) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut i = 0
  while i < n && i < view.length() {
    out[i] = view[i]
    i = i + 1
  }
  Bytes::from_array(out)
}

///|
/// A 2048-bit RSA key, the published test key the RSA vectors use: generating
/// one here would put a minute of prime search in front of every run.
fn rsa_key() -> @rsa.PrivateKey {
  let n = @base16.decode_lossy(
    "be16b0ca8fd918ad254af03af8705941c22283332304ff330de3188871d41a1c0fb61e64198ccf2df4020d8651db24cc8099763b2b83a8b4d078cb6127178e18a2ea04588be5a9d5acf4cd7fb130717ae01b6e08ea4478c1958493eaf546e4258b3db41bb30a9d405c2a2317ec11dba4d701aa7ec4f04a36597f86d01a18b1d956bf90739d911b2a4b5846d206241744b9360f436eefbb8f168b127a98456a5d47382627ee24626a34492ddea6c59a7d2ef33bfc1a616b98a9f9b6df931b399624eb8d0033b4cc0a6d34570dbc20ce5ac3a2e401c085472bd685decef2ddf408a65ce6ea6903356b2f39906f995423c17ff056e681b7c1ae67407d54cfdcd9c7",
  )
  let e = @base16.decode_lossy("010001")
  let d = @base16.decode_lossy(
    "485389e108eaa9a0f7d793a05c7722ff0a46e774c5965923abdd04b0a5def630472a1c562a0291b2026de5877e0dcbeaa3e3c040b345dd232f4f46d32874a5f469c870eee00bfa9afabc0a94d36e833f25964a3fca23536f14dce50b395847e6a11c513358e46900dc108c59c5d0e5a9cac52f821c9cf11fccdde105bd683802b99876aa12be364ee6515382b39067c08c7ac515397442197718e01269725d5ee6cdd1122e2615b7355a3472edb41f6fa733e9bd2b0bf33b5e3b3ea67db34cdeecb9f1524ea3207c5f441dfa01e4c6da5ffbf404743e2c7b6f8c7dda6e3500fa9e2df293ee920147ef44cc8cba9409878e246602787915a15cacefd31bddce81",
  )
  @rsa.PrivateKey::new(n[:], e[:], d[:]) catch {
    _ => abort("the fixed RSA key did not parse")
  }
}
