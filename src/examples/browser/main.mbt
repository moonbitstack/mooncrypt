// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Hand the entry points to the page.
///
/// The page calls `globalThis.mooncrypt.digest("sha256", hex)` and friends. All
/// of them are this library, compiled with the JavaScript backend.
extern "js" fn expose(
  digest : (String, String) -> String,
  seal : (String, String, String, String) -> String,
  open : (String, String, String, String) -> String,
  totp : (String, Int32) -> String,
) -> Unit = "function(digest, seal, open, totp){ globalThis.mooncrypt = { digest: digest, seal: seal, open: open, totp: totp }; }"

///|
/// The marker a refusal comes back as. The page tests for it with `===`.
let refused : String = "!refused"

///|
/// Bytes from a hexadecimal string.
fn unhex(text : String) -> Bytes {
  @base16.decode_lossy(text)
}

///|
/// A digest, by the name the page uses for it.
fn digest(kind : String, input : String) -> String {
  let data = unhex(input)
  let out = match kind {
    "sha256" => @sha2.hash(data[:], kind=@sha2.Sha256)
    "sha512" => @sha2.hash(data[:], kind=@sha2.Sha512)
    "sha3-256" => @sha3.hash(data[:], kind=@sha3.Sha3_256)
    "blake3" => @blake3.hash(data[:])
    "sm3" => @sm3.hash(data[:])
    _ => Bytes::new(0)
  }
  @base16.encode(out)
}

///|
/// Seal a plaintext, returning the ciphertext with its tag.
fn seal(kind : String, key : String, nonce : String, plain : String) -> String {
  let key = unhex(key)
  let nonce = unhex(nonce)
  let plain = unhex(plain)
  let out = match kind {
    "aes-gcm" => {
      let block = @aes.Cipher::new(key[:]) catch { _ => return "" }
      let cipher = @gcm.Gcm::new(block) catch { _ => return "" }
      cipher.seal(nonce=nonce[:], plain=plain[:])
    }
    "sm4-gcm" => {
      let boxed = @sm4gcm.seal(key[:], nonce=nonce[:], plain=plain[:]) catch {
        _ => return ""
      }
      boxed
    }
    "chachapoly" => {
      let cipher = @chachapoly.ChaChaPoly::new(key[:]) catch { _ => return "" }
      cipher.seal(nonce=nonce[:], plain=plain[:])
    }
    _ => return ""
  }
  @base16.encode(out)
}

///|
/// Open a sealed message, or `!refused` when the tag does not match.
fn open(kind : String, key : String, nonce : String, blob : String) -> String {
  let key = unhex(key)
  let nonce = unhex(nonce)
  let blob = unhex(blob)
  let out = match kind {
    "aes-gcm" => {
      let block = @aes.Cipher::new(key[:]) catch { _ => return refused }
      let cipher = @gcm.Gcm::new(block) catch { _ => return refused }
      cipher.open(nonce=nonce[:], cipher=blob[:]) catch {
        _ => return refused
      }
    }
    "sm4-gcm" =>
      @sm4gcm.open(key[:], nonce=nonce[:], cipher=blob[:]) catch {
        _ => return refused
      }
    "chachapoly" => {
      let cipher = @chachapoly.ChaChaPoly::new(key[:]) catch {
        _ => return refused
      }
      cipher.open(nonce=nonce[:], cipher=blob[:]) catch {
        _ => return refused
      }
    }
    _ => return refused
  }
  @base16.encode(out)
}

///|
/// The code a key answers to at a given second.
fn totp(key : String, second : Int32) -> String {
  let key = unhex(key)
  let at : UInt64 = second.to_int64().reinterpret_as_uint64()
  @otp.totp(key[:], at)
}

///|
fn main {
  expose(digest, seal, open, totp)
}
