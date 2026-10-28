// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Every corner of mooncrypt in one run, in nine sections: digests, MACs,
/// key derivations, block ciphers and their modes, AEAD, signatures, key
/// agreement, one-time passwords and key files.
///
///     moon run src/examples/tour
///
/// The point is not the output — most of these are vectors already in the test
/// suite — but that every one is reached the same way: through `@spec`'s traits
/// where the shape fits, and through a plain function where it does not.
#coverage.skip
fn main raise {
  let sha256 = fn() -> &@spec.Hash { @sha2.Hasher::new() }
  let msg = b"the quick brown fox"

  // ------------------------------------------------------------- digests
  //
  // A digest, one shot and streamed. The streamed one is how a large body is
  // hashed without holding it in memory.
  println("--- digests")
  println("sha256      -> \{@base16.encode(@sha2.hash(msg[:]))[0:32]}…")
  let running = @sha2.Hasher::new(kind=Sha512)
  running.write(b"the quick "[:])
  running.write(b"brown fox"[:])
  println("sha512      -> \{@base16.encode(running.finish()[:])[0:32]}…")

  // The four other families, same trait, so HMAC below would take any of them.
  println("sha3-256    -> \{@base16.encode(@sha3.hash(msg[:]))[0:32]}…")
  println(
    "shake256    -> \{@base16.encode(@sha3.shake256(msg[:], 32)[:])[0:32]}…",
  )
  println("blake3      -> \{@base16.encode(@blake3.hash(msg[:]))[0:32]}…")
  println("blake2b     -> \{@base16.encode(@blake2.hash(msg[:])[:])[0:32]}…")
  println("sm3         -> \{@base16.encode(@sm3.hash(msg[:]))[0:32]}…")
  println("ripemd160   -> \{@base16.encode(@ripemd.hash(msg[:]))[0:32]}…")

  // A non-cryptographic digest is still a `Hash`, which is what makes it usable
  // as a checksum or as a key in a table without a second interface.
  println("crc32       -> \{@crc32.crc32(msg[:])}")
  println("xxhash64    -> \{@xxhash.xxhash(msg[:])}")

  // ---------------------------------------------------------------- MACs
  //
  // A MAC. The hash goes in as a factory, so the same HMAC serves every digest.
  println("--- macs")
  let tag = @hmac.mac(b"shared secret"[:], msg[:], sha256)
  println("hmac-sha256 -> \{@base16.encode(tag[:])[0:32]}…")
  println("constant-time compare -> \{@spec.eq(tag[:], tag[:])}")

  // A MAC built on a block cipher: CMAC over AES, GMAC over the same, and KMAC
  // over SHA-3. Three keyed hashes from three different primitives.
  let aes_key = Bytes::make(16, b'\x2b')
  let aes = @aes.Cipher::new(aes_key[:])
  println("aes-cmac    -> \{@base16.encode(@cmac.mac(aes, msg[:])[:])}")
  let nonce16 = Bytes::make(12, b'\x00')
  println(
    "aes-gmac    -> \{@base16.encode(@gmac.mac(aes, nonce16[:], msg[:])[:])}",
  )
  println(
    "kmac256     -> \{@base16.encode(@kmac.mac(aes_key[:], msg[:], kind=Kmac256, len=32)[:])[0:32]}…",
  )
  let siphash_key = Bytes::make(16, b'\x07')
  println(
    "siphash-2-4 -> \{@base16.encode(@siphash.siphash(siphash_key[:], msg[:])[:])}",
  )

  // -------------------------------------------------------- key derivation
  println("--- key derivation")
  let key = @hkdf.key(
    b"input keying material"[:],
    sha256,
    salt=b"salt"[:],
    info=b"client write key"[:],
    len=32,
  )
  println("hkdf        -> \{@base16.encode(key[:])[0:32]}…")
  let stretched = @pbkdf2.key(
    b"correct horse"[:],
    b"battery staple"[:],
    sha256,
    rounds=4096,
    len=32,
  )
  println("pbkdf2      -> \{@base16.encode(stretched[:])[0:32]}…")

  // The three password hashes, each with the smallest parameters that are still
  // that algorithm — a tour should not take a minute to print a line.
  let salt = b"battery staple"[:]
  let scrypt = @scrypt.key(
    b"correct horse"[:],
    salt,
    params=@scrypt.Params::new(n=1024, r=8, p=1),
    len=32,
  )
  println("scrypt      -> \{@base16.encode(scrypt[:])[0:32]}…")
  let argon = @argon2.key(
    b"correct horse"[:],
    salt,
    params=@argon2.minimum,
    len=32,
  )
  println("argon2id    -> \{@base16.encode(argon[:])[0:32]}…")
  let salt16 = Bytes::make(16, b'\x09')
  let bc = @bcrypt.encode(b"correct horse"[:], salt16[:], cost=4)
  println("bcrypt      -> \{bc}")
  println("bcrypt ok   -> \{@bcrypt.verify(b"correct horse"[:], bc)}")

  // A Concat KDF, which is what a NIST key-agreement scheme derives its keys
  // with — the same input material HKDF above started from.
  let concat = @concat.key(
    b"shared secret z"[:],
    sha256,
    other_info=b"info"[:],
    len=32,
  )
  println("concat kdf  -> \{@base16.encode(concat[:])[0:32]}…")

  // -------------------------------------------------- ciphers and modes
  println("--- ciphers")
  let block = Bytes::make(16, b'\x00')
  let sm4 = @sm4.Cipher::new(Bytes::make(16, b'\x01')[:])
  println("sm4         -> \{@base16.encode(sm4.encrypt(block[:])[:])}")
  let camellia = @camellia.Cipher::new(Bytes::make(32, b'\x01')[:])
  println("camellia    -> \{@base16.encode(camellia.encrypt(block[:])[:])}")
  let des = @des.Cipher::new(Bytes::make(8, b'\x01')[:])
  println("des         -> \{@base16.encode(des.encrypt(block[0:8])[:])}")

  // A mode of operation turns a block cipher into something that takes a
  // message. CBC pads, so the ciphertext is longer than the plaintext.
  let iv = Bytes::make(16, b'\x00')
  let cbc = @mode.Cbc::new(aes, iv[:])
  let padded = cbc.encrypt(@mode.pad(16, msg[:])[:])
  println("aes-cbc     -> \{padded.length()} bytes from 19")
  // The context is stateful — it carries the chain from one call to the next, so
  // that a long message can be written in pieces. Starting over means `reset`.
  cbc.reset()
  println("aes-cbc ok  -> \{@mode.unpad(16, cbc.decrypt(padded[:])[:]) == msg}")

  // The stream ciphers, legacy ones included: same shape, no padding.
  let stream_key = Bytes::make(32, b'\x03')
  let nonce8 = Bytes::make(8, b'\x00')
  println(
    "salsa20     -> \{@base16.encode(@salsa20.salsa20(stream_key[:], nonce8[:], msg[:])[:])[0:32]}…",
  )
  let x = @xchacha20.Cipher::new(stream_key[:])
  let nonce24 = Bytes::make(24, b'\x00')
  println(
    "xchacha20   -> \{@base16.encode(x.xor(nonce=nonce24[:], msg[:])[:])[0:32]}…",
  )
  println(
    "rc4         -> \{@base16.encode(@rc4.rc4(b"Key"[:], msg[:])[:])[0:32]}…",
  )

  // ---------------------------------------------------------------- AEAD
  //
  // Four constructions. Each seals with a nonce and associated data, and each
  // refuses to open a ciphertext that has been touched.
  println("--- aead")
  let boxed = @chachapoly.ChaChaPoly::new(stream_key[:])
  let nonce12 = Bytes::make(12, b'\x00')
  let sealed_box = boxed.seal(nonce=nonce12[:], plain=msg[:])
  println("chachapoly  -> \{@base16.encode(sealed_box[:])[0:32]}…")
  println(
    "opened      -> \{boxed.open(nonce=nonce12[:], cipher=sealed_box[:]) == msg}",
  )

  let gcm = @sm4gcm.new(Bytes::make(16, b'\x04')[:])
  let g = gcm.seal(nonce=nonce12[:], plain=msg[:], aad=b"header"[:])
  println("sm4-gcm     -> \{@base16.encode(g[:])[0:32]}…")
  println(
    "sm4-gcm ok  -> \{gcm.open(nonce=nonce12[:], cipher=g[:], aad=b"header"[:]) == msg}",
  )

  let ccm = @ccm.Ccm::new(aes)
  let c = ccm.seal(nonce=nonce12[:], plain=msg[:], aad=b"header"[:])
  println("aes-ccm     -> \{@base16.encode(c[:])[0:32]}…")
  println(
    "aes-ccm ok  -> \{ccm.open(nonce=nonce12[:], cipher=c[:], aad=b"header"[:]) == msg}",
  )

  let siv_cmac = @aes.Cipher::new(Bytes::make(16, b'\x05')[:])
  let siv = @siv.Siv::new(siv_cmac, aes)
  let s = siv.seal(nonce=b"header"[:], plain=msg[:])
  println("aes-siv     -> \{@base16.encode(s[:])[0:32]}…")
  println("aes-siv ok  -> \{siv.open(nonce=b"header"[:], cipher=s[:]) == msg}")

  // ---------------------------------------------------------- signatures
  //
  // Five schemes behind the same two traits, so a verifier written against
  // `@spec.Verifier` takes any of them.
  println("--- signatures")
  let seed = @base16.decode_lossy(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let ed = @ed25519.PrivateKey::new(seed[:])
  let ed_sig = ed.sign(msg[:])
  println("ed25519     -> \{@base16.encode(ed.public().bytes()[:])[0:32]}…")
  println("ed25519 ok  -> \{ed.public().verify(msg[:], ed_sig[:])}")

  // Ed448, with the same API and a 57-byte seed.
  let ed448 = @ed448.PrivateKey::new(Bytes::make(57, b'\x11')[:])
  let ed448_sig = ed448.sign(msg[:])
  println("ed448 ok    -> \{ed448.public().verify(msg[:], ed448_sig[:])}")

  // ECDSA over P-256, with the RFC 6979 nonce — also deterministic.
  let scalar = @base16.decode_lossy(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let ec = @ecdsa.PrivateKey::new(scalar[:])
  let ec_sig = ec.sign(msg[:])
  println("ecdsa p-256 -> \{@base16.encode(ec_sig[:])[0:32]}…")
  println("ecdsa ok    -> \{ec.public().verify(msg[:], ec_sig[:])}")
  println(
    "ecdsa bent  -> \{ec.public().verify(b"the quick brown fix"[:], ec_sig[:])}",
  )

  // SM2, which is ECDSA's shape over the Chinese curve and with the signer's
  // identity mixed into the hash.
  let sm2 = @sm2.PrivateKey::new(Bytes::make(32, b'\x06')[:])
  let sm2_sig = sm2.sign(msg[:])
  println("sm2 ok      -> \{sm2.public().verify(msg[:], sm2_sig[:])}")

  // BIP 340 Schnorr over secp256k1, x-only keys and all.
  let schnorr = @schnorr.PrivateKey::new(Bytes::make(32, b'\x07')[:])
  let schnorr_sig = schnorr.sign(msg[:])
  println("schnorr ok  -> \{schnorr.public().verify(msg[:], schnorr_sig[:])}")

  // ---------------------------------------------------- key agreement
  println("--- key agreement")
  let alice = Bytes::make(32, b'\x11')
  let bob = Bytes::make(32, b'\x22')
  let secret = @ecdh.shared(alice[:], @ecdh.public(bob[:])[:])
  let agreed = @spec.eq(
    secret[:],
    @ecdh.shared(bob[:], @ecdh.public(alice[:])[:])[:],
  )
  println("ecdh agreed -> \{agreed}")

  // X448, the same idea over a different curve and a 56-byte scalar.
  let a448 = Bytes::make(56, b'\x33')
  let b448 = Bytes::make(56, b'\x44')
  let s448 = @x448.shared(a448[:], @x448.public(b448[:])[:])
  println(
    "x448 agreed -> \{@spec.eq(s448[:], @x448.shared(b448[:], @x448.public(a448[:])[:])[:])}",
  )

  // Finite-field Diffie-Hellman over an RFC 7919 group, which is the only place
  // here where a "public key" is 256 bytes rather than 32.
  let dh_a = Bytes::make(32, b'\x55')
  let dh_b = Bytes::make(32, b'\x66')
  let dh_s = @dh.shared_secret(
    @dh.Ffdhe2048,
    dh_a[:],
    @dh.public_key(@dh.Ffdhe2048, dh_b[:])[:],
  )
  println(
    "ffdhe2048   -> \{@dh.Group::size(Ffdhe2048)} bytes, \{dh_s.length()} shared",
  )

  // ------------------------------------------------- one-time passwords
  println("--- one-time passwords")
  let otp_secret = b"12345678901234567890"
  let codes = @otp.Otp::new(otp_secret[:])
  println("hotp 0      -> \{codes.hotp(0UL)}")
  println("hotp 1      -> \{codes.hotp(1UL)}")
  println("totp t=59   -> \{codes.totp(59UL)}")
  println("totp ok     -> \{codes.confirm(codes.totp(59UL)[:], 59UL)}")

  // ------------------------------------------------------- key files
  //
  // PEM is base64 inside a header, which is all a `.pem` file is; DER is what
  // the base64 decodes to, and that is what a key parser reads.
  println("--- key files")
  let pem = @key.armor("EC PRIVATE KEY", Bytes::make(48, b'\x42'))
  let (label, back) = @key.dearmor(pem[:])
  println("pem         -> \{label}, \{back.length()} bytes back")
  println("pem lines   -> \{pem.split("\n").collect().length()}")
}
