// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RSAES-OAEP (RFC 8017 §7.1) against Python's `cryptography` 45.0.2.
//
// The two ciphertexts below were produced by that library, not by this one, so
// decrypting them checks the padding, the masking and the primitive against an
// implementation that shares no code with ours. Encryption is checked the other
// way round — the script that made these fixtures decrypts what we produce —
// because OAEP's seed makes a ciphertext unreproducible by construction.

///|
/// A 1024-bit key from `cryptography`'s own generator.
let oaep_n : String = "d6df23cd32bdb4dad27629dfc654193146f0f2ce3bc33dc6ff981249579aae6b7ab5c18a77846c99d73be2fb6f32061d042da8029a76448f83c07738968535a7d46bde7a939d745108cbef32d19123a483f823cb48db521112b0f66c7c9a7546e9dcce14107140583740a18eb06b8bdf14cf47c7c80d47fc4419982daacfda61"

///|
let oaep_e : String = "010001"

///|
let oaep_d : String = "2737387885ef3ba7c84b8a9eedba81928dc901f783cec162a55962d501e918364382129dabec7e49a18fab808a2dce11d3a665887c1a63aef1b3d9ce79223cc55bf52e53b64be1ea14e42abdc4c1accd7706f87545a8c9d67b330cdbc5420f07bf43a3641d22c9a5236a02c63cddd9ee750c7345f2e0fd80ee2f0125eb00aa31"

///|
let oaep_msg : Bytes = b"heke1228"

///|
fn oaep_key() -> @rsa.PrivateKey raise {
  @rsa.PrivateKey::new(
    @base16.decode(oaep_n)[:],
    @base16.decode(oaep_e)[:],
    @base16.decode(oaep_d)[:],
  )
}

///|
test "OAEP-SHA1 decrypts what another implementation encrypted" {
  let key = oaep_key()
  let cipher = @base16.decode(
    "55bf7a67a9776a9846721053111bc2e69f2a7b05cb201738ba2983ced7aa19ca60521f53b9e55f940e3a5e9cc260aa28960f8140a1c5feeda7baad6ec02a8693349087be7da44ce8513ee759426826559f92fe447479ec2d9900241b1f31a5d74f9ed46be0a98ecdd6688e2a5f1998248c504ec8e9196bbbb8f741a175c6f905",
  )
  assert_eq(key.decrypt(cipher[:]), oaep_msg)
}

///|
test "OAEP-SHA256 decrypts what another implementation encrypted" {
  let key = oaep_key()
  let cipher = @base16.decode(
    "c2dc37b18daf27e74d321c93c11462b74ef2d1ad65deb1f5a0a200cbec75e773d9bb9f9b889523e09af60798d84ad878930ac8d42fa23afcedd1e07e732516c268f84f32d99d04e08ff229d00fcd54ead7d60b77a1290fe9d8ba4e0c2c34b7615e2df1f968a617c9d0fd8f9a3c63cb75e0c955e87fdb92d8c2d3b8c57c2018c3",
  )
  assert_eq(key.decrypt(cipher[:], digest=Sha256), oaep_msg)
}

///|
/// The seed is the only thing that differs between two encryptions of one
/// message, so two seeds must give two ciphertexts and both must come back.
test "OAEP round-trips, and the seed is what makes it probabilistic" {
  let key = oaep_key()
  let pk = key.public()
  let a = pk.encrypt(oaep_msg[:], seed=b"0123456789abcdef0123"[:])
  let b = pk.encrypt(oaep_msg[:], seed=b"fedcba9876543210fedc"[:])
  assert_not_eq(a, b)
  assert_eq(key.decrypt(a[:]), oaep_msg)
  assert_eq(key.decrypt(b[:]), oaep_msg)
}

///|
/// `mgf` defaults to `digest` and can differ from it — the knob Python and Java
/// expose and Go does not.
test "OAEP's mgf follows digest unless it is given" {
  let key = oaep_key()
  let pk = key.public()
  let seed = b"0123456789abcdef0123456789abcdef"[:]
  let followed = pk.encrypt(oaep_msg[:], seed~, digest=Sha256)
  let named = pk.encrypt(oaep_msg[:], seed~, digest=Sha256, mgf=Sha256)
  assert_eq(followed, named)
  // The seed is hLen octets of `digest`, not of `mgf` — MGF1's hash masks, it
  // does not set the seed's width.
  let crossed = pk.encrypt(oaep_msg[:], seed~, digest=Sha256, mgf=Sha1)
  assert_not_eq(followed, crossed)
  assert_eq(key.decrypt(crossed[:], digest=Sha256, mgf=Sha1), oaep_msg)
}

///|
/// A label is part of the block, so decrypting under a different one fails.
test "OAEP's label has to match" {
  let key = oaep_key()
  let cipher = key
    .public()
    .encrypt(oaep_msg[:], seed=b"0123456789abcdef0123"[:], label=b"ctx"[:])
  assert_eq(key.decrypt(cipher[:], label=b"ctx"[:]), oaep_msg)
  let mut refused = false
  try {
    let _ = key.decrypt(cipher[:], label=b"other"[:])
  } catch {
    Tag => refused = true
    _ => refused = false
  }
  assert_eq(refused, true)
}

///|
/// The message has to fit in `k - 2 hLen - 2` octets, and the seed has to be
/// exactly `hLen`.
test "OAEP refuses a message that does not fit, and a seed of the wrong size" {
  let pk = oaep_key().public()
  let big = Bytes::from_array(Array::make(100, b'x'))
  let mut sized = false
  try {
    let _ = pk.encrypt(big[:], seed=b"0123456789abcdef0123"[:])
  } catch {
    Size(..) => sized = true
    _ => sized = false
  }
  assert_eq(sized, true)
  let mut short = false
  try {
    let _ = pk.encrypt(oaep_msg[:], seed=b"tooshort"[:])
  } catch {
    Size(..) => short = true
    _ => short = false
  }
  assert_eq(short, true)
}

///|
/// A flipped octet must not decrypt, and every way of being wrong reports the
/// same thing.
test "OAEP refuses a tampered block" {
  let key = oaep_key()
  let cipher = key
    .public()
    .encrypt(oaep_msg[:], seed=b"0123456789abcdef0123"[:])
  let broken = cipher.to_array()
  broken[64] = (broken[64].to_int() ^ 1).to_byte()
  let mut refused = false
  try {
    let _ = key.decrypt(Bytes::from_array(broken)[:])
  } catch {
    Tag => refused = true
    _ => refused = false
  }
  assert_eq(refused, true)
}
