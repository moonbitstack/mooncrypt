// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The CRT half of the private key, against the single half: a key built from its
// three numbers and the same key built from its five must sign, verify and
// decrypt identically, and a factor pair that does not fit the modulus is
// refused when the key is read.

///|
fn crt_raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
/// A 1024-bit key whose factors are known, so the CRT half and the single half
/// can be built from the same numbers and compared. Generated once.
let crt_n : String = "a78fecd0b2cb3711f6b71656d9afb524ab17a8ec02fcf84ed6c2f634cb05004e760848750e2173933eeef4b259a2c08a8a895ef7b0a2c147b5fc4ba696b2dc971a5e6e7c032e2084cced0b079ebbbe96544ec5b7ca499b94dc64eb07eedfe090dfed2a06a6cacaa864a9a70934bff7e31d685b5232738a42c14c7623f5d26c35"

///|
let crt_e : String = "010001"

///|
let crt_d : String = "2171403a86f4b81105c494d8d0a998e5b0a0103eca79e2b51977dfdbb9894dfe5ae05c55c0743cb4eea29283e60fed8db908a1c39da55e1e09dc48dcfec6c3efb124dc70a85cc11624c06d582fd9c91993e9dac5ff337709c410296b23f48c01d50da38531c446086b0d94a3205a60dbd66dff418c624ca91cd3c5a65c23b321"

///|
let crt_p : String = "b673461710cb543defabd048cc8c270d3157189669a17d8f6d12dcf7586c482f67b63571a745b7c06ba4048099386374ba406fdf7f54f36eff1a9c10b18d3e87"

///|
let crt_q : String = "eb1c3688dd749e800e728271d750743d91c15ed88815c111e66fb26761b121424a593becbbb1b39de43c99482856dc7d96ca2d37e9b05708cef032cfbf745263"

///|
fn key3() -> @rsa.PrivateKey raise {
  @rsa.PrivateKey::new(crt_raw(crt_n)[:], crt_raw(crt_e)[:], crt_raw(crt_d)[:])
}

///|
fn key_crt() -> @rsa.PrivateKey raise {
  @rsa.PrivateKey::new_crt(
    crt_raw(crt_n)[:],
    crt_raw(crt_e)[:],
    crt_raw(crt_d)[:],
    crt_raw(crt_p)[:],
    crt_raw(crt_q)[:],
  )
}

///|
/// The two halves of the same key must produce the same signature: PKCS#1 is
/// deterministic, so signing twice — once through each half — gives one value.
test "the CRT half and the single half sign the same way" {
  let a = key3()
  let b = key_crt()
  let msg = b"the two halves of one key"[:]
  let sa = a.sign(msg)
  let sb = b.sign(msg)
  assert_eq(sa, sb)
  assert_true(a.public().verify(msg, sa[:]))
  assert_true(b.public().verify(msg, sb[:]))
  // A signature made by the CRT half verifies under the three-number key's
  // public half, and one made by that key verifies under the CRT half's.
  assert_true(b.public().verify(msg, sa[:]))
  assert_true(a.public().verify(msg, sb[:]))
  assert_eq(a.size(), b.size())
  assert_eq(a.public().modulus(), b.public().modulus())
}

///|
/// The raw private operation agrees across the two halves and undoes the public
/// one: `rsadp(rsaep(x)) = x`, whether the key carries its factors or not.
test "the CRT half and the single half agree on the raw operation" {
  let a = key3()
  let b = key_crt()
  let k = a.size()
  let x = Bytes::makei(k, i => {
    if i == 0 {
      b'\x00'
    } else {
      ((i * 7) & 0xff).to_byte()
    }
  })
  let c = a.public().rsaep(x[:])
  assert_eq(a.rsadp(c[:]), x)
  assert_eq(b.rsadp(c[:]), x)
  assert_eq(a.rsadp(c[:]), b.rsadp(c[:]))
}

///|
/// The two halves decrypt the same OAEP block to the same message.
test "the CRT half and the single half decrypt the same way" {
  let a = key3()
  let b = key_crt()
  let plain = b"across the two halves"
  let cipher = a.public().encrypt(plain[:], seed=b"0123456789abcdef0123"[:])
  assert_eq(a.decrypt(cipher[:]), plain)
  assert_eq(b.decrypt(cipher[:]), plain)
}

///|
/// A factor pair that does not multiply to the modulus is refused when the key
/// is read, not discovered at a signature.
test "a CRT factor that does not fit the modulus is refused" {
  let mut refused = false
  try {
    let _ = @rsa.PrivateKey::new_crt(
      crt_raw(crt_n)[:],
      crt_raw(crt_e)[:],
      crt_raw(crt_d)[:],
      crt_raw("3")[:],
      crt_raw(crt_n)[:],
    )
  } catch {
    Weak => refused = true
    _ => refused = false
  }
  assert_true(refused)
  // A pair that does multiply to the modulus is accepted and signs correctly.
  let ok = key_crt()
  assert_true(ok.public().verify(b"m"[:], ok.sign(b"m"[:])[:]))
}
