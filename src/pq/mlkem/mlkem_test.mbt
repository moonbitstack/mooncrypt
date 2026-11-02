// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
test "the shared secret is the one both sides compute" {
  for kind in [@mlkem.K512, @mlkem.K768, @mlkem.K1024] {
    let seed = @base16.decode_lossy(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    )
    let key = @mlkem.PrivateKey::from_seed(kind~, seed[:])
    let public = key.encapsulation_key()
    assert_eq(public.bytes().length(), kind.encapsulation())
    assert_eq(key.bytes().length(), kind.decapsulation())
    let out = public.encapsulate(
      @moonseed.Replay::new(b"a shared source of 32 bytes, it is"),
    )
    assert_eq(out.secret.length(), 32)
    assert_eq(out.ciphertext.length(), kind.ciphertext())
    assert_eq(key.decapsulate(out.ciphertext[:]), out.secret)
  }
}

///|
test "a key derived from its seed is the same key again" {
  let seed = @base16.decode_lossy(
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
  )
  let first = @mlkem.PrivateKey::from_seed(kind=@mlkem.K768, seed[:])
  let second = @mlkem.PrivateKey::from_seed(kind=@mlkem.K768, seed[:])
  assert_eq(first.bytes(), second.bytes())
  // The same bytes read back out of a key file are the same key.
  let reread = @mlkem.PrivateKey::new(kind=@mlkem.K768, first.bytes()[:])
  assert_eq(reread.bytes(), first.bytes())
  assert_eq(
    reread.encapsulation_key().bytes(),
    first.encapsulation_key().bytes(),
  )
}

///|
test "a ciphertext that was tampered with yields a different secret, not a failure" {
  let key = @mlkem.PrivateKey::from_seed(
    kind=@mlkem.K768,
    @base16.decode_lossy(
      "11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222",
    )[:],
  )
  let out = key
    .encapsulation_key()
    .encapsulate(@moonseed.Replay::new(b"a shared source of 32 bytes, it is"))
  let broken = out.ciphertext.to_array()
  broken[0] = (broken[0].to_int() ^ 1).to_byte()
  let got = key.decapsulate(Bytes::from_array(broken)[:])
  assert_eq(got.length(), 32)
  assert_false(@spec.eq(got, out.secret))
}

///|
test "panic on a ciphertext of the wrong length" {
  let key = @mlkem.PrivateKey::from_seed(
    kind=@mlkem.K512,
    @base16.decode_lossy(
      "33333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444",
    )[:],
  )
  ignore(key.decapsulate(b"\x00\x00\x00"))
}

///|
test "a decapsulation key whose halves disagree is refused" {
  let seed = @base16.decode_lossy(
    "55555555555555555555555555555555555555555555555555555555555555556666666666666666666666666666666666666666666666666666666666666666",
  )
  let raw = @mlkem.PrivateKey::from_seed(kind=@mlkem.K512, seed[:]).bytes()
  // The stored hash of the encapsulation key is what binds the two halves.
  let wrong = raw.to_array()
  let at = 768 + 32
  wrong[at] = (wrong[at].to_int() ^ 0xff).to_byte()
  assert_true(
    try {
      ignore(
        @mlkem.PrivateKey::new(kind=@mlkem.K512, Bytes::from_array(wrong)[:]),
      )
      false
    } catch {
      @spec.Weak => true
      _ => false
    },
  )
}

///|
test "an encapsulation key that is not canonical is refused" {
  // 0xFFF is above q, so the vector it spells is not the encoding of any
  // polynomial.
  let seed = @base16.decode_lossy(
    "77777777777777777777777777777777777777777777777777777777777777778888888888888888888888888888888888888888888888888888888888888888",
  )
  let raw = @mlkem.PrivateKey::from_seed(kind=@mlkem.K512, seed[:])
    .encapsulation_key()
    .bytes()
  let wrong = raw.to_array()
  wrong[0] = b'\xff'
  wrong[1] = b'\xff'
  assert_true(
    try {
      ignore(
        @mlkem.PublicKey::new(kind=@mlkem.K512, Bytes::from_array(wrong)[:]),
      )
      false
    } catch {
      @spec.Weak => true
      _ => false
    },
  )
}

///|
test "the Kem contract reports the lengths the sets are defined by" {
  let traits : Array[&@spec.Kem] = [@mlkem.K512, @mlkem.K768, @mlkem.K1024]
  let expected = [(800, 1632, 768), (1184, 2400, 1088), (1568, 3168, 1568)]
  for i, kem in traits {
    let (ek, dk, ct) = expected[i]
    assert_eq(kem.encapsulation(), ek)
    assert_eq(kem.shared(), 32)
    assert_eq(kem.ciphertext(), ct)
    // The decapsulation length is not part of the contract, but the key type
    // still has to agree with it.
    ignore(dk)
  }
}

///|
test "panic on a seed of the wrong length" {
  ignore(@mlkem.PrivateKey::from_seed(kind=@mlkem.K512, b"\x00"))
}
