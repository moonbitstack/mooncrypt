// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
/// The two scalar-multiplication vectors of RFC 7748 §5.2.
test "the scalar multiplication vectors of RFC 7748" {
  let cases = [
    (
      "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ),
    (
      "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
      "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    ),
  ]
  for case in cases {
    let (scalar, point, want) = case
    assert_eq(
      @base16.encode(@x25519.shared(raw(scalar)[:], raw(point)[:])),
      want,
    )
  }
}

///|
/// The Diffie-Hellman exchange of RFC 7748 §6.1: two private keys, the public
/// keys they produce, and the one secret both sides arrive at.
test "the exchange of RFC 7748 section 6.1" {
  let alice = raw(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let bob = raw(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  assert_eq(
    @base16.encode(@x25519.public(alice[:])),
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  assert_eq(
    @base16.encode(@x25519.public(bob[:])),
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
  let want = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  // Each side computes it from its own private key and the other's public one,
  // and they must agree — that is the whole point of the exercise.
  assert_eq(
    @base16.encode(@x25519.shared(alice[:], @x25519.public(bob[:])[:])),
    want,
  )
  assert_eq(
    @base16.encode(@x25519.shared(bob[:], @x25519.public(alice[:])[:])),
    want,
  )
}

///|
/// A low-order point makes the shared secret all zeroes, which means the peer
/// picked the answer instead of contributing to it.
test "a low-order point is refused" {
  let scalar = raw(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  // The order-1, order-2 and order-4 points, and the two of order 8. Every one
  // of them drives the ladder to zero.
  let weak = [
    "0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ]
  for point in weak {
    try @x25519.shared(scalar[:], raw(point)[:]) |> ignore catch {
      e => assert_eq(e, @spec.Weak)
    } noraise {
      _ => fail("a low-order point produced a secret: \{point}")
    }
  }
}

///|
/// Anything that is not 32 bytes is refused rather than padded to it.
test "a scalar or point of the wrong length is refused" {
  let good = raw(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  for n in [0, 31, 33, 64] {
    let bad = Bytes::from_array(Array::make(n, b'\x01'))
    try @x25519.shared(bad[:], good[:]) |> ignore catch {
      e => assert_eq(e, @spec.Size(want=32, got=n))
    } noraise {
      _ => fail("a \{n}-byte scalar was accepted")
    }
    try @x25519.shared(good[:], bad[:]) |> ignore catch {
      e => assert_eq(e, @spec.Size(want=32, got=n))
    } noraise {
      _ => fail("a \{n}-byte point was accepted")
    }
  }
  assert_eq(@x25519.size, 32)
  assert_eq(@x25519.base.length(), 32)
  assert_eq(@x25519.base[0], b'\x09')
}

///|
/// Clamping is part of the function, so the bits it ignores really are ignored:
/// two scalars differing only there agree.
test "the bits clamping discards do not reach the answer" {
  let a = raw(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let bent = a.to_array()
  // The low three bits of byte 0 and the top bit of byte 31 are cleared, and
  // bit 254 is set, whatever the caller handed in.
  bent[0] = (bent[0].to_int() | 7).to_byte()
  bent[31] = (bent[31].to_int() | 128).to_byte()
  bent[31] = (bent[31].to_int() & 191).to_byte()
  assert_eq(@x25519.public(Bytes::from_array(bent)[:]), @x25519.public(a[:]))
}
