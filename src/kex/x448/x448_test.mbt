// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
/// The scalar-multiplication vector of RFC 7748 §5.2, which the RFC gives as the
/// output of one iteration of the ladder from a fixed input.
test "the scalar multiplication vector of RFC 7748" {
  assert_eq(
    @base16.encode(
      @x448.shared(
        raw(
          "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        )[:],
        raw(
          "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        )[:],
      ),
    ),
    "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
  )
}

///|
/// The Diffie-Hellman exchange of RFC 7748 §6.2: two private keys, the public
/// keys they produce, and the one secret both sides arrive at.
test "the exchange of RFC 7748 section 6.2" {
  let alice = raw(
    "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
  )
  let bob = raw(
    "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
  )
  assert_eq(
    @base16.encode(@x448.public(alice[:])),
    "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
  )
  assert_eq(
    @base16.encode(@x448.public(bob[:])),
    "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
  )
  let want = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
  // Each side computes it from its own private key and the other's public one,
  // and they must agree — that is the whole point of the exercise.
  assert_eq(
    @base16.encode(@x448.shared(alice[:], @x448.public(bob[:])[:])),
    want,
  )
  assert_eq(
    @base16.encode(@x448.shared(bob[:], @x448.public(alice[:])[:])),
    want,
  )
}

///|
/// A low-order point makes the shared secret all zeroes, which means the peer
/// picked the answer instead of contributing to it.
///
/// Curve448's cofactor is 4, so there are fewer such points than on Curve25519:
/// the u-coordinates 0, 1 and the two of order 4.
test "a low-order point is refused" {
  let scalar = raw(
    "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
  )
  let zero = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  let one = "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  for point in [zero, one] {
    try @x448.shared(scalar[:], raw(point)[:]) |> ignore catch {
      e => assert_eq(e, @spec.Weak)
    } noraise {
      _ => fail("a low-order point produced a secret: \{point}")
    }
  }
}

///|
/// Anything that is not 56 bytes is refused rather than padded to it.
test "a scalar or point of the wrong length is refused" {
  let good = raw(
    "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
  )
  for n in [0, 32, 55, 57, 112] {
    let bad = Bytes::from_array(Array::make(n, b'\x01'))
    try @x448.shared(bad[:], good[:]) |> ignore catch {
      e => assert_eq(e, @spec.Size(want=56, got=n))
    } noraise {
      _ => fail("a \{n}-byte scalar was accepted")
    }
    try @x448.shared(good[:], bad[:]) |> ignore catch {
      e => assert_eq(e, @spec.Size(want=56, got=n))
    } noraise {
      _ => fail("a \{n}-byte point was accepted")
    }
  }
  assert_eq(@x448.size, 56)
  assert_eq(@x448.base.length(), 56)
  assert_eq(@x448.base[0], b'\x05')
}

///|
/// Clamping is part of the function, so the bits it ignores really are ignored:
/// two scalars differing only there agree.
///
/// Curve448 clamps two bits rather than three, and has no bit to mask off the
/// u-coordinate — 56 bytes is exactly 448 bits, which is why an X448 public key
/// whose top byte is set still decodes to itself.
test "the bits clamping discards do not reach the answer" {
  let a = raw(
    "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
  )
  let bent = a.to_array()
  // The low two bits of byte 0 and the top bit of byte 55 are set, whatever the
  // caller handed in.
  bent[0] = (bent[0].to_int() | 3).to_byte()
  bent[55] = (bent[55].to_int() | 128).to_byte()
  assert_eq(@x448.public(Bytes::from_array(bent)[:]), @x448.public(a[:]))
}
