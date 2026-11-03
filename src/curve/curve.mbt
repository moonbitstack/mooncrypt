// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which curve a key lives on.
///
/// The short-Weierstrass curves that protocols in use actually name: the three
/// NIST primes, which TLS and JOSE speak; secp256k1, which Bitcoin and Ethereum
/// speak; and the three brainpool curves RFC 5639 defines, which some European
/// and government profiles require. They differ only in their parameters, so
/// the arithmetic is written once and each curve is a row in a table.
#derive(Eq, Debug)
pub(all) enum Curve {
  P256
  P384
  P521
  Secp256k1
  BrainpoolP256r1
  BrainpoolP384r1
  BrainpoolP512r1
}

///|
pub extend Curve with Eq::{equal, not_equal}

///|
pub extend Curve with Debug::{to_repr}

///|
/// The width in bytes of a coordinate, a scalar, and each half of a signature.
pub fn Curve::size(self : Curve) -> Int32 {
  match self {
    P256 | Secp256k1 | BrainpoolP256r1 => 32
    P384 | BrainpoolP384r1 => 48
    P521 => 66
    BrainpoolP512r1 => 64
  }
}
