// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The curve an exchange runs on. P-256 is the default because RFC 8446 §9.1
/// makes it the one every TLS 1.3 implementation has.
pub using @curve {type Curve}

///|
/// A fresh private scalar for `curve`, drawn from `source` uniformly in
/// [1, n - 1], big-endian and `curve.size()` bytes.
pub fn[S : @moonseed.Source] generate(
  source : S,
  curve~ : Curve = P256,
) -> Bytes raise @moonseed.Unavailable {
  @moonseed.scalar(@ec.params(curve).n.to_octets(length=curve.size()), source)
}

///|
/// The public value for the private `scalar` (big-endian, `curve.size()` bytes,
/// in `[1, n)`): the uncompressed SEC 1 point `04 ∥ X ∥ Y`, which is what a TLS
/// key share carries.
pub fn public(
  scalar : BytesView,
  curve~ : Curve = P256,
) -> Bytes raise @spec.Broken {
  let d = @ec.scalar(curve, scalar)
  @ec.encode(curve, @ec.mul(curve, d, @ec.generator(curve)))
}

///|
/// The shared secret between the private `scalar` and the `peer`'s public value:
/// the X coordinate of their product, `curve.size()` bytes. The peer's point is
/// refused unless it lies on the curve, which is what keeps an invalid-curve
/// attack from reading the scalar out a few bits at a time. Both SEC 1 forms are
/// read; TLS sends only the uncompressed one.
pub fn shared(
  scalar : BytesView,
  peer : BytesView,
  curve~ : Curve = P256,
) -> Bytes raise @spec.Broken {
  let d = @ec.scalar(curve, scalar)
  let q = @ec.decode(curve, peer)
  let s = @ec.mul(curve, d, q)
  guard !s.zero else { raise @spec.Tag }
  s.x.to_octets(length=curve.size())
}
