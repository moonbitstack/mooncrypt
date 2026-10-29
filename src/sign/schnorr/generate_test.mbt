///|
test "generate draws again above the order and keeps a scalar below it" {
  // BIP-340 test vector 1's secret key, after a draw of all ones, which is
  // above the secp256k1 order.
  let secret = raw(
    "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
  )
  let ones = Bytes::make(32, b'\xff')
  let source = @moonrand.Replay::new(ones + secret)
  let key = @schnorr.PrivateKey::generate(source)
  assert_eq(key.bytes(), secret)
  assert_eq(source.remaining(), 0)
}
