///|
test "curve: a coordinate is as wide as the field" {
  assert_eq(@curve.P256.size(), 32)
  assert_eq(@curve.P384.size(), 48)
  assert_eq(@curve.P521.size(), 66)
  assert_eq(@curve.Secp256k1.size(), 32)
}

///|
test "curve: a key built outside the library names its curve" {
  let scalar = Bytes::make(48, b'\x01')
  let point = @ecdsa.PrivateKey::new(scalar[:], curve=P384).public().bytes()
  let key = @ecdsa.PublicKey::new(point[:], curve=P384)
  assert_eq(key.curve(), @curve.P384)
}
