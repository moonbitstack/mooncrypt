///|
test "generate takes its seed from the source, as Go's ed25519.GenerateKey does" {
  // RFC 8032 §7.1, test 1.
  let seed = raw(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let source = @moonseed.Replay::new(seed)
  let key = @ed25519.PrivateKey::generate(source)
  assert_eq(key.bytes(), seed)
  assert_eq(
    @base16.encode(key.public().bytes()),
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  assert_eq(source.remaining(), 0)
}
