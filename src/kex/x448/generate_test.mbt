///|
test "generate takes 56 bytes from the source" {
  let draw = Bytes::makei(56, i => i.to_byte())
  let source = @moonrand.Replay::new(draw)
  assert_eq(@x448.generate(source), draw)
  assert_eq(source.remaining(), 0)
}
