///|
test "generate takes the private scalar from the source" {
  // RFC 7748 §6.1, Alice.
  let private = raw(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let source = @moonrand.Replay::new(private)
  let scalar = @x25519.generate(source)
  assert_eq(scalar, private)
  assert_eq(
    @base16.encode(@x25519.public(scalar)),
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  assert_eq(source.remaining(), 0)
}
