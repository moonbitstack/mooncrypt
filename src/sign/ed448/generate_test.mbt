///|
test "generate takes its 57-byte secret from the source" {
  // RFC 8032 §7.4, the blank message.
  let seed = unhex(
    "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
  )
  let source = @moonseed.Replay::new(seed)
  let key = @ed448.PrivateKey::generate(source)
  assert_eq(
    hx(key.public().bytes()),
    "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
  )
  assert_eq(source.remaining(), 0)
}
