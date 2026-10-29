///|
test "generate keeps d below n - 1, so that 1 + d can be inverted" {
  let n_minus_1 = unhex(
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122",
  )
  let n_minus_2 = unhex(
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54121",
  )
  let source = @moonrand.Replay::new(n_minus_1 + n_minus_2)
  let key = @sm2.PrivateKey::generate(source)
  assert_eq(hex(key.encode()), hex(n_minus_2))
  assert_eq(source.remaining(), 0)
}

///|
test "a key of n - 1 is refused, since 1 + d would be zero" {
  let refused = try {
    ignore(
      @sm2.PrivateKey::new(
        unhex(
          "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122",
        ),
      ),
    )
    false
  } catch {
    _ => true
  }
  assert_true(refused)
}
