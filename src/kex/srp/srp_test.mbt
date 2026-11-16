// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
fn unhex(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
let salt : Bytes = unhex("beb25379d1a8581eb5a727673a2441ee")

///|
let a_secret : Bytes = unhex(
  "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
)

///|
let b_secret : Bytes = unhex(
  "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
)

///|
let v_expected : String = "7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb"

///|
/// RFC 5054 Appendix B: the verifier, both public values and the premaster secret each end
/// computes, for alice and password123 in the 1024-bit group.
test "SRP matches RFC 5054's test vectors" {
  let v = @srp.verifier(G1024, b"alice"[:], b"password123"[:], salt[:])
  assert_eq(hex(v), v_expected)
  let client = @srp.Client::new(G1024, a_secret[:])
  assert_eq(
    hex(client.public()),
    "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
  )
  let server = @srp.Server::new(G1024, v[:], b_secret[:])
  assert_eq(
    hex(server.public()),
    "bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58",
  )
  let premaster = "b0dc82babcf30674ae450c0287745e7990a3381f63b387aaf271a10d233861e359b48220f7c4693c9ae12b0a6f67809f0876e2d013800d6c41bb59b6d5979b5c00a172b4a2a5903a0bdcaf8a709585eb2afafa8f3499b200210dcc1f10eb33943cd67fc88a2f39a4be5bec4ec0a3212dc346d7e474b29ede8a469ffeca686e5a"
  assert_eq(hex(server.premaster(client.public()[:])), premaster)
  assert_eq(
    hex(
      client.premaster(
        server.public()[:],
        salt=salt[:],
        identity=b"alice"[:],
        password=b"password123"[:],
      ),
    ),
    premaster,
  )
}

///|
/// A wrong password gives the client another secret, which is what makes the Finished messages
/// fail.
test "SRP: a wrong password agrees on nothing" {
  let v = @srp.verifier(G1024, b"alice"[:], b"password123"[:], salt[:])
  let client = @srp.Client::new(G1024, a_secret[:])
  let server = @srp.Server::new(G1024, v[:], b_secret[:])
  let wrong = client.premaster(
    server.public()[:],
    salt=salt[:],
    identity=b"alice"[:],
    password=b"password124"[:],
  )
  assert_true(wrong != server.premaster(client.public()[:]))
}

///|
/// RFC 5054 §2.5.3 and §2.5.4: a public value that is 0 modulo N is refused on either side, and
/// so is a secret exponent of zero.
test "SRP refuses a public value that is a multiple of N, and a zero secret" {
  let n = @srp.G1024.prime()
  let v = @srp.verifier(G1024, b"alice"[:], b"password123"[:], salt[:])
  let server = @srp.Server::new(G1024, v[:], b_secret[:])
  let client = @srp.Client::new(G1024, a_secret[:])
  for bad in [b"\x00", n.to_octets(), (n * 2).to_octets()] {
    let by_server = try server.premaster(bad[:]) catch {
      Weak => true
      _ => false
    } noraise {
      _ => false
    }
    assert_true(by_server)
    let by_client = try
      client.premaster(
        bad[:],
        salt=salt[:],
        identity=b"alice"[:],
        password=b"password123"[:],
      )
    catch {
      Weak => true
      _ => false
    } noraise {
      _ => false
    }
    assert_true(by_client)
  }
  let zero = try @srp.Client::new(G1024, b"\x00\x00"[:]) catch {
    Weak => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(zero)
}

///|
/// Each group is told apart by its prime and generator, as a ServerKeyExchange carries them.
test "SRP names a group from its parameters" {
  for group in @srp.groups {
    assert_eq(group.prime().to_octets().length(), group.size())
    assert_eq(
      @srp.Group::of(
        group.prime().to_octets()[:],
        group.generator().to_octets()[:],
      ),
      Some(group),
    )
  }
  assert_eq(@srp.Group::of(@srp.G1024.prime().to_octets()[:], b"\x05"[:]), None)
  assert_eq(@srp.G8192.bits(), 8192)
}
