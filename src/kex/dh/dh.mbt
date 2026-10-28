// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The generator every ffdhe group uses.
///
/// Two, and not because it is convenient: RFC 7919 §3 fixes it, and a group with
/// a different generator is a different group.
pub let generator : Int32 = 2

///|
/// One of the five finite-field groups of RFC 7919.
///
/// They differ only in size, and the size is the whole choice: a larger group is
/// slower and buys a larger margin against a discrete logarithm. `ffdhe2048` is
/// the smallest the RFC defines and the one TLS picks when it has to.
pub(all) enum Group {
  Ffdhe2048
  Ffdhe3072
  Ffdhe4096
  Ffdhe6144
  Ffdhe8192
} derive(Eq, Debug)

///|
pub extend Group with Eq::{equal, not_equal}

///|
pub extend Group with Debug::{to_repr}

///|
/// The size of the group in bytes, which is also the width every value in it is
/// written at.
pub fn Group::size(self : Group) -> Int32 {
  match self {
    Ffdhe2048 => 256
    Ffdhe3072 => 384
    Ffdhe4096 => 512
    Ffdhe6144 => 768
    Ffdhe8192 => 1024
  }
}

///|
/// The size of the group in bits.
pub fn Group::bits(self : Group) -> Int32 {
  self.size() * 8
}

///|
/// How much security the group is estimated to give, in bits (RFC 7919 §5.1).
///
/// It is the number to compare against a symmetric key size: `ffdhe3072` is
/// roughly a 128-bit cipher, and anything smaller than that is the weak link in
/// a handshake that otherwise negotiates AES-128.
pub fn Group::security(self : Group) -> Int32 {
  match self {
    Ffdhe2048 => 112
    Ffdhe3072 => 128
    Ffdhe4096 => 152
    Ffdhe6144 => 176
    Ffdhe8192 => 200
  }
}

///|
/// The name the group is known by, which is what a protocol writes in a
/// negotiated list.
pub fn Group::name(self : Group) -> String {
  match self {
    Ffdhe2048 => "ffdhe2048"
    Ffdhe3072 => "ffdhe3072"
    Ffdhe4096 => "ffdhe4096"
    Ffdhe6144 => "ffdhe6144"
    Ffdhe8192 => "ffdhe8192"
  }
}

///|
/// The prime, decoded on demand.
///
/// Decoding costs a hex conversion; an exponentiation over the same number costs
/// thousands of multiplications, so there is nothing to gain by caching it and a
/// mutable global to lose.
pub fn Group::prime(self : Group) -> BigInt {
  let hex = match self {
    Ffdhe2048 => ffdhe2048
    Ffdhe3072 => ffdhe3072
    Ffdhe4096 => ffdhe4096
    Ffdhe6144 => ffdhe6144
    Ffdhe8192 => ffdhe8192
  }
  BigInt::from_octets(@base16.decode_lossy(hex))
}

///|
/// Write a group element at the width of the group.
///
/// Fixed width rather than minimal, because RFC 7919 §4 requires a public key to
/// be padded to the group size and a verifier is entitled to reject anything
/// shorter. A minimal encoding would also leak the leading zeroes of a value,
/// which is a small thing and free to avoid.
fn Group::pad(self : Group, value : BigInt) -> Bytes {
  value.to_octets(length=self.size())
}

///|
/// A private key: a group and an exponent.
pub struct Private {
  group : Group
  secret : BigInt
}

///|
/// Key an exponent.
///
/// The exponent is taken as given. RFC 7919 §5.1 suggests a length of twice the
/// security level — 225 bits and up — and leaves it to the caller because a
/// short exponent weakens nothing that the group size has not already fixed, but
/// it does weaken the exchange, so the length is worth thinking about.
///
/// Zero is refused: it produces a public key of one and a shared secret of one,
/// which is not a secret at all.
pub fn Private::new(
  group : Group,
  secret : BytesView,
) -> Private raise @spec.Broken {
  let value = BigInt::from_octets(secret)
  guard value != (0 : BigInt) else { raise @spec.Broken::Weak }
  { group, secret: value, }
}

///|
/// The group this exponent belongs to.
pub fn Private::group(self : Private) -> Group {
  self.group
}

///|
/// The public value: the generator raised to the secret, modulo the prime,
/// written at the width of the group.
pub fn Private::public(self : Private) -> Bytes {
  self.group.pad(
    BigInt::from_int(generator).pow(self.secret, modulus=self.group.prime()),
  )
}

///|
/// The shared secret: the peer's public value raised to the secret.
///
/// The peer's value is checked before it is used. It has to be exactly as wide as
/// the group — a shorter one is a peer that did not pad, and accepting it would
/// make two encodings of the same value mean different things — and it has to lie
/// in `[2, p-2]`, because 0, 1 and p-1 are the fixed points that make the result
/// independent of the secret.
pub fn Private::shared(
  self : Private,
  peer : BytesView,
) -> Bytes raise @spec.Broken {
  let size = self.group.size()
  guard peer.length() == size else {
    raise @spec.Broken::Size(want=size, got=peer.length())
  }
  let value = BigInt::from_octets(peer)
  let prime = self.group.prime()
  guard value >= (2 : BigInt) && value <= prime - (2 : BigInt) else {
    raise @spec.Broken::Weak
  }
  self.group.pad(value.pow(self.secret, modulus=prime))
}

///|
/// The public value for a secret, without keeping the secret.
pub fn public_key(
  group : Group,
  secret : BytesView,
) -> Bytes raise @spec.Broken {
  Private::new(group, secret).public()
}

///|
/// The shared secret for one side of an exchange.
pub fn shared_secret(
  group : Group,
  secret : BytesView,
  peer : BytesView,
) -> Bytes raise @spec.Broken {
  Private::new(group, secret).shared(peer)
}

// The five primes of RFC 7919 §A, in hex. Written out rather than generated at
// load time because a group that is wrong is a group that silently agrees with
// nobody.

///|
let ffdhe2048 : String = "// ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"

///|
let ffdhe3072 : String = "// ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff"

///|
let ffdhe4096 : String = "// ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e655f6affffffffffffffff"

///|
let ffdhe6144 : String = "// ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e0dd9020bfd64b645036c7a4e677d2c38532a3a23ba4442caf53ea63bb454329b7624c8917bdd64b1c0fd4cb38e8c334c701c3acdad0657fccfec719b1f5c3e4e46041f388147fb4cfdb477a52471f7a9a96910b855322edb6340d8a00ef092350511e30abec1fff9e3a26e7fb29f8c183023c3587e38da0077d9b4763e4e4b94b2bbc194c6651e77caf992eeaac0232a281bf6b3a739c1226116820ae8db5847a67cbef9c9091b462d538cd72b03746ae77f5e62292c311562a846505dc82db854338ae49f5235c95b91178ccf2dd5cacef403ec9d1810c6272b045b3b71f9dc6b80d63fdd4a8e9adb1e6962a69526d43161c1a41d570d7938dad4a40e329cd0e40e65ffffffffffffffff"

///|
let ffdhe8192 : String = "// ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e0dd9020bfd64b645036c7a4e677d2c38532a3a23ba4442caf53ea63bb454329b7624c8917bdd64b1c0fd4cb38e8c334c701c3acdad0657fccfec719b1f5c3e4e46041f388147fb4cfdb477a52471f7a9a96910b855322edb6340d8a00ef092350511e30abec1fff9e3a26e7fb29f8c183023c3587e38da0077d9b4763e4e4b94b2bbc194c6651e77caf992eeaac0232a281bf6b3a739c1226116820ae8db5847a67cbef9c9091b462d538cd72b03746ae77f5e62292c311562a846505dc82db854338ae49f5235c95b91178ccf2dd5cacef403ec9d1810c6272b045b3b71f9dc6b80d63fdd4a8e9adb1e6962a69526d43161c1a41d570d7938dad4a40e329ccff46aaa36ad004cf600c8381e425a31d951ae64fdb23fcec9509d43687feb69edd1cc5e0b8cc3bdf64b10ef86b63142a3ab8829555b2f747c932665cb2c0f1cc01bd70229388839d2af05e454504ac78b7582822846c0ba35c35f5c59160cc046fd8251541fc68c9c86b022bb7099876a460e7451a8a93109703fee1c217e6c3826e52c51aa691e0e423cfc99e9e31650c1217b624816cdad9a95f9d5b8019488d9c0a0a1fe3075a577e23183f81d4a3f2fa4571efc8ce0ba8a4fe8b6855dfe72b0a66eded2fbabfbe58a30fafabe1c5d71a87e2f741ef8c1fe86fea6bbfde530677f0d97d11d49f7a8443d0822e506a9f4614e011e2a94838ff88cd68c8bb7c5c6424cffffffffffffffff"
