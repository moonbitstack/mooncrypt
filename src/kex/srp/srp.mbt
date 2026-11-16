// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// One of the seven groups of RFC 5054 Appendix A, named by its size in bits.
#derive(Eq, Debug)
pub(all) enum Group {
  G1024
  G1536
  G2048
  G3072
  G4096
  G6144
  G8192
}

///|
pub extend Group with Eq::{equal, not_equal}

///|
pub extend Group with Debug::{to_repr}

///|
/// Every group, smallest first.
pub let groups : Array[Group] = [
  G1024,
  G1536,
  G2048,
  G3072,
  G4096,
  G6144,
  G8192,
]

///|
/// The size of the group in bytes, which is the width `PAD()` writes a value at.
pub fn Group::size(self : Group) -> Int32 {
  self.bits() / 8
}

///|
/// The size of the group in bits.
pub fn Group::bits(self : Group) -> Int32 {
  match self {
    G1024 => 1024
    G1536 => 1536
    G2048 => 2048
    G3072 => 3072
    G4096 => 4096
    G6144 => 6144
    G8192 => 8192
  }
}

///|
/// The prime N, decoded on demand.
pub fn Group::prime(self : Group) -> BigInt {
  let hex = match self {
    G1024 => g1024
    G1536 => g1536
    G2048 => g2048
    G3072 => g3072
    G4096 => g4096
    G6144 => g6144
    G8192 => g8192
  }
  BigInt::from_octets(@base16.decode_lossy(hex))
}

///|
/// The generator g. The larger primes are RFC 3526's, with generators recomputed to be primitive
/// roots rather than RFC 3526's 2.
pub fn Group::generator(self : Group) -> BigInt {
  match self {
    G1024 | G1536 | G2048 => 2
    G3072 | G4096 | G6144 => 5
    G8192 => 19
  }
}

///|
/// The group a ServerKeyExchange's prime and generator name, `None` for parameters outside the
/// appendix: RFC 5054 §2.5.3 has a client refuse those unless it has its own reason to trust them.
pub fn Group::of(prime : BytesView, generator : BytesView) -> Group? {
  let n = BigInt::from_octets(prime)
  let g = BigInt::from_octets(generator)
  groups
  .iter()
  .find_first(group => group.prime() == n && group.generator() == g)
}

///|
/// `PAD()` (RFC 5054 §2.1): the value at the width of N.
fn Group::pad(self : Group, value : BigInt) -> Bytes {
  value.to_octets(length=self.size())
}

///|
/// The implicit conversion of RFC 5054 §2.1: big-endian with no leading zero byte.
fn minimal(value : BigInt) -> Bytes {
  let octets = value.to_octets()
  let mut start = 0
  while start < octets.length() - 1 && octets[start] == b'\x00' {
    start = start + 1
  }
  octets[start:].to_owned()
}

///|
fn number(digest : Bytes) -> BigInt {
  BigInt::from_octets(digest)
}

///|
/// k = SHA1(N | PAD(g)), the SRP-6 multiplier.
fn Group::multiplier(self : Group) -> BigInt {
  let buf = Buffer()
  buf.write_bytes(minimal(self.prime()))
  buf.write_bytes(self.pad(self.generator()))
  number(@sha1.hash(buf.to_bytes()[:]))
}

///|
/// u = SHA1(PAD(A) | PAD(B)), which binds the secret to both public values.
fn Group::scrambler(self : Group, a : BigInt, b : BigInt) -> BigInt {
  let buf = Buffer()
  buf.write_bytes(self.pad(a))
  buf.write_bytes(self.pad(b))
  number(@sha1.hash(buf.to_bytes()[:]))
}

///|
/// x = SHA1(s | SHA1(I | ":" | P)).
fn exponent(
  salt : BytesView,
  identity : BytesView,
  password : BytesView,
) -> BigInt {
  let inner = Buffer()
  inner.write_bytesview(identity)
  inner.write_byte(b':')
  inner.write_bytesview(password)
  let outer = Buffer()
  outer.write_bytesview(salt)
  outer.write_bytes(@sha1.hash(inner.to_bytes()[:]))
  number(@sha1.hash(outer.to_bytes()[:]))
}

///|
/// The verifier a server stores for a user, v = g^x % N (RFC 5054 §2.4). The user name and
/// password are the UTF-8 octets after SASLprep (§2.3), which the caller has done.
pub fn verifier(
  group : Group,
  identity : BytesView,
  password : BytesView,
  salt : BytesView,
) -> Bytes {
  let x = exponent(salt, identity, password)
  minimal(group.generator().pow(x, modulus=group.prime()))
}

///|
/// A secret exponent: a number the caller drew, which RFC 5054 §2.5.3 wants at least 256 bits
/// long. Zero is refused.
fn secret_of(secret : BytesView) -> BigInt raise @spec.Broken {
  let value = BigInt::from_octets(secret)
  guard value != 0 else { raise Weak }
  value
}

///|
/// A peer's public value, refused when it is 0 modulo N (RFC 5054 §2.5.3, §2.5.4): the secret
/// would then be one an attacker computes without the password.
fn public_of(group : Group, value : BytesView) -> BigInt raise @spec.Broken {
  let v = BigInt::from_octets(value)
  guard v % group.prime() != 0 else { raise Weak }
  v
}

///|
/// The client's half: its secret exponent a and its public value A = g^a % N.
pub struct Client {
  priv group : Group
  priv secret : BigInt
  priv public : BigInt
}

///|
/// A client in `group` with the secret exponent `secret`.
pub fn Client::new(
  group : Group,
  secret : BytesView,
) -> Client raise @spec.Broken {
  let a = secret_of(secret)
  { group, secret: a, public: group.generator().pow(a, modulus=group.prime()), }
}

///|
/// A, as the ClientKeyExchange carries it.
pub fn Client::public(self : Client) -> Bytes {
  minimal(self.public)
}

///|
/// The premaster secret (RFC 5054 §2.6), (B - k * g^x) ^ (a + u * x) % N, from the server's
/// public value and salt and the user's name and password.
pub fn Client::premaster(
  self : Client,
  server : BytesView,
  salt~ : BytesView,
  identity~ : BytesView,
  password~ : BytesView,
) -> Bytes raise @spec.Broken {
  let group = self.group
  let n = group.prime()
  let b = public_of(group, server)
  let u = group.scrambler(self.public, b)
  guard u != 0 else { raise Weak }
  let x = exponent(salt, identity, password)
  let k = group.multiplier()
  let base = (b - k * group.generator().pow(x, modulus=n)) % n
  let base = if base < 0 { base + n } else { base }
  minimal(base.pow(self.secret + u * x, modulus=n))
}

///|
/// The server's half: its secret exponent b, the user's verifier v and its public value
/// B = (k * v + g^b) % N.
pub struct Server {
  priv group : Group
  priv secret : BigInt
  priv verifier : BigInt
  priv public : BigInt
}

///|
/// A server in `group` for the user whose verifier is `verifier`, with the secret exponent
/// `secret`.
pub fn Server::new(
  group : Group,
  verifier : BytesView,
  secret : BytesView,
) -> Server raise @spec.Broken {
  let b = secret_of(secret)
  let n = group.prime()
  let v = BigInt::from_octets(verifier)
  let public = (group.multiplier() * v + group.generator().pow(b, modulus=n)) %
    n
  { group, secret: b, verifier: v, public, }
}

///|
/// B, as the ServerKeyExchange carries it.
pub fn Server::public(self : Server) -> Bytes {
  minimal(self.public)
}

///|
/// The premaster secret (RFC 5054 §2.6), (A * v^u) ^ b % N, from the client's public value.
pub fn Server::premaster(
  self : Server,
  client : BytesView,
) -> Bytes raise @spec.Broken {
  let group = self.group
  let n = group.prime()
  let a = public_of(group, client)
  let u = group.scrambler(a, self.public)
  guard u != 0 else { raise Weak }
  let base = a * self.verifier.pow(u, modulus=n) % n
  minimal(base.pow(self.secret, modulus=n))
}

///|
let g1024 : String = "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3"

///|
let g1536 : String = "9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea9614b19cc4d5f4f5f556e27cbde51c6a94be4607a291558903ba0d0f84380b655bb9a22e8dcdf028a7cec67f0d08134b1c8b97989149b609e0be3bab63d47548381dbc5b1fc764e3f4b53dd9da1158bfd3e2b9c8cf56edf019539349627db2fd53d24b7c48665772e437d6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b5292e5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf76e3fed135f9bb"

///|
let g2048 : String = "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73"

///|
let g3072 : String = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"

///|
let g4096 : String = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff"

///|
let g6144 : String = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff"

///|
let g8192 : String = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652de3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851df9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f924009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dfffffffffffffffff"
