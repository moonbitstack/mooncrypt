// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
using @curve {type Curve}

///|
pub(all) struct Params {
  p : BigInt
  a : BigInt
  b : BigInt
  n : BigInt
  gx : BigInt
  gy : BigInt
}

///|
pub(all) struct Point {
  x : BigInt
  y : BigInt
  zero : Bool
}

///|
pub fn big(s : String) -> BigInt {
  BigInt::from_string(s, radix=16)
}

///|
/// FIPS 186-4 §D.1.2 for the three NIST primes, SEC 2 §2.4.1 for secp256k1.
/// `a = p - 3` for all three NIST curves; secp256k1 is `y² = x³ + 7`.
let p256 : Params = {
  p: big("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
  a: big("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
  b: big("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
  n: big("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
  gx: big("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
  gy: big("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
}

///|
let p384 : Params = {
  p: big(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
  ),
  a: big(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
  ),
  b: big(
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
  ),
  n: big(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
  ),
  gx: big(
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
  ),
  gy: big(
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
  ),
}

///|
let p521 : Params = {
  p: big(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
  ),
  a: big(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
  ),
  b: big(
    "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
  ),
  n: big(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
  ),
  gx: big(
    "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
  ),
  gy: big(
    "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
  ),
}

///|
let secp256k1 : Params = {
  p: big("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
  a: 0,
  b: 7,
  n: big("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
  gx: big("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
  gy: big("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
}

///|
/// RFC 5639 §3.2–3.4: the three brainpool curves some European and government
/// profiles require. All three primes are congruent to 3 mod 4, so the same
/// `(p + 1) / 4` square root recovers a y from an x here as on the NIST curves.
let brainpool_p256r1 : Params = {
  p: big("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"),
  a: big("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"),
  b: big("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"),
  n: big("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
  gx: big("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"),
  gy: big("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"),
}

///|
let brainpool_p384r1 : Params = {
  p: big(
    "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
  ),
  a: big(
    "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
  ),
  b: big(
    "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
  ),
  n: big(
    "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
  ),
  gx: big(
    "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
  ),
  gy: big(
    "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
  ),
}

///|
let brainpool_p512r1 : Params = {
  p: big(
    "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
  ),
  a: big(
    "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
  ),
  b: big(
    "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
  ),
  n: big(
    "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
  ),
  gx: big(
    "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
  ),
  gy: big(
    "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
  ),
}

///|
pub fn params(c : Curve) -> Params {
  match c {
    P256 => p256
    P384 => p384
    P521 => p521
    Secp256k1 => secp256k1
    BrainpoolP256r1 => brainpool_p256r1
    BrainpoolP384r1 => brainpool_p384r1
    BrainpoolP512r1 => brainpool_p512r1
  }
}

///|
pub fn generator(c : Curve) -> Point {
  let q = params(c)
  { x: q.gx, y: q.gy, zero: false, }
}

///|
pub fn mod_p(c : Curve, a : BigInt) -> BigInt {
  let p = params(c).p
  let m = a % p
  if m < (0 : BigInt) {
    m + p
  } else {
    m
  }
}

///|
pub fn mod_n(c : Curve, a : BigInt) -> BigInt {
  let n = params(c).n
  let m = a % n
  if m < (0 : BigInt) {
    m + n
  } else {
    m
  }
}

///|
/// The inverse by Fermat's little theorem, which needs a prime modulus — both
/// the field prime and the group order are prime, so it serves for each.
pub fn inv(a : BigInt, modulus : BigInt) -> BigInt {
  let m = a % modulus
  let norm = if m < (0 : BigInt) { m + modulus } else { m }
  norm.pow(modulus - 2, modulus~)
}

///|
pub fn on_curve(c : Curve, x : BigInt, y : BigInt) -> Bool {
  let q = params(c)
  mod_p(c, y * y) == mod_p(c, x * x * x + q.a * x + q.b)
}

///|
/// Recover `Y` from `X` for a compressed point. Every curve here has
/// `p ≡ 3 (mod 4)`, so the square root is one exponentiation.
pub fn y_of(c : Curve, x : BigInt, odd : Bool) -> BigInt {
  let q = params(c)
  let yy = mod_p(c, x * x * x + q.a * x + q.b)
  let y = yy.pow((q.p + 1) / 4, modulus=q.p)
  if (y % 2 == (1 : BigInt)) == odd {
    y
  } else {
    q.p - y
  }
}

///|
pub fn double(c : Curve, pt : Point) -> Point {
  if pt.zero || pt.y == (0 : BigInt) {
    return { x: 0, y: 0, zero: true, }
  }
  let lam = mod_p(
    c,
    (3 * pt.x * pt.x + params(c).a) * inv(2 * pt.y, params(c).p),
  )
  let x = mod_p(c, lam * lam - 2 * pt.x)
  { x, y: mod_p(c, lam * (pt.x - x) - pt.y), zero: false, }
}

///|
pub fn add(c : Curve, a : Point, b : Point) -> Point {
  if a.zero {
    return b
  }
  if b.zero {
    return a
  }
  if a.x == b.x {
    return if a.y == b.y { double(c, a) } else { { x: 0, y: 0, zero: true, } }
  }
  let lam = mod_p(c, (b.y - a.y) * inv(b.x - a.x, params(c).p))
  let x = mod_p(c, lam * lam - a.x - b.x)
  { x, y: mod_p(c, lam * (a.x - x) - a.y), zero: false, }
}

///|
/// `[k]P`. The scalar multiplication runs in fixed-width 32-bit limbs with a
/// Montgomery ladder and a branch-free swap, so every bit costs one addition
/// and one doubling whatever its value; see [`mul_limb`] for the field.
pub fn mul(c : Curve, k : BigInt, pt : Point) -> Point {
  if pt.zero {
    return pt
  }
  mul_limb(c, k, pt)
}

///|
/// `[k]G`, with the generator fixed: this is what a signature and a key pair
/// need, and every curve here has a comb table for it that turns the per-bit
/// doubling into a table read.
///
/// `k` is a scalar below `n`, as everywhere in this module. The table covers
/// `ceil(bits(n)/5)·5` bits, a little more than `n` has, so a scalar in range is
/// never cut short.
pub fn mul_g(c : Curve, k : BigInt) -> Point {
  mul_g_limb(c, k)
}

///|
/// `[k1]G + [k2]P`, in one pass. A signature verification is always a fixed
/// multiple of the generator plus a multiple of the public key, and running the
/// two through one loop shares the doublings — the bulk of the work — between
/// them.
pub fn mul2_g(c : Curve, k1 : BigInt, k2 : BigInt, pt : Point) -> Point {
  if pt.zero {
    return mul_g(c, k1)
  }
  mul2_g_limb(c, k1, k2, pt)
}

///|
/// The number of bits in `n`, or zero for zero. Counted off the top octet:
/// shifting a `BigInt` down one bit at a time allocates a new one per bit, and
/// on a 256-bit prime that was eighty microseconds a call.
pub fn bits(n : BigInt) -> Int32 {
  if n <= (0 : BigInt) {
    return 0
  }
  let mut count : Int32 = 0
  let mut started = false
  for b in n.to_octets() {
    let v = b.to_int()
    if started || v != 0 {
      if count == 0 {
        // The first octet that is not zero: count only the bits it uses.
        started = true
        let mut rest = v
        while rest != 0 {
          count = count + 1
          rest = rest >> 1
        }
      } else {
        count = count + 8
      }
    }
  }
  count
}

///|
/// A point read from SEC 1 §2.3.3: `04 ∥ X ∥ Y` uncompressed, or `02`/`03 ∥ X`
/// compressed with the prefix giving the parity of `Y`. Refused unless it lies on
/// the curve.
pub fn decode(c : Curve, point : BytesView) -> Point raise @spec.Broken {
  let size = c.size()
  let (x, y) = if point.length() == 1 + 2 * size && point[0] == b'\x04' {
    (
      BigInt::from_octets(point[1:1 + size]),
      BigInt::from_octets(point[1 + size:]),
    )
  } else if point.length() == 1 + size &&
    (point[0] == b'\x02' || point[0] == b'\x03') {
    let x = BigInt::from_octets(point[1:])
    (x, y_of(c, x, point[0] == b'\x03'))
  } else {
    raise @spec.Size(want=1 + 2 * size, got=point.length())
  }
  guard x < params(c).p && y < params(c).p && on_curve(c, x, y) else {
    raise @spec.Tag
  }
  { x, y, zero: false, }
}

///|
/// A point as an uncompressed SEC 1 point, `04 ∥ X ∥ Y`.
pub fn encode(c : Curve, pt : Point) -> Bytes {
  let size = c.size()
  let out : Array[Byte] = [b'\x04']
  for b in pt.x.to_octets(length=size) {
    out.push(b)
  }
  for b in pt.y.to_octets(length=size) {
    out.push(b)
  }
  Bytes::from_array(out)
}

///|
/// A scalar read big-endian and fixed-width, refused unless it is in `[1, n)`.
pub fn scalar(c : Curve, bytes : BytesView) -> BigInt raise @spec.Broken {
  let size = c.size()
  guard bytes.length() == size else {
    raise @spec.Size(want=size, got=bytes.length())
  }
  let d = BigInt::from_octets(bytes)
  guard d >= (1 : BigInt) && d < params(c).n else { raise @spec.Tag }
  d
}
