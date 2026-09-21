// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Which member of the SHA-2 family.
///
/// The six are one design at two word widths. `Sha512_224` and `Sha512_256` are
/// SHA-512 with a different initial vector and a truncated digest, which is why
/// they are not simply SHA-512 cut short — cutting SHA-512 short would leave the
/// discarded half recoverable in a length-extension.
pub(all) enum Kind {
  Sha224
  Sha256
  Sha384
  Sha512
  Sha512_224
  Sha512_256
} derive(Eq, Debug)

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The digest length in bytes.
pub fn Kind::size(self : Kind) -> Int {
  match self {
    Sha224 => 28
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
    Sha512_224 => 28
    Sha512_256 => 32
  }
}

///|
/// The compression block length in bytes.
pub fn Kind::block(self : Kind) -> Int {
  match self {
    Sha224 | Sha256 => 64
    _ => 128
  }
}

///|
/// A SHA-2 computation in progress.
///
/// Abstract on purpose: the state is a working buffer plus a chaining value,
/// and reading either of them halfway through is never what a caller wants.
struct Hasher {
  kind : Kind
  core : Core
}

///|
priv enum Core {
  Narrow(Narrow)
  Wide(Wide)
}

///|
priv struct Narrow {
  h : FixedArray[UInt]
  buf : FixedArray[Byte]
  mut used : Int
  mut n : UInt64
}

///|
priv struct Wide {
  h : FixedArray[UInt64]
  buf : FixedArray[Byte]
  mut used : Int
  mut lo : UInt64
  mut hi : UInt64
}

///|
/// A fresh hasher, SHA-256 unless another member is named.
pub fn Hasher::new(kind? : Kind = Sha256) -> Hasher {
  let core = match kind {
    Sha224 | Sha256 =>
      Narrow({
        h: FixedArray::make(8, 0U),
        buf: FixedArray::make(64, b'\x00'),
        used: 0,
        n: 0,
      })
    _ =>
      Wide({
        h: FixedArray::make(8, 0UL),
        buf: FixedArray::make(128, b'\x00'),
        used: 0,
        lo: 0,
        hi: 0,
      })
  }
  let hasher = { kind, core, }
  hasher.reset()
  hasher
}

///|
/// Hash one whole message.
pub fn hash(msg : BytesView, kind? : Kind = Sha256) -> Bytes {
  let h = Hasher::new(kind~)
  h.write(msg)
  h.finish()
}

///|
pub extend Hasher with @spec.Hash::{block, finish, reset, size, write}

///|
pub impl @spec.Hash for Hasher with fn write(self : Hasher, msg : BytesView) -> Unit {
  match self.core {
    Narrow(s) => narrow_write(s, msg)
    Wide(s) => wide_write(s, msg)
  }
}

///|
pub impl @spec.Hash for Hasher with fn finish(self : Hasher) -> Bytes {
  match self.core {
    Narrow(s) => narrow_finish(s, self.kind.size())
    Wide(s) => wide_finish(s, self.kind.size())
  }
}

///|
pub impl @spec.Hash for Hasher with fn reset(self : Hasher) -> Unit {
  match self.core {
    Narrow(s) => {
      let iv = if self.kind == Sha224 { iv224 } else { iv256 }
      for i in 0..<8 {
        s.h[i] = iv[i]
      }
      s.used = 0
      s.n = 0
    }
    Wide(s) => {
      let iv = match self.kind {
        Sha384 => iv384
        Sha512_224 => iv512_224
        Sha512_256 => iv512_256
        _ => iv512
      }
      for i in 0..<8 {
        s.h[i] = iv[i]
      }
      s.used = 0
      s.lo = 0
      s.hi = 0
    }
  }
}

///|
pub impl @spec.Hash for Hasher with fn size(self : Hasher) -> Int {
  self.kind.size()
}

///|
pub impl @spec.Hash for Hasher with fn block(self : Hasher) -> Int {
  self.kind.block()
}

// ---------------------------------------------------------------- 32-bit half

///|
/// The 64 round constants: the first 32 bits of the fractional parts of the cube
/// roots of the first 64 primes (FIPS 180-4 §4.2.2).
let k32 : FixedArray[UInt] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
  0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
  0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
  0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
  0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
]

///|
let iv256 : FixedArray[UInt] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
  0x5be0cd19,
]

///|
let iv224 : FixedArray[UInt] = [
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
  0xbefa4fa4,
]

///|
fn rotr32(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
fn narrow_block(
  h : FixedArray[UInt],
  data : FixedArray[Byte],
  off : Int,
) -> Unit {
  let w : FixedArray[UInt] = FixedArray::make(64, 0U)
  for i in 0..<16 {
    let j = off + i * 4
    w[i] = (data[j].to_int().reinterpret_as_uint() << 24) |
      (data[j + 1].to_int().reinterpret_as_uint() << 16) |
      (data[j + 2].to_int().reinterpret_as_uint() << 8) |
      data[j + 3].to_int().reinterpret_as_uint()
  }
  for i in 16..<64 {
    let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
    let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }
  let mut a = h[0]
  let mut b = h[1]
  let mut c = h[2]
  let mut d = h[3]
  let mut e = h[4]
  let mut f = h[5]
  let mut g = h[6]
  let mut s = h[7]
  for i in 0..<64 {
    let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
    let ch = (e & f) ^ (e.lnot() & g)
    let t1 = s + s1 + ch + k32[i] + w[i]
    let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let t2 = s0 + maj
    s = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }
  h[0] += a
  h[1] += b
  h[2] += c
  h[3] += d
  h[4] += e
  h[5] += f
  h[6] += g
  h[7] += s
}

///|
fn narrow_write(s : Narrow, msg : BytesView) -> Unit {
  s.n += msg.length().to_uint64()
  let mut at = 0
  while at < msg.length() {
    let room = 64 - s.used
    let left = msg.length() - at
    let take = if room < left { room } else { left }
    for i in 0..<take {
      s.buf[s.used + i] = msg[at + i]
    }
    s.used += take
    at += take
    if s.used == 64 {
      narrow_block(s.h, s.buf, 0)
      s.used = 0
    }
  }
}

///|
/// Pad and read, on a copy: a caller may keep writing after reading a digest,
/// which is what makes a hasher usable as a running checksum.
fn narrow_finish(s : Narrow, out : Int) -> Bytes {
  let h : FixedArray[UInt] = FixedArray::make(8, 0U)
  for i in 0..<8 {
    h[i] = s.h[i]
  }
  let pad : FixedArray[Byte] = FixedArray::make(128, b'\x00')
  for i in 0..<s.used {
    pad[i] = s.buf[i]
  }
  pad[s.used] = b'\x80'
  let total = if s.used < 56 { 64 } else { 128 }
  let bits = s.n * 8UL
  for i in 0..<8 {
    pad[total - 1 - i] = ((bits >> (i * 8)) & 0xFFUL).to_byte()
  }
  for off = 0; off < total; off = off + 64 {
    narrow_block(h, pad, off)
  }
  let digest : Array[Byte] = []
  for i in 0..<((out + 3) / 4) {
    for k = 3; k >= 0; k = k - 1 {
      digest.push(((h[i] >> (k * 8)) & 0xFFU).to_byte())
    }
  }
  Bytes::from_array(digest[0:out].to_owned())
}

// ---------------------------------------------------------------- 64-bit half

///|
/// The 80 round constants: the first 64 bits of the fractional parts of the cube
/// roots of the first 80 primes (FIPS 180-4 §4.2.3).
let k64 : FixedArray[UInt64] = [
  0x428A2F98D728AE22UL, 0x7137449123EF65CDUL, 0xB5C0FBCFEC4D3B2FUL, 0xE9B5DBA58189DBBCUL,
  0x3956C25BF348B538UL, 0x59F111F1B605D019UL, 0x923F82A4AF194F9BUL, 0xAB1C5ED5DA6D8118UL,
  0xD807AA98A3030242UL, 0x12835B0145706FBEUL, 0x243185BE4EE4B28CUL, 0x550C7DC3D5FFB4E2UL,
  0x72BE5D74F27B896FUL, 0x80DEB1FE3B1696B1UL, 0x9BDC06A725C71235UL, 0xC19BF174CF692694UL,
  0xE49B69C19EF14AD2UL, 0xEFBE4786384F25E3UL, 0x0FC19DC68B8CD5B5UL, 0x240CA1CC77AC9C65UL,
  0x2DE92C6F592B0275UL, 0x4A7484AA6EA6E483UL, 0x5CB0A9DCBD41FBD4UL, 0x76F988DA831153B5UL,
  0x983E5152EE66DFABUL, 0xA831C66D2DB43210UL, 0xB00327C898FB213FUL, 0xBF597FC7BEEF0EE4UL,
  0xC6E00BF33DA88FC2UL, 0xD5A79147930AA725UL, 0x06CA6351E003826FUL, 0x142929670A0E6E70UL,
  0x27B70A8546D22FFCUL, 0x2E1B21385C26C926UL, 0x4D2C6DFC5AC42AEDUL, 0x53380D139D95B3DFUL,
  0x650A73548BAF63DEUL, 0x766A0ABB3C77B2A8UL, 0x81C2C92E47EDAEE6UL, 0x92722C851482353BUL,
  0xA2BFE8A14CF10364UL, 0xA81A664BBC423001UL, 0xC24B8B70D0F89791UL, 0xC76C51A30654BE30UL,
  0xD192E819D6EF5218UL, 0xD69906245565A910UL, 0xF40E35855771202AUL, 0x106AA07032BBD1B8UL,
  0x19A4C116B8D2D0C8UL, 0x1E376C085141AB53UL, 0x2748774CDF8EEB99UL, 0x34B0BCB5E19B48A8UL,
  0x391C0CB3C5C95A63UL, 0x4ED8AA4AE3418ACBUL, 0x5B9CCA4F7763E373UL, 0x682E6FF3D6B2B8A3UL,
  0x748F82EE5DEFB2FCUL, 0x78A5636F43172F60UL, 0x84C87814A1F0AB72UL, 0x8CC702081A6439ECUL,
  0x90BEFFFA23631E28UL, 0xA4506CEBDE82BDE9UL, 0xBEF9A3F7B2C67915UL, 0xC67178F2E372532BUL,
  0xCA273ECEEA26619CUL, 0xD186B8C721C0C207UL, 0xEADA7DD6CDE0EB1EUL, 0xF57D4F7FEE6ED178UL,
  0x06F067AA72176FBAUL, 0x0A637DC5A2C898A6UL, 0x113F9804BEF90DAEUL, 0x1B710B35131C471BUL,
  0x28DB77F523047D84UL, 0x32CAAB7B40C72493UL, 0x3C9EBE0A15C9BEBCUL, 0x431D67C49C100D4CUL,
  0x4CC5D4BECB3E42B6UL, 0x597F299CFC657E2AUL, 0x5FCB6FAB3AD6FAECUL, 0x6C44198C4A475817UL,
]

///|
let iv512 : FixedArray[UInt64] = [
  0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
  0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL,
]

///|
let iv384 : FixedArray[UInt64] = [
  0xCBBB9D5DC1059ED8UL, 0x629A292A367CD507UL, 0x9159015A3070DD17UL, 0x152FECD8F70E5939UL,
  0x67332667FFC00B31UL, 0x8EB44A8768581511UL, 0xDB0C2E0D64F98FA7UL, 0x47B5481DBEFA4FA4UL,
]

///|
/// The SHA-512/t vectors are SHA-512's own, run over the string "SHA-512/224"
/// with every IV word complemented (FIPS 180-4 §5.3.6).
let iv512_224 : FixedArray[UInt64] = [
  0x8C3D37C819544DA2UL, 0x73E1996689DCD4D6UL, 0x1DFAB7AE32FF9C82UL, 0x679DD514582F9FCFUL,
  0x0F6D2B697BD44DA8UL, 0x77E36F7304C48942UL, 0x3F9D85A86A1D36C8UL, 0x1112E6AD91D692A1UL,
]

///|
let iv512_256 : FixedArray[UInt64] = [
  0x22312194FC2BF72CUL, 0x9F555FA3C84C64C2UL, 0x2393B86B6F53B151UL, 0x963877195940EABDUL,
  0x96283EE2A88EFFE3UL, 0xBE5E1E2553863992UL, 0x2B0199FC2C85B8AAUL, 0x0EB72DDC81C52CA2UL,
]

///|
fn rotr64(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn wide_block(
  h : FixedArray[UInt64],
  data : FixedArray[Byte],
  off : Int,
) -> Unit {
  let w : FixedArray[UInt64] = FixedArray::make(80, 0UL)
  for i in 0..<16 {
    let j = off + i * 8
    let mut v = 0UL
    for b in 0..<8 {
      v = (v << 8) | data[j + b].to_int().to_uint64()
    }
    w[i] = v
  }
  for i in 16..<80 {
    let s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
    let s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }
  let mut a = h[0]
  let mut b = h[1]
  let mut c = h[2]
  let mut d = h[3]
  let mut e = h[4]
  let mut f = h[5]
  let mut g = h[6]
  let mut s = h[7]
  for i in 0..<80 {
    let s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
    let ch = (e & f) ^ (e.lnot() & g)
    let t1 = s + s1 + ch + k64[i] + w[i]
    let s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let t2 = s0 + maj
    s = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }
  h[0] += a
  h[1] += b
  h[2] += c
  h[3] += d
  h[4] += e
  h[5] += f
  h[6] += g
  h[7] += s
}

///|
fn wide_write(s : Wide, msg : BytesView) -> Unit {
  let before = s.lo
  s.lo += msg.length().to_uint64()
  if s.lo < before {
    s.hi += 1
  }
  let mut at = 0
  while at < msg.length() {
    let room = 128 - s.used
    let left = msg.length() - at
    let take = if room < left { room } else { left }
    for i in 0..<take {
      s.buf[s.used + i] = msg[at + i]
    }
    s.used += take
    at += take
    if s.used == 128 {
      wide_block(s.h, s.buf, 0)
      s.used = 0
    }
  }
}

///|
fn wide_finish(s : Wide, out : Int) -> Bytes {
  let h : FixedArray[UInt64] = FixedArray::make(8, 0UL)
  for i in 0..<8 {
    h[i] = s.h[i]
  }
  let pad : FixedArray[Byte] = FixedArray::make(256, b'\x00')
  for i in 0..<s.used {
    pad[i] = s.buf[i]
  }
  pad[s.used] = b'\x80'
  let total = if s.used < 112 { 128 } else { 256 }
  // The length is 128 bits wide, so it carries out of `lo` into `hi` — which a
  // 2 EiB message would need and nothing else ever will.
  let low = s.lo << 3
  let high = (s.hi << 3) | (s.lo >> 61)
  for i in 0..<8 {
    pad[total - 1 - i] = ((low >> (i * 8)) & 0xFFUL).to_byte()
    pad[total - 9 - i] = ((high >> (i * 8)) & 0xFFUL).to_byte()
  }
  for off = 0; off < total; off = off + 128 {
    wide_block(h, pad, off)
  }
  let digest : Array[Byte] = []
  for i in 0..<((out + 7) / 8) {
    for k = 7; k >= 0; k = k - 1 {
      digest.push(((h[i] >> (k * 8)) & 0xFFUL).to_byte())
    }
  }
  Bytes::from_array(digest[0:out].to_owned())
}
