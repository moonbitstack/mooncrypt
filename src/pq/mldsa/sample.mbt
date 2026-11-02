// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Concatenate byte strings in order, which every hash input here is.
fn concat(parts : Array[BytesView]) -> Bytes {
  let out : Array[Byte] = []
  for part in parts {
    for i in 0..<part.length() {
      out.push(part[i])
    }
  }
  Bytes::from_array(out)
}

///|
/// A seed followed by a counter, little-endian, which is how the samplers
/// distinguish one polynomial from the next.
fn with_u16(seed : BytesView, n : Int32) -> Bytes {
  let out = Array::make(seed.length() + 2, b'\x00')
  for i in 0..<seed.length() {
    out[i] = seed[i]
  }
  out[seed.length()] = (n & 0xFF).to_byte()
  out[seed.length() + 1] = ((n >> 8) & 0xFF).to_byte()
  Bytes::from_array(out)
}

///|
/// A seed followed by two index bytes, which is what the matrix expansion
/// absorbs to tell one entry from another.
fn with_pair(seed : BytesView, a : Int32, b : Int32) -> Bytes {
  let out = Array::make(seed.length() + 2, b'\x00')
  for i in 0..<seed.length() {
    out[i] = seed[i]
  }
  out[seed.length()] = a.to_byte()
  out[seed.length() + 1] = b.to_byte()
  Bytes::from_array(out)
}

///|
/// `RejNTTPoly` (FIPS 204 Algorithm 30): rejection sampling of a uniform
/// coefficient stream, 23 bits at a time, keeping what is below `q`.
///
/// The stream is read three bytes at a time because a rejected value must not
/// advance it by a whole extra triple — SHAKE's squeeze is a stream, so three
/// bytes at a time says exactly that.
fn rej_ntt_poly(seed : BytesView) -> Poly {
  let r = poly()
  let x = @sha3.Xof::new(kind=@sha3.Shake128)
  x.absorb(seed)
  let mut i = 0
  while i < degree {
    let b = x.squeeze(3)
    let v = b[0].to_int() |
      (b[1].to_int() << 8) |
      ((b[2].to_int() & 0x7F) << 16)
    if v < q {
      r[i] = v
      i += 1
    }
  }
  r
}

///|
/// The coefficient a half-byte stands for, or `q` for a rejected one
/// (FIPS 204 Algorithm 31). `eta` is 2 or 4.
fn coef_from_half_byte(b : Int32, eta : Int32) -> Int32 {
  if eta == 2 {
    if b < 15 {
      2 - b % 5
    } else {
      q
    }
  } else if b < 9 {
    4 - b
  } else {
    q
  }
}

///|
/// `RejBoundedPoly` (FIPS 204 Algorithm 31): a coefficient of the secret, drawn
/// from the centered binomial distribution one nibble at a time, low nibble
/// first.
///
/// The rejection here is on the sampled value, not on a secret bit: the
/// standard's sampler is defined as variable-length, and hiding it would mean
/// consuming a fixed number of bytes and discarding the surplus, which the
/// distribution does not permit.
fn rej_bounded_poly(seed : BytesView, eta : Int32) -> Poly {
  let r = poly()
  let x = @sha3.Xof::new(kind=@sha3.Shake256)
  x.absorb(seed)
  let mut i = 0
  while i < degree {
    let b = x.squeeze(1)[0].to_int()
    let low = coef_from_half_byte(b & 0x0F, eta)
    if low != q {
      r[i] = low
      i += 1
    }
    if i < degree {
      let high = coef_from_half_byte(b >> 4, eta)
      if high != q {
        r[i] = high
        i += 1
      }
    }
  }
  r
}

///|
/// `ExpandA` (FIPS 204 Algorithm 32): the public matrix as `k` rows of `l`
/// entries, row `i` and column `j` absorbing `rho || j || i` — the column
/// index first, which is what makes the transpose free.
fn expand_a(rho : BytesView, kind : Kind) -> Array[Poly] {
  let k = kind.k()
  let l = kind.l()
  let out : Array[Poly] = []
  for i in 0..<k {
    for j in 0..<l {
      out.push(rej_ntt_poly(with_pair(rho, j, i)))
    }
  }
  out
}

///|
/// `ExpandS` (FIPS 204 Algorithm 33): the two secret vectors, `s1` of length
/// `l` and then `s2` of length `k`, from one seed and consecutive counters.
fn expand_s(rho : BytesView, kind : Kind) -> (Array[Poly], Array[Poly]) {
  let k = kind.k()
  let l = kind.l()
  let eta = kind.eta()
  let s1 : Array[Poly] = []
  for i in 0..<l {
    s1.push(rej_bounded_poly(with_u16(rho, i), eta))
  }
  let s2 : Array[Poly] = []
  for i in 0..<k {
    s2.push(rej_bounded_poly(with_u16(rho, l + i), eta))
  }
  (s1, s2)
}

///|
/// The number of bits one masked coefficient occupies: 18 for `gamma1 = 2^17`,
/// 20 for `2^19`.
fn mask_bits(kind : Kind) -> Int32 {
  if kind.gamma1() == 1 << 17 {
    18
  } else {
    20
  }
}

///|
/// `ExpandMask` (FIPS 204 Algorithm 34): the masking vector `y`, one
/// polynomial per counter value, each coefficient `gamma1 - t` for a packed
/// `t`, which puts it in `(gamma1, gamma1]` around zero.
fn expand_mask(rho : BytesView, kappa : Int32, kind : Kind) -> Array[Poly] {
  let bits = mask_bits(kind)
  let gamma1 = kind.gamma1()
  let out : Array[Poly] = []
  for i in 0..<kind.l() {
    let r = unpack(@sha3.shake256(with_u16(rho, kappa + i), 32 * bits), bits)
    for j in 0..<degree {
      r[j] = gamma1 - r[j]
    }
    out.push(r)
  }
  out
}

///|
/// `SampleInBall` (FIPS 204 Algorithm 29): a polynomial with `tau` coefficients
/// of `±1` at distinct positions, the challenge of the signature.
///
/// The first eight bytes of the stream are the signs, one bit each; the rest
/// picks positions by rejection, which is what keeps them distinct — a
/// repeated position would quietly turn two `±1` into one `0`.
fn sample_in_ball(rho : BytesView, kind : Kind) -> Poly {
  let r = poly()
  let x = @sha3.Xof::new(kind=@sha3.Shake256)
  x.absorb(rho)
  let first = x.squeeze(8)
  let mut signs = 0L
  for i in 0..<8 {
    signs = signs | (first[i].to_int64() << (8 * i))
  }
  for i in (degree - kind.tau())..<degree {
    let mut b = -1
    while b < 0 {
      let s = x.squeeze(1)[0].to_int()
      if s <= i {
        b = s
      }
    }
    r[i] = r[b]
    r[b] = 1 - 2 * (signs & 1).to_int()
    signs = signs >> 1
  }
  r
}
