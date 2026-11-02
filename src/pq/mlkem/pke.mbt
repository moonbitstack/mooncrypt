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
/// A seed followed by one counter byte, the shape every `PRF` and every matrix
/// entry in FIPS 203 absorbs.
fn with_byte(seed : BytesView, n : Byte) -> Bytes {
  let out = Array::make(seed.length() + 1, b'\x00')
  for i in 0..<seed.length() {
    out[i] = seed[i]
  }
  out[seed.length()] = n
  Bytes::from_array(out)
}

///|
/// The matrix `A` of FIPS 203 Algorithm 13, expanded from the public seed.
///
/// Row `i`, column `j` absorbs `rho || j || i`. The entries are held in row
/// order and encryption walks them by column, so the one array serves both
/// directions and the two can never disagree about which stream is which.
fn gen_matrix(rho : BytesView, k : Int32) -> Array[Poly] {
  let m : Array[Poly] = []
  for i in 0..<k {
    for j in 0..<k {
      m.push(
        sample_ntt(concat([rho, Bytes::from_array([j.to_byte(), i.to_byte()])])),
      )
    }
  }
  m
}

///|
fn polys(n : Int32) -> Array[Poly] {
  let out : Array[Poly] = []
  for _ in 0..<n {
    out.push(poly())
  }
  out
}

///|
/// `PRF_eta(sigma, n)` (FIPS 203 §4.1): SHAKE256 of the seed and one counter
/// byte, 64 eta bytes of it, read four bits at a time.
fn prf(sigma : BytesView, n : Int32, eta : Int32) -> Poly {
  sample_cbd(with_byte(sigma, n.to_byte()), eta)
}

///|
/// K-PKE.KeyGen (FIPS 203 Algorithm 13). `d` is the 32-byte seed; the third
/// component is `rho`, the public seed the matrix expands from.
fn pke_keygen(kind : Kind, d : BytesView) -> (Array[Poly], Array[Poly], Bytes) {
  let k = kind.k()
  let eta1 = kind.eta1()
  // G(d || k): the rank is hashed in so a 512 seed cannot be read as the seed
  // of a 768 key.
  let seed = @sha3.hash(
    concat([d, Bytes::from_array([k.to_byte()])]),
    kind=@sha3.Sha3_512,
  )
  let rho = seed[0:32]
  let sigma = seed[32:64]
  let a = gen_matrix(rho, k)
  let s = polys(k)
  let e = polys(k)
  for i in 0..<k {
    s[i] = prf(sigma, i, eta1)
    // Both the secret and the error are wide (FIPS 203 Algorithm 13); only the
    // encryption noise narrows to eta_2.
    e[i] = prf(sigma, k + i, eta1)
    ntt(s[i])
    ntt(e[i])
  }
  let t = polys(k)
  for i in 0..<k {
    for j in 0..<k {
      basemul_add(t[i], a[i * k + j], s[j])
    }
    to_mont(t[i])
    add_assign(t[i], e[i])
    reduce_poly(t[i])
  }
  (t, s, rho.to_owned())
}

///|
/// K-PKE.Encrypt (FIPS 203 Algorithm 14). `message` is the 32-byte plaintext of
/// the inner scheme, which ML-KEM fills with the seed of the shared secret.
fn pke_encrypt(
  kind : Kind,
  ek : BytesView,
  message : BytesView,
  r : BytesView,
) -> Bytes {
  let k = kind.k()
  let eta1 = kind.eta1()
  let du = kind.du()
  let dv = kind.dv()
  let t = polys(k)
  for i in 0..<k {
    t[i] = unpack(ek[i * 384:(i + 1) * 384], 12)
  }
  let rho = ek[384 * k:384 * k + 32]
  let a = gen_matrix(rho, k)
  let y = polys(k)
  let e1 = polys(k)
  for i in 0..<k {
    y[i] = prf(r, i, eta1)
    e1[i] = prf(r, k + i, 2)
    ntt(y[i])
  }
  let e2 = prf(r, 2 * k, 2)
  let u = polys(k)
  let v = poly()
  for i in 0..<k {
    for j in 0..<k {
      // A transposed: row i of A^T is column i of A.
      basemul_add(u[i], a[j * k + i], y[j])
    }
  }
  for j in 0..<k {
    basemul_add(v, t[j], y[j])
  }
  let m = decompress_poly(message, 1)
  let c1 : Array[BytesView] = []
  for i in 0..<k {
    inv_ntt(u[i])
    add_assign(u[i], e1[i])
    c1.push(compress_poly(u[i], du))
  }
  inv_ntt(v)
  add_assign(v, e2)
  add_assign(v, m)
  c1.push(compress_poly(v, dv))
  concat(c1)
}

///|
/// K-PKE.Decrypt (FIPS 203 Algorithm 15).
fn pke_decrypt(kind : Kind, dk : BytesView, c : BytesView) -> Bytes {
  let k = kind.k()
  let du = kind.du()
  let dv = kind.dv()
  let u = polys(k)
  for i in 0..<k {
    u[i] = decompress_poly(c[i * 32 * du:(i + 1) * 32 * du], du)
    ntt(u[i])
  }
  let at = 32 * du * k
  let v = decompress_poly(c[at:at + 32 * dv], dv)
  let w = poly()
  for j in 0..<k {
    let s = unpack(dk[j * 384:(j + 1) * 384], 12)
    basemul_add(w, s, u[j])
  }
  inv_ntt(w)
  compress_poly(sub(v, w), 1)
}
