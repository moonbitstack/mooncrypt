// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// Key generation, the signing loop and verification: FIPS 204 Algorithms 6, 7
// and 8. The arithmetic they call is in `poly.mbt`, the samplers in
// `sample.mbt`, the byte layouts in `encode.mbt`.

///|
/// Copy one polynomial into another array, since the transform works in place
/// and some of its inputs are kept.
fn clone(r : Poly) -> Poly {
  let out = poly()
  for i in 0..<degree {
    out[i] = r[i]
  }
  out
}

///|
/// ML-DSA.KeyGen (FIPS 204 Algorithm 6). `xi` is the 32-byte seed.
fn keygen_internal(kind : Kind, xi : BytesView) -> (Bytes, Bytes) {
  // The rank and the column count are hashed in, so a seed for one parameter
  // set cannot be read as a seed for another.
  let seed = @sha3.shake256(
    concat([xi, Bytes::from_array([kind.k().to_byte(), kind.l().to_byte()])]),
    128,
  )
  // rho' is sixty-four bytes: it seeds the whole secret, both vectors, and is
  // not the same width as the other two.
  let rho = seed[0:32]
  let rho_prime = seed[32:96]
  let key = seed[96:128]
  let a = expand_a(rho, kind)
  let (s1, s2) = expand_s(rho_prime, kind)
  let s1h = polys(kind.l())
  for i in 0..<kind.l() {
    s1h[i] = clone(s1[i])
    ntt(s1h[i])
  }
  let t = polys(kind.k())
  for i in 0..<kind.k() {
    for j in 0..<kind.l() {
      pointwise_add(t[i], a[i * kind.l() + j], s1h[j])
    }
    inv_ntt(t[i])
    add_assign(t[i], s2[i])
  }
  let t1 = polys(kind.k())
  let t0 = polys(kind.k())
  for i in 0..<kind.k() {
    for j in 0..<degree {
      let (hi, lo) = power2round(freeze(t[i][j]))
      t1[i][j] = hi
      t0[i][j] = lo
    }
  }
  let pk = public_bytes(kind, rho, t1)
  let tr = @sha3.shake256(pk, 64)
  let sk = secret_bytes(kind, rho, key, tr, s1, s2, t0)
  (pk, sk)
}

///|
/// Build the in-memory key from its bytes and its public half, expanding the
/// three vectors into the transform domain once.
fn key_of(kind : Kind, sk : Bytes, pk : Bytes) -> PrivateKey {
  let (rho, key, tr, s1, s2, t0) = secret_parse(kind, sk[:])
  for i in 0..<kind.l() {
    ntt(s1[i])
  }
  for i in 0..<kind.k() {
    ntt(s2[i])
    ntt(t0[i])
  }
  { kind, raw: sk, public: pk, rho, key, tr, s1, s2, t0, }
}

///|
/// The public key a private key implies: rerun the key generation's matrix
/// product without the noise.
fn public_of_private(kind : Kind, sk : BytesView) -> (Array[Poly], Bytes) {
  let (rho, _, _, s1, s2, t0) = secret_parse(kind, sk)
  ignore(t0)
  let a = expand_a(rho[:], kind)
  let s1h = polys(kind.l())
  for i in 0..<kind.l() {
    s1h[i] = clone(s1[i])
    ntt(s1h[i])
  }
  let t1 = polys(kind.k())
  for i in 0..<kind.k() {
    for j in 0..<kind.l() {
      pointwise_add(t1[i], a[i * kind.l() + j], s1h[j])
    }
    inv_ntt(t1[i])
    // t = A s1 + s2, and the published half is its rounding; s2 is in the
    // private key, so nothing has to be inferred.
    for j in 0..<degree {
      let t = freeze(t1[i][j]) + s2[i][j]
      t1[i][j] = power2round(freeze(t)).0
    }
  }
  (t1, public_bytes(kind, rho[:], t1))
}

///|
/// One signing attempt chain: FIPS 204 Algorithm 7.
///
/// `mu` is the message representative and `rnd` the 32 bytes the hedged variant
/// mixes in; the loop restarts with a fresh mask whenever a bound is crossed,
/// which is expected to happen a handful of times.
fn sign_inner(key : PrivateKey, mu : Bytes, rnd : BytesView) -> Bytes {
  let kind = key.kind
  let gamma1 = kind.gamma1()
  let gamma2 = kind.gamma2()
  let beta = kind.beta()
  let rho_pp = @sha3.shake256(concat([key.key, rnd, mu]), 64)
  let a = expand_a(key.rho[:], kind)
  let mut kappa = 0
  let mut attempt = 0
  while attempt < 1000 {
    attempt += 1
    let y = expand_mask(rho_pp, kappa, kind)
    let yh = polys(kind.l())
    let w = polys(kind.k())
    for i in 0..<kind.l() {
      yh[i] = clone(y[i])
      ntt(yh[i])
    }
    for i in 0..<kind.k() {
      for j in 0..<kind.l() {
        pointwise_add(w[i], a[i * kind.l() + j], yh[j])
      }
      inv_ntt(w[i])
    }
    let w1 = polys(kind.k())
    for i in 0..<kind.k() {
      w1[i] = high_bits(w[i], gamma2)
    }
    let c_tilde = @sha3.shake256(
      concat([mu, high_bits_bytes(kind, w1)]),
      kind.challenge(),
    )
    let c = sample_in_ball(c_tilde, kind)
    let ch = clone(c)
    ntt(ch)
    let z = polys(kind.l())
    for i in 0..<kind.l() {
      let cs = pointwise(ch, key.s1[i])
      inv_ntt(cs)
      for j in 0..<degree {
        cs[j] = freeze(y[i][j] + cs[j])
      }
      z[i] = cs
    }
    let r0 = polys(kind.k())
    for i in 0..<kind.k() {
      let cs = pointwise(ch, key.s2[i])
      inv_ntt(cs)
      for j in 0..<degree {
        cs[j] = freeze(w[i][j] - cs[j])
      }
      r0[i] = cs
    }
    let mut good = true
    for i in 0..<kind.l() {
      if max_abs(z[i]) >= gamma1 - beta {
        good = false
      }
    }
    if good {
      for i in 0..<kind.k() {
        if max_abs(low_bits(r0[i], gamma2)) >= gamma2 - beta {
          good = false
        }
      }
    }
    if good {
      let ct0 = polys(kind.k())
      let mut small = true
      for i in 0..<kind.k() {
        ct0[i] = pointwise(ch, key.t0[i])
        inv_ntt(ct0[i])
        if max_abs(ct0[i]) >= gamma2 {
          small = false
        }
      }
      if small {
        let hint = polys(kind.k())
        let mut ones = 0
        for i in 0..<kind.k() {
          let neg = poly()
          let shifted = poly()
          for j in 0..<degree {
            neg[j] = -ct0[i][j]
            shifted[j] = r0[i][j] + ct0[i][j]
          }
          hint[i] = make_hint(neg, shifted, gamma2)
          ones += count_nonzero(hint[i])
        }
        if ones <= kind.omega() {
          return signature_bytes(kind, c_tilde, z, hint)
        }
      }
    }
    kappa += kind.l()
  }
  abort("mldsa: no signature after a thousand attempts")
}

///|
/// ML-DSA.Verify (FIPS 204 Algorithm 8) given the message representative, which
/// is the standard's internal interface: a caller that already holds `mu` — a
/// hardware signer, or a protocol that composes the hash itself — can verify
/// without the message.
fn verify_mu(
  key : PublicKey,
  mu : Bytes,
  sig : BytesView,
) -> Bool raise @spec.Broken {
  let kind = key.kind
  guard sig.length() == kind.signature() else {
    raise @spec.Size(want=kind.signature(), got=sig.length())
  }
  let (rho, t1) = public_parse(kind, key.raw[:])
  let (c_tilde, z, hint) = signature_parse(kind, sig)
  let gamma1 = kind.gamma1()
  let gamma2 = kind.gamma2()
  // A `z` outside the mask range would let a forger shift the challenge, so it
  // is the first thing refused.
  for i in 0..<kind.l() {
    if max_abs(z[i]) >= gamma1 - kind.beta() {
      return false
    }
  }
  let c = sample_in_ball(c_tilde, kind)
  let ch = clone(c)
  ntt(ch)
  let a = expand_a(rho[:], kind)
  let zh = polys(kind.l())
  let t1h = polys(kind.k())
  for i in 0..<kind.l() {
    zh[i] = clone(z[i])
    ntt(zh[i])
  }
  for i in 0..<kind.k() {
    for j in 0..<degree {
      t1h[i][j] = t1[i][j] << dropped
    }
    ntt(t1h[i])
  }
  let w = polys(kind.k())
  for i in 0..<kind.k() {
    for j in 0..<kind.l() {
      pointwise_add(w[i], a[i * kind.l() + j], zh[j])
    }
    let ct1 = pointwise(ch, t1h[i])
    sub_assign(w[i], ct1)
    inv_ntt(w[i])
  }
  let w1 = polys(kind.k())
  for i in 0..<kind.k() {
    for j in 0..<degree {
      w1[i][j] = use_hint(w[i][j], hint[i][j], gamma2)
    }
  }
  let got = @sha3.shake256(
    concat([mu, high_bits_bytes(kind, w1)]),
    kind.challenge(),
  )
  @spec.eq(got, c_tilde)
}

///|
/// ML-DSA.Verify on a message: the representative is computed here and the rest
/// of the algorithm is shared with [`verify_mu`].
fn verify_inner(
  key : PublicKey,
  msg : BytesView,
  sig : BytesView,
  context : BytesView,
  prehash : PreHash?,
) -> Bool raise @spec.Broken {
  guard sig.length() == key.kind.signature() else {
    raise @spec.Size(want=key.kind.signature(), got=sig.length())
  }
  let mu = message_representative(
    @sha3.shake256(key.raw, 64),
    context,
    msg,
    prehash,
  )
  verify_mu(key, mu, sig)
}

///|
/// Sign a message representative directly, the internal interface of FIPS 204.
fn sign_mu(key : PrivateKey, mu : Bytes) -> Bytes {
  sign_inner(key, mu, Bytes::makei(32, fn(_) { b'\x00' }))
}
