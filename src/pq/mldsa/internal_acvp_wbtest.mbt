// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// The internal interface of FIPS 204, which ACVP calls `internal`: a signing
// or verification that starts from the message representative `mu` instead of
// from a message. It is not part of the public surface — a caller that
// composes `mu` itself takes over the domain separation the standard puts in
// front of the message — so the vectors that cover it are here, on the
// package's own functions.

///|
fn check_internal_siggen(
  kind : Kind,
  cases : Array[(String, String, String, String, String)],
) -> Unit raise {
  for (tag, sk, input, rnd, sig) in cases {
    let key = PrivateKey::new(kind~, @base16.decode_lossy(sk)[:])
    let mu = if tag == "mu" {
      @base16.decode_lossy(input)
    } else {
      // The internal interface over a message hashes it against `tr` with no
      // domain byte and no context, which is what makes it a different
      // function from the external one.
      @sha3.shake256(concat([key.tr, @base16.decode_lossy(input)]), 64)
    }
    let rnd = if rnd == "" {
      Bytes::makei(32, fn(_) { b'\x00' })
    } else {
      @base16.decode_lossy(rnd)
    }
    assert_eq(@base16.encode(sign_inner(key, mu, rnd)), sig, msg="group \{tag}")
  }
}

///|
test "ACVP: signing over a representative matches the standard" {
  check_internal_siggen(D44, siggen_internal_d44)
  check_internal_siggen(D65, siggen_internal_d65)
  check_internal_siggen(D87, siggen_internal_d87)
}

///|
fn check_internal_sigver(
  kind : Kind,
  cases : Array[(String, String, String, String, Bool)],
) -> Unit raise {
  let mut accepted = 0
  let mut refused = 0
  for (tag, pk, input, sig, pass) in cases {
    let key = PublicKey::new(kind~, @base16.decode_lossy(pk)[:])
    let mu = if tag == "mu" {
      @base16.decode_lossy(input)
    } else {
      @sha3.shake256(
        concat([@sha3.shake256(key.raw, 64), @base16.decode_lossy(input)]),
        64,
      )
    }
    let got = verify_mu(key, mu, @base16.decode_lossy(sig)[:]) catch {
      _ => false
    }
    assert_eq(got, pass, msg="group \{tag}")
    if got {
      accepted += 1
    } else {
      refused += 1
    }
  }
  assert_true(accepted > 0 && refused > 0)
}

///|
test "ACVP: verification over a representative accepts and refuses as it should" {
  check_internal_sigver(D44, sigver_internal_d44)
  check_internal_sigver(D65, sigver_internal_d65)
  check_internal_sigver(D87, sigver_internal_d87)
}
