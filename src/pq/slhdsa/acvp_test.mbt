// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// NIST's ACVP vectors for SLH-DSA, from ACVP-Server's SLH-DSA-keyGen-FIPS205,
// SLH-DSA-sigGen-FIPS205 and SLH-DSA-sigVer-FIPS205.
//
// Key generation is replayed in full — 120 cases, ten per parameter set — and
// signing once per set: a signature is up to fifty kilobytes and the slow sets
// take seconds each, so the sample covers every set rather than repeating one.

///|
fn check_keygen(
  kind : @slhdsa.Kind,
  cases : Array[(String, String, String, String, String)],
) -> Unit raise {
  for (sk_seed, sk_prf, pk_seed, pk, sk) in cases {
    let key = @slhdsa.PrivateKey::from_seed(
      kind~,
      @base16.decode_lossy(sk_seed + sk_prf + pk_seed)[:],
    )
    assert_eq(@base16.encode(key.public_key().bytes()), pk)
    assert_eq(@base16.encode(key.bytes()), sk)
  }
}

///|
test "ACVP: key generation derives the standard's pairs" {
  check_keygen(@slhdsa.Sha2_128s, keygen_sha2_128s)
  check_keygen(@slhdsa.Sha2_128f, keygen_sha2_128f)
  check_keygen(@slhdsa.Sha2_192s, keygen_sha2_192s)
  check_keygen(@slhdsa.Sha2_192f, keygen_sha2_192f)
  check_keygen(@slhdsa.Sha2_256s, keygen_sha2_256s)
  check_keygen(@slhdsa.Sha2_256f, keygen_sha2_256f)
  check_keygen(@slhdsa.Shake_128s, keygen_shake_128s)
  check_keygen(@slhdsa.Shake_128f, keygen_shake_128f)
  check_keygen(@slhdsa.Shake_192s, keygen_shake_192s)
  check_keygen(@slhdsa.Shake_192f, keygen_shake_192f)
  check_keygen(@slhdsa.Shake_256s, keygen_shake_256s)
  check_keygen(@slhdsa.Shake_256f, keygen_shake_256f)
}

///|
fn check_siggen(
  kind : @slhdsa.Kind,
  cases : Array[(String, String, String, String)],
) -> Unit raise {
  for (sk, message, context, sig) in cases {
    let key = @slhdsa.PrivateKey::new(kind~, @base16.decode_lossy(sk)[:])
    let got = key.sign(
      @base16.decode_lossy(message)[:],
      context=@base16.decode_lossy(context)[:],
    )
    assert_eq(@base16.encode(got), sig)
  }
}

///|
test "ACVP: signing reproduces the standard's signatures" {
  check_siggen(@slhdsa.Sha2_128s, siggen_sha2_128s)
  check_siggen(@slhdsa.Sha2_128f, siggen_sha2_128f)
  check_siggen(@slhdsa.Sha2_192s, siggen_sha2_192s)
  check_siggen(@slhdsa.Sha2_192f, siggen_sha2_192f)
  check_siggen(@slhdsa.Sha2_256s, siggen_sha2_256s)
  check_siggen(@slhdsa.Sha2_256f, siggen_sha2_256f)
  check_siggen(@slhdsa.Shake_128s, siggen_shake_128s)
  check_siggen(@slhdsa.Shake_128f, siggen_shake_128f)
  check_siggen(@slhdsa.Shake_192s, siggen_shake_192s)
  check_siggen(@slhdsa.Shake_192f, siggen_shake_192f)
  check_siggen(@slhdsa.Shake_256s, siggen_shake_256s)
  check_siggen(@slhdsa.Shake_256f, siggen_shake_256f)
}

///|
fn check_sigver(
  kind : @slhdsa.Kind,
  cases : Array[(String, String, String, String, Bool)],
) -> Unit raise {
  for (pk, message, context, sig, pass) in cases {
    let key = @slhdsa.PublicKey::new(kind~, @base16.decode_lossy(pk)[:])
    let got = key.verify(
      @base16.decode_lossy(message)[:],
      @base16.decode_lossy(sig)[:],
      context=@base16.decode_lossy(context)[:],
    )
    assert_eq(got, pass)
  }
}

///|
test "ACVP: verification accepts and refuses as it should" {
  check_sigver(@slhdsa.Sha2_128s, sigver_sha2_128s)
  check_sigver(@slhdsa.Sha2_128f, sigver_sha2_128f)
  check_sigver(@slhdsa.Sha2_192s, sigver_sha2_192s)
  check_sigver(@slhdsa.Sha2_192f, sigver_sha2_192f)
  check_sigver(@slhdsa.Sha2_256s, sigver_sha2_256s)
  check_sigver(@slhdsa.Sha2_256f, sigver_sha2_256f)
  check_sigver(@slhdsa.Shake_128s, sigver_shake_128s)
  check_sigver(@slhdsa.Shake_128f, sigver_shake_128f)
  check_sigver(@slhdsa.Shake_192s, sigver_shake_192s)
  check_sigver(@slhdsa.Shake_192f, sigver_shake_192f)
  check_sigver(@slhdsa.Shake_256s, sigver_shake_256s)
  check_sigver(@slhdsa.Shake_256f, sigver_shake_256f)
}
