// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// ACVP CTR-DRBG: the twelve AES groups of NIST's ctrDRBG-1.0 vectors — three
// key lengths, the derivation function on and off, prediction resistance on and
// off. The tables live in `vectors_ctr_test.mbt`. Each case drives the
// operations the standard names and compares the final generate's output, which
// is what the JSON's `returnedBits` holds.

///|
fn drbg_kind(tag : String) -> @drbg.Kind {
  match tag {
    "Aes128" => @drbg.Aes128
    "Aes192" => @drbg.Aes192
    _ => @drbg.Aes256
  }
}

///|
fn drbg_unhex(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
/// Prediction resistance: each generate is preceded by a reseed whose entropy
/// comes from that same entry, and the generate carries no additional input.
test "ACVP: CTR-DRBG with prediction resistance" {
  for
    (tag, derivation, entropy, nonce, perso, e0, a0, e1, a1, expected) in ctr_pr {
    let d = @drbg.CtrDrbg::new(
      entropy=drbg_unhex(entropy)[:],
      nonce=drbg_unhex(nonce)[:],
      personalization=drbg_unhex(perso)[:],
      kind=drbg_kind(tag),
      derivation~,
    )
    let n = drbg_unhex(expected).length()
    d.reseed(entropy=drbg_unhex(e0)[:], additional=drbg_unhex(a0)[:])
    ignore(d.generate_with(n, additional=b""[:]))
    d.reseed(entropy=drbg_unhex(e1)[:], additional=drbg_unhex(a1)[:])
    let out = d.generate_with(n, additional=b""[:])
    assert_eq(
      @base16.encode(out),
      expected,
      msg="ACVP \{tag} derivation=\{derivation}",
    )
  }
}

///|
/// An explicit reseed followed by two generates that carry additional input.
test "ACVP: CTR-DRBG with an explicit reseed" {
  for
    (tag, derivation, entropy, nonce, perso, re_e, re_a, a1, a2, expected) in ctr_nopr {
    let d = @drbg.CtrDrbg::new(
      entropy=drbg_unhex(entropy)[:],
      nonce=drbg_unhex(nonce)[:],
      personalization=drbg_unhex(perso)[:],
      kind=drbg_kind(tag),
      derivation~,
    )
    let n = drbg_unhex(expected).length()
    d.reseed(entropy=drbg_unhex(re_e)[:], additional=drbg_unhex(re_a)[:])
    ignore(d.generate_with(n, additional=drbg_unhex(a1)[:]))
    let out = d.generate_with(n, additional=drbg_unhex(a2)[:])
    assert_eq(
      @base16.encode(out),
      expected,
      msg="ACVP \{tag} derivation=\{derivation}",
    )
  }
}

///|
test "CTR-DRBG reports the key length it was built on" {
  assert_eq(
    @drbg.CtrDrbg::new(
      entropy=b""[:],
      nonce=b""[:],
      personalization=b""[:],
      kind=@drbg.Aes128,
    ).kind(),
    @drbg.Aes128,
  )
  assert_eq(
    @drbg.CtrDrbg::new(
      entropy=b""[:],
      nonce=b""[:],
      personalization=b""[:],
      kind=@drbg.Aes192,
    ).kind(),
    @drbg.Aes192,
  )
  assert_eq(
    @drbg.CtrDrbg::new(entropy=b""[:], nonce=b""[:], personalization=b""[:]).kind(),
    @drbg.Aes256,
  )
}
