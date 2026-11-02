// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// NIST's ACVP vectors for ML-KEM, from ACVP-Server's ML-KEM-keyGen-FIPS203 and
// ML-KEM-encapDecap-FIPS203. The tables in `vectors_*_test.mbt` are generated;
// these are the drivers. Everything goes through the public interface, so a
// vector that passes here also says the interface can express the standard.

///|
fn check_keygen(
  kind : @mlkem.Kind,
  cases : Array[(String, String, String, String)],
) -> Unit raise {
  for (d, z, ek, dk) in cases {
    let key = @mlkem.PrivateKey::from_seed(
      kind~,
      @base16.decode_lossy(d + z)[:],
    )
    assert_eq(@base16.encode(key.encapsulation_key().bytes()), ek)
    assert_eq(@base16.encode(key.bytes()), dk)
  }
}

///|
test "ACVP: key generation derives the standard's pairs" {
  check_keygen(@mlkem.K512, keygen_k512)
  check_keygen(@mlkem.K768, keygen_k768)
  check_keygen(@mlkem.K1024, keygen_k1024)
}

///|
test "ACVP: encapsulation reproduces ciphertext and secret" {
  let sets : Array[(@mlkem.Kind, Array[(String, String, String, String)])] = [
    (@mlkem.K512, encapsulation_k512),
    (@mlkem.K768, encapsulation_k768),
    (@mlkem.K1024, encapsulation_k1024),
  ]
  for set, (kind, cases) in sets {
    for i, (ek, m, c, k) in cases {
      let key = @mlkem.PublicKey::new(kind~, @base16.decode_lossy(ek)[:])
      let out = key.encapsulate_with(@base16.decode_lossy(m)[:])
      assert_eq(@base16.encode(out.ciphertext), c, msg="set \{set}, case \{i}")
      assert_eq(@base16.encode(out.secret), k, msg="set \{set}, case \{i}")
    }
  }
}

///|
test "ACVP: decapsulation recovers the secret from the given key" {
  let sets : Array[(@mlkem.Kind, Array[(String, String, String)])] = [
    (@mlkem.K512, decapsulation_k512),
    (@mlkem.K768, decapsulation_k768),
    (@mlkem.K1024, decapsulation_k1024),
  ]
  for set, (kind, cases) in sets {
    for i, (dk, c, k) in cases {
      let key = @mlkem.PrivateKey::new(kind~, @base16.decode_lossy(dk)[:])
      let got = key.decapsulate(@base16.decode_lossy(c)[:])
      assert_eq(@base16.encode(got), k, msg="set \{set}, case \{i}")
    }
  }
}

///|
test "ACVP: the encapsulation key check accepts and refuses as it should" {
  let sets : Array[(@mlkem.Kind, Array[(String, Bool)])] = [
    (@mlkem.K512, encapsulation_key_check_k512),
    (@mlkem.K768, encapsulation_key_check_k768),
    (@mlkem.K1024, encapsulation_key_check_k1024),
  ]
  let mut accepted = 0
  let mut refused = 0
  for (kind, cases) in sets {
    for (ek, pass) in cases {
      let got = Some(@mlkem.PublicKey::new(kind~, @base16.decode_lossy(ek)[:])) catch {
        _ => None
      }
      match (pass, got) {
        (true, Some(_)) => accepted += 1
        (false, None) => refused += 1
        (true, None) => fail("a valid encapsulation key was refused")
        (false, Some(_)) => fail("an invalid encapsulation key was accepted")
      }
    }
  }
  assert_true(accepted > 0 && refused > 0)
}

///|
test "ACVP: the decapsulation key check accepts and refuses as it should" {
  let sets : Array[(@mlkem.Kind, Array[(String, Bool)])] = [
    (@mlkem.K512, decapsulation_key_check_k512),
    (@mlkem.K768, decapsulation_key_check_k768),
    (@mlkem.K1024, decapsulation_key_check_k1024),
  ]
  let mut accepted = 0
  let mut refused = 0
  for (kind, cases) in sets {
    for (dk, pass) in cases {
      let got = Some(@mlkem.PrivateKey::new(kind~, @base16.decode_lossy(dk)[:])) catch {
        _ => None
      }
      match (pass, got) {
        (true, Some(_)) => accepted += 1
        (false, None) => refused += 1
        (true, None) => fail("a valid decapsulation key was refused")
        (false, Some(_)) => fail("an invalid decapsulation key was accepted")
      }
    }
  }
  assert_true(accepted > 0 && refused > 0)
}
