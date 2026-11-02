// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The three FIPS post-quantum schemes, each in one run.
///
///     moon run src/examples/post-quantum
///
/// The point is not the output — every one of these is a vector already in the
/// test suite — but that they are reached the same way as everything else in
/// the library: a key from a source, an operation, and a trait where the shape
/// fits.
#coverage.skip
fn main raise {
  let seed = @base16.decode_lossy(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  // A replay source hands out the bytes it was given and then stops, so each
  // key takes a fresh one: the same key every run, without an entropy call.
  let fresh = fn() { @moonseed.Replay::new(seed) }

  // ---------------------------------------------------------------- ML-KEM
  // Key establishment: the sender encapsulates to the published key and the
  // holder of the private key recovers the same secret from the ciphertext.
  for kind in [@mlkem.K512, @mlkem.K768, @mlkem.K1024] {
    let key = @mlkem.PrivateKey::generate(fresh(), kind~)
    let label = match kind {
      @mlkem.K512 => "512 "
      @mlkem.K768 => "768 "
      _ => "1024"
    }
    let public = key.encapsulation_key()
    let sent = public.encapsulate(fresh())
    let back = key.decapsulate(sent.ciphertext[:])
    println(
      "ML-KEM \{label}  ek \{public.bytes().length()}  dk \{key.bytes().length()}  " +
      "ct \{sent.ciphertext.length()}  secret \{sent.secret.length()}  " +
      "agrees \{@spec.eq(back, sent.secret)}",
    )
  }

  // ---------------------------------------------------------------- ML-DSA
  // A signature, and the same signature refused under a different context.
  let dsa = @mldsa.PrivateKey::generate(fresh(), kind=@mldsa.D65)
  let msg = b"the quick brown fox jumps over the lazy dog"
  let sig = dsa.sign(msg[:], context=b"example"[:])
  println(
    "ML-DSA          pk \{dsa.public_key().bytes().length()}  " +
    "sig \{sig.length()}  verifies " +
    "\{dsa.public_key().verify(msg[:], sig[:], context=b"example"[:])}  " +
    "under another context " +
    "\{dsa.public_key().verify(msg[:], sig[:], context=b"another"[:])}",
  )

  // --------------------------------------------------------------- SLH-DSA
  // The hash-based scheme: the fast parameter set signs in well under a
  // second, the small ones take seconds and give a shorter signature.
  let slh = @slhdsa.PrivateKey::generate(fresh(), kind=@slhdsa.Sha2_128f)
  let slh_sig = slh.sign(msg[:])
  println(
    "SLH-DSA-128f    pk \{slh.public_key().bytes().length()}  " +
    "sig \{slh_sig.length()}  verifies " +
    "\{slh.public_key().verify(msg[:], slh_sig[:])}",
  )

  // A tampered ciphertext does not fail, it decapsulates to a secret the
  // sender never computed: FIPS 203 replaces it with one the reject seed
  // derives, so an attacker learns nothing from the difference.
  let kem = @mlkem.PrivateKey::generate(fresh())
  let sent = kem.encapsulation_key().encapsulate(fresh())
  let bent = sent.ciphertext.to_array()
  bent[0] = (bent[0].to_int() ^ 1).to_byte()
  let wrong = kem.decapsulate(Bytes::from_array(bent)[:])
  println(
    "a bent ciphertext gives back the same secret: \{@spec.eq(wrong, sent.secret)}",
  )
}
