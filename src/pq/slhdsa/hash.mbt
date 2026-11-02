// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// The six tweakable functions of FIPS 205 §11, each one hash with the address
// mixed in: F, H, T_len, PRF, PRF_msg and H_msg.
//
// The two families differ in how they carry the address. A SHAKE set absorbs
// the whole thirty-two bytes. A SHA-2 set absorbs a twenty-two byte compression
// of it — one byte of layer, eight of tree, one of type, then the twelve the
// type interprets — and pads in front of it so that `PK.seed` alone fills the
// first compression block, which is what lets an implementation keep that block
// precomputed. The bytes are part of the standard, not an optimisation: a full
// address would give different digests.
//
// Everything runs around a `Hashing` value that holds the digest states of the
// set, because one signature is millions of these calls.

///|
/// Which hash family a parameter set is built on.
priv enum Family {
  Sha2
  Shake
}

///|
/// The digest machinery of one parameter set, made once and reset per call.
priv struct Hashing {
  family : Family
  n : Int32
  m : Int32
  // SHA-256 and SHA-512, both of them: a SHA-2 set of any width uses SHA-256
  // for PRF and F, and only the wider ones move H and T to SHA-512.
  narrow : @sha2.Hasher
  wide2 : @sha2.Hasher
  // Every one of the six is SHAKE256, the 128-bit sets included: the width of
  // a set is how much of the output it keeps, not which sponge it runs.
  shake256 : @sha3.Xof
}

///|
fn hashing(kind : Kind) -> Hashing {
  let n = kind.n()
  {
    family: kind.family(),
    n,
    m: kind.m(),
    narrow: @sha2.Hasher::new(kind=@sha2.Sha256),
    wide2: @sha2.Hasher::new(kind=@sha2.Sha512),
    shake256: @sha3.Xof::new(kind=@sha3.Shake256),
  }
}

///|
/// A run of zero bytes, for the padding in front of a compressed address. The
/// buffer is made once and sliced, because this padding is allocated on every
/// one of the millions of hash calls a signature makes.
let zero_pad : Bytes = Bytes::makei(128, fn(_) { b'\x00' })

///|
fn zeros(count : Int32) -> BytesView {
  zero_pad[0:count]
}

///|
/// The twenty-two byte address a SHA-2 set absorbs: `ADRS[3] ‖ ADRS[8:16] ‖
/// ADRS[19] ‖ ADRS[20:32]` (FIPS 205 §11.2, Figure 18).
fn adrs_compressed(a : FixedArray[Byte]) -> Bytes {
  let out = Array::make(22, b'\x00')
  out[0] = a[3]
  for i in 0..<8 {
    out[1 + i] = a[8 + i]
  }
  out[9] = a[19]
  for i in 0..<12 {
    out[10 + i] = a[20 + i]
  }
  Bytes::from_array(out)
}

///|
/// The same, with the two-block message of `H`.
fn sha2_digest5(
  hs : Hashing,
  narrow : Bool,
  a : BytesView,
  b : BytesView,
  c : BytesView,
  d : BytesView,
  e : BytesView,
) -> Bytes {
  let h = if narrow { hs.narrow } else { hs.wide2 }
  h.reset()
  h.write(a)
  h.write(b)
  h.write(c)
  h.write(d)
  h.write(e)
  h.finish()
}

///|
/// The first `n` bytes of a digest, which is all a SLH-DSA value keeps.
fn trunc_n(digest : Bytes, n : Int32) -> Bytes {
  digest[0:n].to_owned()
}

///|
/// One SHA-2 digest over up to five parts, without a parts array: the callers
/// are all fixed-shape and a `Vec` per hash would cost more than the hash.
fn sha2_digest(
  hs : Hashing,
  narrow : Bool,
  a : BytesView,
  b : BytesView,
  c : BytesView,
  d : BytesView,
) -> Bytes {
  let h = if narrow { hs.narrow } else { hs.wide2 }
  h.reset()
  h.write(a)
  h.write(b)
  h.write(c)
  h.write(d)
  h.finish()
}

///|
/// SHAKE256 over the given parts, exactly `len` bytes of it.
fn shake_of(hs : Hashing, parts : Array[BytesView], len : Int32) -> Bytes {
  hs.shake256.reset()
  for part in parts {
    hs.shake256.absorb(part)
  }
  hs.shake256.squeeze(len)
}

///|
/// `F` (FIPS 205 Algorithm 2): one `n`-byte block, with the address in front.
fn f(
  hs : Hashing,
  hkey : BytesView,
  adrs : FixedArray[Byte],
  m1 : BytesView,
) -> Bytes {
  match hs.family {
    Sha2 =>
      trunc_n(
        sha2_digest(hs, true, hkey, zeros(64 - hs.n), adrs_compressed(adrs), m1),
        hs.n,
      )
    Shake => shake_of(hs, [hkey, adrs_bytes(adrs), m1], hs.n)
  }
}

///|
/// `H` (Algorithm 3): two blocks folded together.
fn h(
  hs : Hashing,
  hkey : BytesView,
  adrs : FixedArray[Byte],
  m1 : BytesView,
  m2 : BytesView,
) -> Bytes {
  match hs.family {
    Sha2 => {
      let narrow = hs.n == 16
      let pad = (if narrow { 64 } else { 128 }) - hs.n
      trunc_n(
        sha2_digest5(
          hs,
          narrow,
          hkey,
          zeros(pad),
          adrs_compressed(adrs),
          m1,
          m2,
        ),
        hs.n,
      )
    }
    Shake => shake_of(hs, [hkey, adrs_bytes(adrs), m1, m2], hs.n)
  }
}

///|
/// `T_len` (Algorithm 4): any number of blocks, for a node's children.
fn t(
  hs : Hashing,
  hkey : BytesView,
  adrs : FixedArray[Byte],
  m : BytesView,
) -> Bytes {
  match hs.family {
    Sha2 => {
      let narrow = hs.n == 16
      let pad = (if narrow { 64 } else { 128 }) - hs.n
      trunc_n(
        sha2_digest(hs, narrow, hkey, zeros(pad), adrs_compressed(adrs), m),
        hs.n,
      )
    }
    Shake => shake_of(hs, [hkey, adrs_bytes(adrs), m], hs.n)
  }
}

///|
/// `PRF` (Algorithm 5): the secret behind a WOTS+ chain or a FORS leaf.
///
/// A SHA-2 set always uses SHA-256 here, whatever its width: the PRF only needs
/// `n` bytes and SHA-512 would be wasted work.
fn prf(
  hs : Hashing,
  pk_seed : BytesView,
  sk_seed : BytesView,
  adrs : FixedArray[Byte],
) -> Bytes {
  match hs.family {
    Sha2 =>
      trunc_n(
        sha2_digest(
          hs,
          true,
          pk_seed,
          zeros(64 - hs.n),
          adrs_compressed(adrs),
          sk_seed,
        ),
        hs.n,
      )
    Shake => shake_of(hs, [pk_seed, adrs_bytes(adrs), sk_seed], hs.n)
  }
}

///|
/// `PRF_msg` (Algorithm 6): the randomized `R` of a signature.
fn prf_msg(
  hs : Hashing,
  sk_prf : BytesView,
  opt_rand : BytesView,
  m : BytesView,
) -> Bytes {
  match hs.family {
    Sha2 => {
      let keyed = if hs.n == 16 {
        @hmac.mac(sk_prf, concat([opt_rand, m]), fn() {
          @sha2.Hasher::new(kind=@sha2.Sha256)
        })
      } else {
        @hmac.mac(sk_prf, concat([opt_rand, m]), fn() {
          @sha2.Hasher::new(kind=@sha2.Sha512)
        })
      }
      keyed[0:hs.n].to_owned()
    }
    Shake => shake_of(hs, [sk_prf, opt_rand, m], hs.n)
  }
}

///|
/// `H_msg` (Algorithm 7): the digest the whole signature is built on.
fn h_msg(
  hs : Hashing,
  r : BytesView,
  pk_seed : BytesView,
  pk_root : BytesView,
  m : BytesView,
) -> Bytes {
  match hs.family {
    Sha2 => {
      let inner = sha2_digest(hs, hs.n == 16, r, pk_seed, pk_root, m)
      mgf1(hs, hs.n == 16, r, pk_seed, inner, hs.m)
    }
    Shake => shake_of(hs, [r, pk_seed, pk_root, m], hs.m)
  }
}

///|
/// MGF1 (RFC 8017 B.2.1): the seed, a four-byte big-endian counter, and the
/// set's digest per block.
fn mgf1(
  hs : Hashing,
  narrow : Bool,
  seed1 : BytesView,
  seed2 : BytesView,
  seed3 : BytesView,
  len : Int32,
) -> Bytes {
  let out : Array[Byte] = []
  let mut counter = 0
  while out.length() < len {
    let block = sha2_digest(
      hs,
      narrow,
      seed1,
      seed2,
      seed3,
      Bytes::from_array([
        (counter >> 24).to_byte(),
        (counter >> 16).to_byte(),
        (counter >> 8).to_byte(),
        counter.to_byte(),
      ]),
    )
    for i in 0..<block.length() {
      if out.length() < len {
        out.push(block[i])
      }
    }
    counter += 1
  }
  Bytes::from_array(out)
}
