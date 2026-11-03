// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// CTR-DRBG (SP 800-90A §10.2.1): AES-128, AES-192 or AES-256, with or without
// the derivation function. The derivation function and the chaining helper are
// §10.3.2 and §10.3.3. The seed is the key length plus one block, so the three
// key lengths give three seed lengths: 32, 40 and 48 bytes.

///|
/// The block cipher a generator runs on. The key length is the only thing that
/// distinguishes the three, and it also fixes the seed length — the key length
/// plus one 16-byte block.
#derive(Eq, Debug)
pub(all) enum Kind {
  Aes128
  Aes192
  Aes256
}

///|
pub extend Kind with Eq::{equal, not_equal}

///|
pub extend Kind with Debug::{to_repr}

///|
/// The key length in bytes: 16, 24 or 32.
pub fn Kind::size(self : Kind) -> Int32 {
  match self {
    Aes128 => 16
    Aes192 => 24
    Aes256 => 32
  }
}

///|
fn dupn(a : FixedArray[Byte]) -> FixedArray[Byte] {
  let o = FixedArray::make(a.length(), b'\x00')
  for i in 0..<a.length() {
    o[i] = a[i]
  }
  o
}

///|
fn aes_ctx(key : FixedArray[Byte]) -> @aes.Cipher {
  @aes.Cipher::new(key.unsafe_reinterpret_as_bytes()[:]) catch {
    _ => abort("ctr-drbg: a full-length key must build a cipher")
  }
}

///|
/// Add one to a 128-bit big-endian counter, in place.
fn increment(v : FixedArray[Byte]) -> Unit {
  let mut i = 15
  let mut carry = true
  while i >= 0 && carry {
    let s = v[i].to_int() + 1
    v[i] = (s & 0xFF).to_byte()
    carry = s >> 8 != 0
    i = i - 1
  }
}

///|
/// The block cipher chaining BCC (§10.3.3): CBC-MAC without a fixed IV,
/// returned as the final block. The key is the derivation function's key, and
/// `data` is a whole number of blocks.
fn bcc(key : FixedArray[Byte], data : BytesView) -> FixedArray[Byte] {
  let c = aes_ctx(key)
  let x = FixedArray::make(16, b'\x00')
  let mut at = 0
  while at < data.length() {
    for i in 0..<16 {
      x[i] = (x[i].to_int() ^ data[at + i].to_int()).to_byte()
    }
    let enc = c.encrypt(x.unsafe_reinterpret_as_bytes()[:])
    for i in 0..<16 {
      x[i] = enc[i]
    }
    at = at + 16
  }
  x
}

///|
/// Block_Cipher_df (§10.3.2): stretch an input to `nbytes` with BCC under the
/// fixed key `00 01 … (keylen-1)`, then a counter-mode expansion under the
/// derived key. The block cipher is the one the DRBG runs on, so the fixed key
/// and the derived key are the DRBG's own key length — not always AES-256.
fn block_cipher_df(
  input : BytesView,
  nbytes : Int32,
  keylen : Int32,
) -> FixedArray[Byte] {
  let il = input.length()
  let s : Array[Byte] = [
    ((il >> 24) & 0xFF).to_byte(),
    ((il >> 16) & 0xFF).to_byte(),
    ((il >> 8) & 0xFF).to_byte(),
    (il & 0xFF).to_byte(),
    ((nbytes >> 24) & 0xFF).to_byte(),
    ((nbytes >> 16) & 0xFF).to_byte(),
    ((nbytes >> 8) & 0xFF).to_byte(),
    (nbytes & 0xFF).to_byte(),
  ]
  for b in input {
    s.push(b)
  }
  s.push(b'\x80')
  while s.length() % 16 != 0 {
    s.push(b'\x00')
  }
  let sb = Bytes::from_array(s)
  let kfixed = FixedArray::make(keylen, b'\x00')
  for i in 0..<keylen {
    kfixed[i] = i.to_byte()
  }
  let temp : Array[Byte] = []
  let iv = FixedArray::make(16, b'\x00')
  let mut counter = 0
  while temp.length() < keylen + 16 {
    iv[0] = ((counter >> 24) & 0xFF).to_byte()
    iv[1] = ((counter >> 16) & 0xFF).to_byte()
    iv[2] = ((counter >> 8) & 0xFF).to_byte()
    iv[3] = (counter & 0xFF).to_byte()
    let niv = bcc(kfixed, join([iv.unsafe_reinterpret_as_bytes()[:], sb[:]]))
    for b in niv {
      temp.push(b)
    }
    counter = counter + 1
  }
  let key = FixedArray::make(keylen, b'\x00')
  for i in 0..<keylen {
    key[i] = temp[i]
  }
  let x = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    x[i] = temp[keylen + i]
  }
  let c = aes_ctx(key)
  let out : Array[Byte] = []
  while out.length() < nbytes {
    let blk = c.encrypt(x.unsafe_reinterpret_as_bytes()[:])
    for b in blk {
      out.push(b)
    }
    for i in 0..<16 {
      x[i] = blk[i]
    }
  }
  let r = FixedArray::make(nbytes, b'\x00')
  for i in 0..<nbytes {
    r[i] = out[i]
  }
  r
}

///|
/// CTR_DRBG_Update (§10.2.1.2): refill Key and V from the AES keystream, then
/// fold any provided data in.
fn update(
  key : FixedArray[Byte],
  v : FixedArray[Byte],
  provided : BytesView,
  keylen : Int32,
) -> (FixedArray[Byte], FixedArray[Byte]) {
  let seed = keylen + 16
  let c = aes_ctx(key)
  let vv = dupn(v)
  let temp : Array[Byte] = []
  while temp.length() < seed {
    increment(vv)
    let blk = c.encrypt(vv.unsafe_reinterpret_as_bytes()[:])
    for b in blk {
      temp.push(b)
    }
  }
  let nk = FixedArray::make(keylen, b'\x00')
  for i in 0..<keylen {
    let p = if i < provided.length() { provided[i].to_int() } else { 0 }
    nk[i] = (temp[i].to_int() ^ p).to_byte()
  }
  let nv = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    let idx = keylen + i
    let p = if idx < provided.length() { provided[idx].to_int() } else { 0 }
    nv[i] = (temp[idx].to_int() ^ p).to_byte()
  }
  (nk, nv)
}

///|
/// A CTR-DRBG over AES-128, AES-192 or AES-256, with or without the derivation
/// function (§10.2.1).
pub struct CtrDrbg {
  kind : Kind
  derivation : Bool
  mut key : FixedArray[Byte]
  mut v : FixedArray[Byte]
  mut reseed_counter : UInt64
}

///|
/// Seed the generator from an entropy input, a nonce and a personalization
/// string (§10.2.1.3).
///
/// Without the derivation function the entropy input must already be the seed
/// length — key length plus one block — which is what full-entropy instantiation
/// requires; only the personalization string is folded in, and the nonce is not
/// used. With it, the three are concatenated and stretched to the seed length.
pub fn CtrDrbg::new(
  entropy~ : BytesView,
  nonce~ : BytesView,
  personalization~ : BytesView,
  kind~ : Kind = Aes256,
  derivation~ : Bool = true,
) -> CtrDrbg {
  let keylen = kind.size()
  let seed = keylen + 16
  let seed_material = if derivation {
    block_cipher_df(join([entropy, nonce, personalization]), seed, keylen)
  } else {
    let out = FixedArray::make(seed, b'\x00')
    for i in 0..<seed {
      let e = if i < entropy.length() { entropy[i].to_int() } else { 0 }
      let p = if i < personalization.length() {
        personalization[i].to_int()
      } else {
        0
      }
      out[i] = (e ^ p).to_byte()
    }
    out
  }
  let key = FixedArray::make(keylen, b'\x00')
  let v = FixedArray::make(16, b'\x00')
  let (k, vv) = update(
    key,
    v,
    seed_material.unsafe_reinterpret_as_bytes()[:],
    keylen,
  )
  { kind, derivation, key: k, v: vv, reseed_counter: 1, }
}

///|
/// Reseed from fresh entropy (§10.2.1.4). Without the derivation function the
/// entropy input must be the seed length and the additional input is folded in
/// by XOR.
pub fn CtrDrbg::reseed(
  self : CtrDrbg,
  entropy~ : BytesView,
  additional~ : BytesView,
) -> Unit {
  let keylen = self.kind.size()
  let seed = keylen + 16
  let seed_material = if self.derivation {
    block_cipher_df(join([entropy, additional]), seed, keylen)
  } else {
    let out = FixedArray::make(seed, b'\x00')
    for i in 0..<seed {
      let e = if i < entropy.length() { entropy[i].to_int() } else { 0 }
      let a = if i < additional.length() { additional[i].to_int() } else { 0 }
      out[i] = (e ^ a).to_byte()
    }
    out
  }
  let (k, vv) = update(
    self.key,
    self.v,
    seed_material.unsafe_reinterpret_as_bytes()[:],
    keylen,
  )
  self.key = k
  self.v = vv
  self.reseed_counter = 1
}

///|
/// Draw `n` bytes with no additional input.
pub fn CtrDrbg::generate(self : CtrDrbg, n : Int32) -> Bytes {
  self.generate_with(n, additional=b""[:])
}

///|
/// Draw `n` bytes with an additional input (§10.2.1.5).
///
/// The additional input is processed before the keystream, and the processed
/// value — zeroes when there is none — is folded back into the state afterwards,
/// so producing output always advances Key and V.
pub fn CtrDrbg::generate_with(
  self : CtrDrbg,
  n : Int32,
  additional~ : BytesView,
) -> Bytes {
  let keylen = self.kind.size()
  let seed = keylen + 16
  let processed = if additional.length() > 0 {
    let p = if self.derivation {
      block_cipher_df(additional, seed, keylen)
    } else {
      let out = FixedArray::make(seed, b'\x00')
      for i in 0..<seed {
        let a = if i < additional.length() { additional[i].to_int() } else { 0 }
        out[i] = a.to_byte()
      }
      out
    }
    let (k, vv) = update(
      self.key,
      self.v,
      p.unsafe_reinterpret_as_bytes()[:],
      keylen,
    )
    self.key = k
    self.v = vv
    p
  } else {
    FixedArray::make(seed, b'\x00')
  }
  let c = aes_ctx(self.key)
  let vv = dupn(self.v)
  let out : Array[Byte] = []
  while out.length() < n {
    increment(vv)
    let blk = c.encrypt(vv.unsafe_reinterpret_as_bytes()[:])
    for b in blk {
      out.push(b)
    }
  }
  let r = Array::make(n, b'\x00')
  for i in 0..<n {
    r[i] = out[i]
  }
  self.v = vv
  let (k2, v2) = update(
    self.key,
    self.v,
    processed.unsafe_reinterpret_as_bytes()[:],
    keylen,
  )
  self.key = k2
  self.v = v2
  self.reseed_counter = self.reseed_counter + 1UL
  Bytes::from_array(r)
}

///|
pub fn CtrDrbg::reseed_counter(self : CtrDrbg) -> UInt64 {
  self.reseed_counter
}

///|
/// The block cipher the generator runs on.
pub fn CtrDrbg::kind(self : CtrDrbg) -> Kind {
  self.kind
}

///|
pub extend CtrDrbg with @moonseed.Source::{fill}

///|
pub impl @moonseed.Source for CtrDrbg with fn fill(
  self : CtrDrbg,
  buf : FixedArray[Byte],
) -> Unit {
  let out = self.generate_with(buf.length(), additional=b""[:])
  for i in 0..<buf.length() {
    buf[i] = out[i]
  }
}
