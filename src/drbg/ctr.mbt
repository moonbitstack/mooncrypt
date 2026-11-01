// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// CTR-DRBG (SP 800-90A §10.2.1) over AES-256: keylen 32 bytes, block 16 bytes,
// seedlen 48 bytes. The derivation function and the chaining helper are §10.3.2
// and §10.3.3.

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
/// returned as the final block.
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
/// Block_Cipher_df (§10.3.2): stretch an input to `nbits` with BCC under a fixed
/// key, then a counter-mode expansion under the derived key.
fn block_cipher_df(input : BytesView, nbits : Int32) -> FixedArray[Byte] {
  let nbytes = (nbits + 7) / 8
  let il = input.length()
  let s : Array[Byte] = [
    ((nbits >> 24) & 0xFF).to_byte(),
    ((nbits >> 16) & 0xFF).to_byte(),
    ((nbits >> 8) & 0xFF).to_byte(),
    (nbits & 0xFF).to_byte(),
    ((il >> 24) & 0xFF).to_byte(),
    ((il >> 16) & 0xFF).to_byte(),
    ((il >> 8) & 0xFF).to_byte(),
    (il & 0xFF).to_byte(),
  ]
  for b in input {
    s.push(b)
  }
  s.push(b'\x80')
  while s.length() % 16 != 0 {
    s.push(b'\x00')
  }
  let sb = Bytes::from_array(s)
  let kfixed = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    kfixed[i] = i.to_byte()
  }
  let temp : Array[Byte] = []
  let iv = FixedArray::make(16, b'\x00')
  while temp.length() < 48 {
    let niv = bcc(kfixed, join([iv.unsafe_reinterpret_as_bytes()[:], sb[:]]))
    for b in niv {
      temp.push(b)
    }
    for i in 0..<16 {
      iv[i] = niv[i]
    }
  }
  let key = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    key[i] = temp[i]
  }
  let x = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    x[i] = temp[32 + i]
  }
  let c = aes_ctx(key)
  let out : Array[Byte] = []
  while out.length() < nbytes {
    let blk = c.encrypt(x.unsafe_reinterpret_as_bytes()[:])
    for b in blk {
      out.push(b)
    }
    increment(x)
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
) -> (FixedArray[Byte], FixedArray[Byte]) {
  let c = aes_ctx(key)
  let vv = dupn(v)
  let temp : Array[Byte] = []
  while temp.length() < 48 {
    increment(vv)
    let blk = c.encrypt(vv.unsafe_reinterpret_as_bytes()[:])
    for b in blk {
      temp.push(b)
    }
  }
  let nk = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    nk[i] = temp[i]
  }
  let nv = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    nv[i] = temp[32 + i]
  }
  if provided.length() > 0 {
    for i in 0..<32 {
      let p = if i < provided.length() { provided[i].to_int() } else { 0 }
      nk[i] = (nk[i].to_int() ^ p).to_byte()
    }
    for i in 0..<16 {
      let idx = 32 + i
      let p = if idx < provided.length() { provided[idx].to_int() } else { 0 }
      nv[i] = (nv[i].to_int() ^ p).to_byte()
    }
  }
  (nk, nv)
}

///|
/// A CTR-DRBG over AES-256.
pub struct CtrDrbg {
  mut key : FixedArray[Byte]
  mut v : FixedArray[Byte]
  mut reseed_counter : UInt64
}

///|
/// Seed the generator from an entropy input, a nonce and a personalization
/// string (§10.2.1.3).
pub fn CtrDrbg::new(
  entropy~ : BytesView,
  nonce~ : BytesView,
  personalization~ : BytesView,
) -> CtrDrbg {
  let seed = block_cipher_df(join([entropy, nonce, personalization]), 384)
  let key = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    key[i] = seed[i]
  }
  let v = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    v[i] = seed[32 + i]
  }
  let (k, vv) = update(key, v, b""[:])
  { key: k, v: vv, reseed_counter: 1, }
}

///|
/// Reseed from fresh entropy (§10.2.1.4).
pub fn CtrDrbg::reseed(
  self : CtrDrbg,
  entropy~ : BytesView,
  additional~ : BytesView,
) -> Unit {
  let seed = block_cipher_df(join([entropy, additional]), 384)
  let key = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    key[i] = seed[i]
  }
  let v = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    v[i] = seed[32 + i]
  }
  let (k, vv) = update(key, v, b""[:])
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
pub fn CtrDrbg::generate_with(
  self : CtrDrbg,
  n : Int32,
  additional~ : BytesView,
) -> Bytes {
  let (k1, v1) = update(self.key, self.v, additional)
  self.key = k1
  self.v = v1
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
  let (k2, v2) = update(self.key, self.v, additional)
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
