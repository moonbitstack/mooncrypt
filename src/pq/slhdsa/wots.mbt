// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// WOTS+ and the Merkle tree above it: FIPS 205 Algorithms 5-9. A WOTS+ key is
// `len` chains of `w = 16` hashes, each revealing exactly one value — which is
// why the signature is one value per chain, and why a forger who could walk a
// chain forward could sign anything.

///|
/// One chain step: `steps` applications of `F` from index `start`
/// (FIPS 205 Algorithm 5).
fn chain(
  hs : Hashing,
  x : BytesView,
  start : Int32,
  steps : Int32,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
) -> Bytes {
  let mut tmp = x.to_owned()
  for i in start..<(start + steps) {
    adrs_set_hash(adrs, i)
    tmp = f(hs, pk_seed, adrs, tmp[:])
  }
  tmp
}

///|
/// The number of chains for this width: `2n + 3`.
fn len_of(hs : Hashing) -> Int32 {
  2 * hs.n + 3
}

///|
/// The base-`w` digits of a message message, with the checksum that stops a
/// forger from choosing a message whose digits are all smaller.
fn digits_of(hs : Hashing, msg : BytesView) -> FixedArray[Int32] {
  let len = len_of(hs)
  let out = FixedArray::make(len, 0)
  for i in 0..<(len - 3) {
    let b = msg[i / 2].to_int()
    out[i] = if i % 2 == 0 { (b >> 4) & 0x0F } else { b & 0x0F }
  }
  let mut sum = 0
  for i in 0..<(len - 3) {
    sum += 15 - out[i]
  }
  // Three checksum digits, big-endian. The shift the standard writes is
  // `(8 - (len_1 * lg_w) % 8) % 8`, which is zero for every set: `len_1` is
  // `2n` and `lg_w` is four, so the product is a whole number of bytes.
  for i in 0..<3 {
    out[len - 3 + i] = (sum >> (4 * (2 - i))) & 0x0F
  }
  out
}

///|
/// `wots_pkGen` (FIPS 205 Algorithm 6).
///
/// The key pair index is read once and set again after every type change,
/// because a type change clears the twelve bytes the type interprets — which is
/// exactly where the index lives.
fn wots_pk_gen(
  hs : Hashing,
  sk_seed : BytesView,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
) -> Bytes {
  let len = len_of(hs)
  let kp = adrs_get_key_pair(adrs)
  let chain_adrs = adrs_copy(adrs)
  adrs_set_type(chain_adrs, adrs_wots_hash)
  adrs_set_key_pair(chain_adrs, kp)
  let sk_adrs = adrs_copy(chain_adrs)
  adrs_set_type(sk_adrs, adrs_wots_prf)
  adrs_set_key_pair(sk_adrs, kp)
  let parts : Array[Byte] = []
  for i in 0..<len {
    adrs_set_chain(sk_adrs, i)
    let sk = prf(hs, pk_seed, sk_seed, sk_adrs)
    adrs_set_chain(chain_adrs, i)
    adrs_set_hash(chain_adrs, 0)
    let node = chain(hs, sk[:], 0, 15, pk_seed, chain_adrs)
    for j in 0..<node.length() {
      parts.push(node[j])
    }
  }
  let pk_adrs = adrs_copy(chain_adrs)
  adrs_set_type(pk_adrs, adrs_wots_pk)
  adrs_set_key_pair(pk_adrs, kp)
  t(hs, pk_seed, pk_adrs, Bytes::from_array(parts)[:])
}

///|
/// `wots_sign` (FIPS 205 Algorithm 7): one value per chain, at the step the
/// message digit names.
fn wots_sign(
  hs : Hashing,
  msg : BytesView,
  sk_seed : BytesView,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
) -> Bytes {
  let len = len_of(hs)
  let d = digits_of(hs, msg)
  let kp = adrs_get_key_pair(adrs)
  let chain_adrs = adrs_copy(adrs)
  adrs_set_type(chain_adrs, adrs_wots_hash)
  adrs_set_key_pair(chain_adrs, kp)
  let sk_adrs = adrs_copy(chain_adrs)
  adrs_set_type(sk_adrs, adrs_wots_prf)
  adrs_set_key_pair(sk_adrs, kp)
  let parts : Array[Byte] = []
  for i in 0..<len {
    adrs_set_chain(sk_adrs, i)
    let sk = prf(hs, pk_seed, sk_seed, sk_adrs)
    adrs_set_chain(chain_adrs, i)
    adrs_set_hash(chain_adrs, 0)
    let node = chain(hs, sk[:], 0, d[i], pk_seed, chain_adrs)
    for j in 0..<node.length() {
      parts.push(node[j])
    }
  }
  Bytes::from_array(parts)
}

///|
/// `wots_pkFromSig` (FIPS 205 Algorithm 8): walk each chain from where the
/// signature left it to the end, and fold.
fn wots_pk_from_sig(
  hs : Hashing,
  sig : BytesView,
  msg : BytesView,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
) -> Bytes {
  let len = len_of(hs)
  let n = hs.n
  let d = digits_of(hs, msg)
  let kp = adrs_get_key_pair(adrs)
  let chain_adrs = adrs_copy(adrs)
  adrs_set_type(chain_adrs, adrs_wots_hash)
  adrs_set_key_pair(chain_adrs, kp)
  let parts : Array[Byte] = []
  for i in 0..<len {
    adrs_set_chain(chain_adrs, i)
    adrs_set_hash(chain_adrs, 0)
    let node = chain(
      hs,
      sig[i * n:(i + 1) * n],
      d[i],
      15 - d[i],
      pk_seed,
      chain_adrs,
    )
    for j in 0..<node.length() {
      parts.push(node[j])
    }
  }
  let pk_adrs = adrs_copy(chain_adrs)
  adrs_set_type(pk_adrs, adrs_wots_pk)
  adrs_set_key_pair(pk_adrs, kp)
  t(hs, pk_seed, pk_adrs, Bytes::from_array(parts)[:])
}

///|
/// `xmss_node` (FIPS 205 Algorithm 9): the root of the subtree of `2^target`
/// leaves starting at `start`, and, when `auth` is given, the sibling on the
/// path down to `index` at every height.
///
/// A stack holds one unfinished node per level, so a tree of 2^9 leaves costs
/// nine values and never materialises: a node is merged the moment its sibling
/// exists, and the sibling of the path is the node whose index, at its height,
/// is the path's index with its lowest bit flipped.
fn treehash(
  hs : Hashing,
  sk_seed : BytesView,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
  start : Int32,
  target : Int32,
  auth : Array[Bytes]?,
  index : Int32,
) -> Bytes {
  let stack : Array[Bytes] = []
  for i in 0..<(1 << target) {
    let leaf_adrs = adrs_copy(adrs)
    adrs_set_type(leaf_adrs, adrs_wots_hash)
    adrs_set_key_pair(leaf_adrs, start + i)
    let mut node = wots_pk_gen(hs, sk_seed, pk_seed, leaf_adrs)
    let mut height = 0
    match auth {
      Some(a) => if i == (index ^ 1) { a[0] = node }
      None => ()
    }
    while height < target && ((i >> height) & 1) == 1 {
      let left = stack.pop().unwrap()
      let node_adrs = adrs_copy(adrs)
      adrs_set_type(node_adrs, adrs_tree)
      adrs_set_tree_height(node_adrs, height + 1)
      adrs_set_tree_index(node_adrs, (start + i) >> (height + 1))
      node = h(hs, pk_seed, node_adrs, left[:], node[:])
      height += 1
      match auth {
        Some(a) =>
          if height < target && i >> height == ((index >> height) ^ 1) {
            a[height] = node
          }
        None => ()
      }
    }
    stack.push(node)
  }
  stack[0]
}
