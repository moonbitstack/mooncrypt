// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// FORS, the few-time signature at the bottom of the scheme (FIPS 205
// Algorithms 14-17).
//
// The `k` trees are addressed as one forest: a node's index at height `z` is
// `i * 2^(a - z) + offset`, so the leaf of tree `i` under digest index `j` is
// node `i * 2^a + j` of the forest. That is why the address carries the node
// index in its tree-index field and the FORS key's own position in the key pair
// field — the two are different numbers, and the leaf and its parent must agree
// about which tree they are in.

///|
/// `fors_skGen` (FIPS 205 Algorithm 14): the secret behind one leaf of the
/// forest, keyed through `PRF` and addressed by the forest-wide index.
fn fors_sk_gen(
  hs : Hashing,
  sk_seed : BytesView,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
  index : Int32,
) -> Bytes {
  let kp = adrs_get_key_pair(adrs)
  let sk_adrs = adrs_copy(adrs)
  adrs_set_type(sk_adrs, adrs_fors_prf)
  adrs_set_key_pair(sk_adrs, kp)
  adrs_set_tree_index(sk_adrs, index)
  prf(hs, pk_seed, sk_seed, sk_adrs)
}

///|
/// `fors_node` (FIPS 205 Algorithm 15): the node at `index` and `height` of the
/// forest, its leaf case being the hash of a secret.
fn fors_node(
  hs : Hashing,
  sk_seed : BytesView,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
  index : Int32,
  height : Int32,
) -> Bytes {
  let kp = adrs_get_key_pair(adrs)
  if height == 0 {
    let sk = fors_sk_gen(hs, sk_seed, pk_seed, adrs, index)
    let leaf_adrs = adrs_copy(adrs)
    adrs_set_type(leaf_adrs, adrs_fors_tree)
    adrs_set_key_pair(leaf_adrs, kp)
    adrs_set_tree_height(leaf_adrs, 0)
    adrs_set_tree_index(leaf_adrs, index)
    return f(hs, pk_seed, leaf_adrs, sk[:])
  }
  let left = fors_node(hs, sk_seed, pk_seed, adrs, 2 * index, height - 1)
  let right = fors_node(hs, sk_seed, pk_seed, adrs, 2 * index + 1, height - 1)
  let node_adrs = adrs_copy(adrs)
  adrs_set_type(node_adrs, adrs_fors_tree)
  adrs_set_key_pair(node_adrs, kp)
  adrs_set_tree_height(node_adrs, height)
  adrs_set_tree_index(node_adrs, index)
  h(hs, pk_seed, node_adrs, left[:], right[:])
}

///|
/// The `a`-bit indices the digest picks, one per FORS tree (`base_2b`).
fn fors_indices(md : BytesView, a : Int32, k : Int32) -> FixedArray[Int32] {
  let out = FixedArray::make(k, 0)
  for i in 0..<k {
    let mut v = 0
    for j in 0..<a {
      let bit = i * a + j
      v = (v << 1) | ((md[bit >> 3].to_int() >> (7 - (bit & 7))) & 1)
    }
    out[i] = v
  }
  out
}

///|
/// `fors_sign` (FIPS 205 Algorithm 16): the secret at each digest index, and
/// the path that proves it belongs to the forest.
fn fors_sign(
  hs : Hashing,
  md : BytesView,
  sk_seed : BytesView,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
  a : Int32,
  k : Int32,
) -> Bytes {
  let indices = fors_indices(md, a, k)
  let n = hs.n
  let parts : Array[Byte] = []
  for i in 0..<k {
    let sk = fors_sk_gen(hs, sk_seed, pk_seed, adrs, i * (1 << a) + indices[i])
    for j in 0..<n {
      parts.push(sk[j])
    }
    for j in 0..<a {
      let sibling = (indices[i] >> j) ^ 1
      let node = fors_node(
        hs,
        sk_seed,
        pk_seed,
        adrs,
        i * (1 << (a - j)) + sibling,
        j,
      )
      for t in 0..<n {
        parts.push(node[t])
      }
    }
  }
  Bytes::from_array(parts)
}

///|
/// `fors_pkFromSig` (FIPS 205 Algorithm 17): rebuild one root per tree from the
/// revealed secrets and paths, then fold the roots into the FORS public key.
fn fors_pk_from_sig(
  hs : Hashing,
  sig : BytesView,
  md : BytesView,
  pk_seed : BytesView,
  adrs : FixedArray[Byte],
  a : Int32,
  k : Int32,
) -> Bytes {
  let indices = fors_indices(md, a, k)
  let n = hs.n
  let stride = (a + 1) * n
  let kp = adrs_get_key_pair(adrs)
  let roots : Array[Byte] = []
  for i in 0..<k {
    let sk = sig[i * stride:i * stride + n]
    let mut index = i * (1 << a) + indices[i]
    let node_adrs = adrs_copy(adrs)
    adrs_set_type(node_adrs, adrs_fors_tree)
    adrs_set_key_pair(node_adrs, kp)
    adrs_set_tree_height(node_adrs, 0)
    adrs_set_tree_index(node_adrs, index)
    let mut node = f(hs, pk_seed, node_adrs, sk)
    for j in 0..<a {
      let sibling = sig[i * stride + (j + 1) * n:i * stride + (j + 2) * n]
      index = index >> 1
      adrs_set_tree_height(node_adrs, j + 1)
      adrs_set_tree_index(node_adrs, index)
      node = if ((indices[i] >> j) & 1) == 0 {
        h(hs, pk_seed, node_adrs, node[:], sibling)
      } else {
        h(hs, pk_seed, node_adrs, sibling, node[:])
      }
    }
    for t in 0..<n {
      roots.push(node[t])
    }
  }
  let root_adrs = adrs_copy(adrs)
  adrs_set_type(root_adrs, adrs_fors_roots)
  adrs_set_key_pair(root_adrs, kp)
  t(hs, pk_seed, root_adrs, Bytes::from_array(roots)[:])
}
